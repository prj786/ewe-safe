//! Test support for ewe-safe (never shipped): a mock WebDAV server on
//! 127.0.0.1 that understands what the store sends — ETags, conditional
//! PUTs, MKCOL, basic auth — with switches for a server that ignores
//! conditions, sends no ETags, fails, or hangs.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub const USER: &str = "sam";
pub const PASS: &str = "app-password-1";
pub const ROOT: &str = "/remote.php/dav/files/sam/";
pub const FILE: &str = "/remote.php/dav/files/sam/ewe/safe/passwords.kdbx";

#[derive(Default)]
pub struct Inner {
    pub files: HashMap<String, (Vec<u8>, u64)>,
    pub dirs: HashSet<String>,
    next: u64,
    /// The server writes over a stale version anyway (no conditional PUT).
    pub ignore_conditions: bool,
    /// The server sends no ETags at all.
    pub no_etags: bool,
    /// Answer the next n requests with 503.
    pub fail_next: usize,
    /// (method, path, status) of every request.
    pub log: Vec<(String, String, u16)>,
    /// Every request waits while this is on: a place that hangs.
    pub hang: bool,
}

/// A WebDAV server on 127.0.0.1 that understands what the store sends.
pub struct Mock {
    port: u16,
    pub inner: Arc<Mutex<Inner>>,
    stop: Arc<AtomicBool>,
}

impl Mock {
    pub fn start() -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let mut inner = Inner::default();
        // the account's root, as Nextcloud has it
        let mut at = String::from("/");
        inner.dirs.insert(at.clone());
        for seg in ROOT.trim_matches('/').split('/') {
            at.push_str(seg);
            at.push('/');
            inner.dirs.insert(at.clone());
        }
        let inner = Arc::new(Mutex::new(inner));
        let stop = Arc::new(AtomicBool::new(false));
        let (i, s) = (inner.clone(), stop.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = stream {
                    let i = i.clone();
                    thread::spawn(move || serve(stream, &i));
                }
            }
        });
        Mock { port, inner, stop }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}{ROOT}", self.port)
    }

    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .files
            .get(path)
            .map(|f| f.0.clone())
    }

    /// Another program (or a restore) writes the file: a new version.
    pub fn replace(&self, path: &str, bytes: &[u8]) {
        let mut i = self.inner.lock().unwrap();
        i.next += 1;
        let n = i.next;
        i.files.insert(path.to_string(), (bytes.to_vec(), n));
    }

    pub fn remove(&self, path: &str) {
        self.inner.lock().unwrap().files.remove(path);
    }

    pub fn set(&self, f: impl FnOnce(&mut Inner)) {
        f(&mut self.inner.lock().unwrap());
    }

    pub fn count(&self, method: &str) -> usize {
        let i = self.inner.lock().unwrap();
        i.log.iter().filter(|(m, _, _)| m == method).count()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(stream: TcpStream, inner: &Mutex<Inner>) {
    for _ in 0..600 {
        if !inner.lock().unwrap().hang {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    if len > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }

    let (status, etag, out) = handle(inner, &method, &path, &headers, body);
    let mut resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        out.len()
    );
    if let Some(e) = etag {
        resp.push_str(&format!("ETag: \"{e}\"\r\nOC-ETag: \"{e}\"\r\n"));
    }
    resp.push_str("\r\n");
    let mut stream = stream;
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(&out);
    let _ = stream.flush();
}

fn handle(
    inner: &Mutex<Inner>,
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: Vec<u8>,
) -> (u16, Option<String>, Vec<u8>) {
    let mut i = inner.lock().unwrap();
    let want = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASS}")));
    let (status, etag, out) = if headers.get("authorization") != Some(&want) {
        (401, None, Vec::new())
    } else if i.fail_next > 0 {
        i.fail_next -= 1;
        (503, None, Vec::new())
    } else {
        respond(&mut i, method, path, headers, body)
    };
    i.log.push((method.to_string(), path.to_string(), status));
    let etag = if i.no_etags { None } else { etag };
    (status, etag, out)
}

fn parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(n) => trimmed[..=n].to_string(),
        None => "/".to_string(),
    }
}

fn respond(
    i: &mut Inner,
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: Vec<u8>,
) -> (u16, Option<String>, Vec<u8>) {
    let etag = |n: u64| Some(format!("e-{n}"));
    let current = i.files.get(path).map(|f| f.1);
    match method {
        "GET" | "HEAD" => match i.files.get(path) {
            None => (404, None, Vec::new()),
            Some((bytes, n)) => {
                let quoted = format!("\"e-{n}\"");
                if !i.no_etags && headers.get("if-none-match") == Some(&quoted) {
                    (304, etag(*n), Vec::new())
                } else if method == "HEAD" {
                    (200, etag(*n), Vec::new())
                } else {
                    (200, etag(*n), bytes.clone())
                }
            }
        },
        "PUT" => {
            if !i.dirs.contains(&parent(path)) {
                return (409, None, Vec::new());
            }
            if !i.ignore_conditions {
                if let Some(m) = headers.get("if-match")
                    && current.map(|n| format!("\"e-{n}\"")).as_ref() != Some(m)
                {
                    return (412, None, Vec::new());
                }
                if headers.get("if-none-match").map(String::as_str) == Some("*")
                    && current.is_some()
                {
                    return (412, None, Vec::new());
                }
            }
            i.next += 1;
            let n = i.next;
            i.files.insert(path.to_string(), (body, n));
            (
                if current.is_some() { 204 } else { 201 },
                etag(n),
                Vec::new(),
            )
        }
        "MKCOL" => {
            let dir = if path.ends_with('/') {
                path.to_string()
            } else {
                format!("{path}/")
            };
            if i.dirs.contains(&dir) {
                (405, None, Vec::new())
            } else if !i.dirs.contains(&parent(&dir)) {
                (409, None, Vec::new())
            } else {
                i.dirs.insert(dir);
                (201, None, Vec::new())
            }
        }
        "DELETE" => match i.files.remove(path) {
            Some(_) => (204, None, Vec::new()),
            None => (404, None, Vec::new()),
        },
        _ => (405, None, Vec::new()),
    }
}

/// A port nothing listens on.
pub fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

/// A TCP proxy to the mock that can be switched off: one machine going
/// offline while another stays online. Off, nothing listens on its port
/// (a refused connection, as when the network is gone).
pub struct Proxy {
    port: u16,
    target: u16,
    on: Arc<AtomicBool>,
    epoch: Arc<std::sync::atomic::AtomicU64>,
}

impl Proxy {
    pub fn start(target: u16) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let p = Proxy {
            port,
            target,
            on: Arc::new(AtomicBool::new(true)),
            epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        p.run(listener);
        p
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The mock's base URL through this proxy.
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}{ROOT}", self.port)
    }

    pub fn offline(&self) {
        self.on.store(false, Ordering::SeqCst);
        self.epoch.fetch_add(1, Ordering::SeqCst);
        // let the accept loop see it and drop the listener
        thread::sleep(std::time::Duration::from_millis(100));
    }

    pub fn online(&self) {
        if self.on.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut tries = 0;
        let listener = loop {
            match TcpListener::bind(("127.0.0.1", self.port)) {
                Ok(l) => break l,
                Err(e) if tries < 50 => {
                    tries += 1;
                    let _ = e;
                    thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => panic!("rebind {}: {e}", self.port),
            }
        };
        self.run(listener);
    }

    fn run(&self, listener: TcpListener) {
        listener.set_nonblocking(true).expect("nonblocking");
        let (on, epoch, target) = (self.on.clone(), self.epoch.clone(), self.target);
        let mine = epoch.load(Ordering::SeqCst);
        thread::spawn(move || {
            while on.load(Ordering::SeqCst) && epoch.load(Ordering::SeqCst) == mine {
                match listener.accept() {
                    Ok((client, _)) => {
                        let _ = client.set_nonblocking(false);
                        thread::spawn(move || pipe(client, target));
                    }
                    Err(_) => thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
        });
    }
}

fn pipe(client: TcpStream, target: u16) {
    let Ok(server) = TcpStream::connect(("127.0.0.1", target)) else {
        return;
    };
    let (mut c2, mut s2) = match (client.try_clone(), server.try_clone()) {
        (Ok(c), Ok(s)) => (c, s),
        _ => return,
    };
    let up = thread::spawn(move || {
        let mut c = client;
        let mut s = server;
        let _ = std::io::copy(&mut c, &mut s);
        let _ = s.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut s2, &mut c2);
    let _ = c2.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}
