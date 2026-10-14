//! What the store tests share: a mock WebDAV server, switchable
//! credentials (a machine going offline), cheap keys and small safes.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use keepass::DatabaseKey;
use keepass::config::KdfConfig;
use safe_core::{Draft, Kind, Safe};
use safe_store::{Credentials, Error, Login, Syncer, WebDav};
use zeroize::Zeroizing;

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

/// Credentials whose server can be switched off: a machine going offline.
#[derive(Clone)]
pub struct Switch {
    base: Arc<Mutex<String>>,
    online: String,
    password: Arc<Mutex<String>>,
}

impl Switch {
    pub fn new(base: &str) -> Switch {
        Switch {
            base: Arc::new(Mutex::new(base.to_string())),
            online: base.to_string(),
            password: Arc::new(Mutex::new(PASS.to_string())),
        }
    }

    pub fn offline(&self) {
        *self.base.lock().unwrap() = format!("http://127.0.0.1:{}{ROOT}", dead_port());
    }

    pub fn online(&self) {
        *self.base.lock().unwrap() = self.online.clone();
    }

    pub fn set_password(&self, p: &str) {
        *self.password.lock().unwrap() = p.to_string();
    }
}

impl Credentials for Switch {
    fn base(&self) -> Result<String, Error> {
        Ok(self.base.lock().unwrap().clone())
    }

    fn login(&self) -> Result<Login, Error> {
        Ok(Login {
            user: USER.to_string(),
            password: Zeroizing::new(self.password.lock().unwrap().clone()),
        })
    }
}

/// A port nothing listens on.
pub fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

pub fn place(creds: &Switch) -> Box<WebDav> {
    Box::new(
        WebDav::new(
            "nextcloud",
            "ewe/safe/passwords.kdbx",
            Box::new(creds.clone()),
        )
        .insecure_loopback(true),
    )
}

/// A fresh scratch directory for one test.
pub fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("safe-store-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

pub fn cheap() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

pub fn key() -> DatabaseKey {
    safe_core::safe::key("correct horse battery", None).expect("key")
}

pub fn other_key() -> DatabaseKey {
    safe_core::safe::key("a new master password", None).expect("key")
}

pub fn new_safe() -> Safe {
    Safe::create("Sam's safe", cheap())
}

pub fn login(title: &str, username: &str) -> Draft {
    Draft {
        kind: Kind::Login,
        title: title.into(),
        username: username.into(),
        password: Zeroizing::new(format!("pw-{title}")),
        websites: vec![format!("https://{}.example", title.to_lowercase())],
        ..Draft::default()
    }
}

/// Titles of the items outside the recycle bin, sorted.
pub fn titles(s: &Safe) -> Vec<String> {
    let mut t: Vec<String> = s.items().into_iter().map(|i| i.title).collect();
    t.sort();
    t
}

pub fn id_of(s: &Safe, title: &str) -> String {
    s.items()
        .into_iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
        .id
}

pub fn username_of(s: &Safe, title: &str) -> String {
    s.items()
        .into_iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
        .username
}

/// Every username an item has had: now and in its history.
pub fn usernames_ever(s: &Safe, title: &str) -> Vec<String> {
    let db = s.database();
    let mut out = Vec::new();
    for e in db.iter_all_entries() {
        if e.get_title() != Some(title) {
            continue;
        }
        out.push(e.get_username().unwrap_or("").to_string());
        if let Some(h) = &e.history {
            for v in h.get_entries() {
                out.push(v.get_username().unwrap_or("").to_string());
            }
        }
    }
    out
}

/// A machine: its own state directory, credentials and syncer.
pub struct Machine {
    pub creds: Switch,
    pub sync: Syncer,
    pub dir: PathBuf,
}

pub fn machine(mock: &Mock, dir: PathBuf, name: &str) -> Machine {
    let creds = Switch::new(&mock.base());
    let sync = Syncer::new(place(&creds), &dir, name).expect("syncer");
    Machine { creds, sync, dir }
}

/// The error a load gives (a `Safe` has no `Debug`, on purpose).
pub fn load_err(sync: &mut Syncer, key: &DatabaseKey) -> Error {
    match sync.load(key) {
        Ok(_) => panic!("the load succeeded"),
        Err(e) => e,
    }
}
