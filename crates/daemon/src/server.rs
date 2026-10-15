//! The socket: `$XDG_RUNTIME_DIR/ewe-safe.sock`, from systemd socket
//! activation or bound here (0600). Every peer is checked with
//! `SO_PEERCRED`: another uid gets no answer. Newline-delimited JSON, v1
//! (docs/PROTOCOL.md).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use serde_json::{Map, Value, json};
use zeroize::Zeroize;

use crate::config::Paths;
use crate::daemon::{Daemon, Fail};
use crate::{log, verbs};

/// A request line can't be longer than this (a note's text fits easily).
const MAX_LINE: usize = 1 << 20;

/// The listening socket, and the path to remove at exit when it was bound
/// here (systemd owns an activated one).
pub fn listen(paths: &Paths) -> Result<(UnixListener, Option<PathBuf>), String> {
    if let Some(l) = activated() {
        return Ok((l, None));
    }
    let path = paths.socket();
    if path.exists() {
        if answers(&path) {
            return Err(format!(
                "another ewe-safed already answers on {}",
                path.display()
            ));
        }
        let _ = std::fs::remove_file(&path);
    }
    // never connectable by anyone else, not even for a moment
    // SAFETY: umask only changes this process's file-mode mask
    let old = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(&path);
    unsafe { libc::umask(old) };
    let l = bound.map_err(|e| format!("can't listen on {}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("can't make {} private: {e}", path.display()))?;
    Ok((l, Some(path)))
}

/// systemd's `LISTEN_FDS`: the socket is fd 3. A unit that also listens
/// for the SSH agent passes its socket too; each fd is told apart by the
/// path it is bound to, and the agent's waits for agent.rs.
fn activated() -> Option<UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let fds: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if pid != std::process::id() || fds < 1 {
        return None;
    }
    // SAFETY: still one thread (main runs this first), so nothing reads the
    // environment while it changes; fds 3… are ours by the activation protocol
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
        let mut main = None;
        for fd in 3..3 + fds {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            if !crate::agent::claim(fd) && main.is_none() {
                main = Some(fd);
            }
        }
        main.map(|fd| UnixListener::from_raw_fd(fd))
    }
}

/// A live daemon answers a ping within two seconds.
fn answers(path: &PathBuf) -> bool {
    let Ok(mut s) = UnixStream::connect(path) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"{\"v\":1,\"id\":0,\"verb\":\"ping\"}\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    matches!(s.read(&mut buf), Ok(n) if n > 0)
}

pub fn serve(l: UnixListener, d: Arc<Daemon>) {
    for conn in l.incoming() {
        match conn {
            Ok(s) => {
                let d = d.clone();
                std::thread::spawn(move || handle(s, d));
            }
            Err(e) => log(&format!("accept: {e}")),
        }
    }
}

pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a ucred of exactly `len` bytes on a valid fd
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (r == 0).then_some(cred.uid)
}

fn handle(stream: UnixStream, d: Arc<Daemon>) {
    // SAFETY: getuid has no failure mode
    let me = unsafe { libc::getuid() };
    if peer_uid(&stream) != Some(me) {
        return;
    }
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut rd = BufReader::new(read_half);
    let mut wr = stream;
    loop {
        let mut buf = Vec::new();
        let n = match (&mut rd)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
        {
            Ok(n) => n,
            Err(_) => return,
        };
        if n == 0 || buf.len() > MAX_LINE {
            buf.zeroize();
            return;
        }
        let req: Result<Value, _> = serde_json::from_slice(&buf);
        buf.zeroize();
        let Ok(mut req) = req else {
            if !reply(
                &mut wr,
                Value::Null,
                Err(Fail::bad("That isn't a JSON request.")),
            ) {
                return;
            }
            continue;
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let v = req.get("v").and_then(Value::as_u64);
        let verb = req
            .get("verb")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if v != Some(1) {
            let f = Fail::bad("This ewe-safed speaks protocol 1.");
            if !reply(&mut wr, id, Err(f)) {
                return;
            }
            continue;
        }
        if verb == "subscribe" {
            if reply(&mut wr, id, Ok(json!({"subscribed": true}))) {
                events(&d, &mut wr);
            }
            return;
        }
        let mut args = match req.get_mut("args").map(Value::take) {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        let out = verbs::dispatch(&d, &verb, &mut args);
        // anything secret left in the request goes with it
        drop(args);
        drop(req);
        if !reply(&mut wr, id, out) {
            return;
        }
    }
}

fn reply(wr: &mut UnixStream, id: Value, out: Result<Value, Fail>) -> bool {
    let mut v = match out {
        Ok(mut v) => {
            v["ok"] = json!(true);
            v
        }
        Err(f) => f.to_json(),
    };
    v["v"] = json!(1);
    v["id"] = id;
    let mut line = v.to_string();
    line.push('\n');
    let ok = wr.write_all(line.as_bytes()).is_ok() && wr.flush().is_ok();
    line.zeroize();
    ok
}

/// A subscriber's connection: event lines until it goes away.
fn events(d: &Daemon, wr: &mut UnixStream) {
    let rx = d.subscribe();
    loop {
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => {
                if wr.write_all(line.as_bytes()).is_err() || wr.flush().is_err() {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if closed(wr) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The peer hung up (a read would see the end of the stream).
fn closed(s: &UnixStream) -> bool {
    let mut b = [0u8; 1];
    // SAFETY: a one-byte peek into a local buffer on a valid fd
    let r = unsafe {
        libc::recv(
            s.as_raw_fd(),
            b.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    r == 0
}
