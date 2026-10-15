//! safe-client — talking to `ewe-safed` over
//! `$XDG_RUNTIME_DIR/ewe-safe.sock` (docs/PROTOCOL.md v1). The CLI and the
//! Safe window use this one implementation.
//!
//! - [`call`]: one request on its own connection (the CLI).
//! - [`Connection`]: many requests on one connection (the window).
//! - [`subscribe`]: the event stream.
//!
//! The daemon must be this user's: `SO_PEERCRED` is checked from this end
//! too. Secrets in a request's args are wiped once the line is sent
//! ([`scrub`]); a reply that carries one (`reveal`) is the caller's to wipe.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroize;

pub const PROTOCOL: u64 = 1;
/// Verbs that answer from memory.
pub const FAST: Duration = Duration::from_secs(30);
/// Verbs that derive a key or talk to the place (the place's own timeout is
/// two minutes).
pub const SLOW: Duration = Duration::from_secs(300);
/// `import`: `op` asks the 1Password app for every item, one by one.
pub const IMPORT: Duration = Duration::from_secs(1800);
/// The arg keys that carry a secret (PROTOCOL.md, "The socket").
pub const SECRET_KEYS: &[&str] = &["password", "new_password", "password_value", "notes"];

/// How long a verb may take: a key derivation or a talk with the place
/// gets [`SLOW`], an import [`IMPORT`], everything else [`FAST`].
pub fn wait_for(verb: &str) -> Duration {
    match verb {
        "import" => IMPORT,
        "init" | "open" | "unlock" | "passwd" | "add" | "edit" | "rm" | "restore" | "sync"
        | "place" => SLOW,
        // it saves, as `add` does
        "passkey-create" => SLOW,
        _ => FAST,
    }
}

/// `$XDG_RUNTIME_DIR/ewe-safe.sock`; `EWE_SAFE_SOCKET` is a test switch (a
/// sandboxed daemon, while the Wayland display stays the session's).
pub fn socket() -> PathBuf {
    if let Some(p) = std::env::var_os("EWE_SAFE_SOCKET").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", uid())));
    dir.join("ewe-safe.sock")
}

fn uid() -> u32 {
    // SAFETY: getuid has no failure mode
    unsafe { libc::getuid() }
}

fn peer_uid(s: &UnixStream) -> Option<u32> {
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

pub fn unavailable(why: &str) -> Value {
    json!({
        "ok": false,
        "error": "daemon-unavailable",
        "message": format!("Safe's service isn't running ({why})."),
        "hint": "systemctl --user start ewe-safe.socket",
    })
}

fn no_answer() -> Value {
    json!({
        "ok": false,
        "error": "internal",
        "message": "Safe's service didn't answer in time.",
    })
}

/// Wipe every secret string in `args` ([`SECRET_KEYS`]) in place.
pub fn scrub(args: &mut Value) {
    if let Value::Object(m) = args {
        for k in SECRET_KEYS {
            if let Some(Value::String(s)) = m.get_mut(*k) {
                s.zeroize();
            }
        }
    }
}

fn connect(path: &Path) -> Result<UnixStream, Value> {
    let s = UnixStream::connect(path).map_err(|e| unavailable(&e.to_string()))?;
    if peer_uid(&s) != Some(uid()) {
        return Err(unavailable("the socket belongs to another user"));
    }
    let _ = s.set_write_timeout(Some(FAST));
    Ok(s)
}

/// Counts what would be written, so the request line is allocated once at
/// its exact size: a buffer that grew would leave copies behind, unwiped.
struct Count(usize);

impl Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len();
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn send(s: &mut UnixStream, id: u64, verb: &str, args: Value) -> Result<(), Value> {
    let mut req = json!({"v": PROTOCOL, "id": id, "verb": verb, "args": args});
    let mut n = Count(0);
    let _ = serde_json::to_writer(&mut n, &req);
    let mut line = Vec::with_capacity(n.0 + 1);
    let made = serde_json::to_writer(&mut line, &req);
    if let Some(a) = req.get_mut("args") {
        scrub(a);
    }
    line.push(b'\n');
    let sent = match made {
        Ok(()) => s.write_all(&line).and_then(|_| s.flush()),
        Err(e) => Err(std::io::Error::other(e)),
    };
    line.zeroize();
    sent.map_err(|e| unavailable(&e.to_string()))
}

/// One line, wiped after parsing. `Ok(None)` = the daemon hung up.
fn read_line(r: &mut BufReader<UnixStream>) -> std::io::Result<Option<Value>> {
    let mut buf = String::new();
    let n = r.read_line(&mut buf);
    let v = match n {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(
            serde_json::from_str::<Value>(&buf).unwrap_or(Value::Null),
        )),
        Err(e) => Err(e),
    };
    buf.zeroize();
    v
}

fn strip(v: Value) -> Value {
    match v {
        Value::Object(mut m) => {
            m.remove("v");
            m.remove("id");
            Value::Object(m)
        }
        _ => no_answer(),
    }
}

/// Send one request on its own connection; the reply without `v` and `id`.
/// Nothing waits longer than `wait`.
pub fn call(verb: &str, mut args: Value, wait: Duration) -> Value {
    match Connection::open_at(&socket()) {
        Ok(mut c) => c.call(verb, args, wait),
        Err(v) => {
            scrub(&mut args);
            v
        }
    }
}

/// Many requests, one at a time, on one connection.
pub struct Connection {
    reader: BufReader<UnixStream>,
    next_id: u64,
}

impl Connection {
    pub fn open() -> Result<Connection, Value> {
        Connection::open_at(&socket())
    }

    pub fn open_at(path: &Path) -> Result<Connection, Value> {
        Ok(Connection {
            reader: BufReader::new(connect(path)?),
            next_id: 1,
        })
    }

    /// The reply to this request (lines for other ids are skipped). A
    /// connection that failed answers `daemon-unavailable` and should be
    /// dropped; one that timed out answers `internal`.
    pub fn call(&mut self, verb: &str, args: Value, wait: Duration) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        if let Err(v) = send(self.reader.get_mut(), id, verb, args) {
            return v;
        }
        let _ = self.reader.get_ref().set_read_timeout(Some(wait));
        loop {
            match read_line(&mut self.reader) {
                Ok(Some(v)) if v.get("id").and_then(Value::as_u64) == Some(id) => {
                    return strip(v);
                }
                Ok(Some(_)) => continue,
                Ok(None) => return unavailable("it closed the connection"),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return no_answer();
                }
                Err(e) => return unavailable(&e.to_string()),
            }
        }
    }
}

pub enum Next {
    /// `{"v": 1, "event": …}` without `v`.
    Event(Value),
    /// Nothing within the wait; the stream is still open.
    Quiet,
    /// The daemon went away; subscribe again later.
    Closed,
}

/// The daemon's events (PROTOCOL.md, "Events"): never a title, a username
/// or a value.
pub struct Events {
    reader: BufReader<UnixStream>,
}

pub fn subscribe() -> Result<Events, Value> {
    subscribe_at(&socket())
}

pub fn subscribe_at(path: &Path) -> Result<Events, Value> {
    let mut s = connect(path)?;
    send(&mut s, 1, "subscribe", json!({}))?;
    let mut reader = BufReader::new(s);
    let _ = reader.get_ref().set_read_timeout(Some(FAST));
    match read_line(&mut reader) {
        Ok(Some(v)) if v.get("ok").and_then(Value::as_bool) == Some(true) => Ok(Events { reader }),
        Ok(Some(v)) => Err(strip(v)),
        Ok(None) => Err(unavailable("it closed the connection")),
        Err(e) => Err(unavailable(&e.to_string())),
    }
}

impl Events {
    pub fn next(&mut self, wait: Duration) -> Next {
        let _ = self.reader.get_ref().set_read_timeout(Some(wait));
        match read_line(&mut self.reader) {
            Ok(Some(Value::Object(mut m))) if m.contains_key("event") => {
                m.remove("v");
                Next::Event(Value::Object(m))
            }
            Ok(Some(_)) => Next::Quiet,
            Ok(None) => Next::Closed,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Next::Quiet
            }
            Err(_) => Next::Closed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_count_is_the_exact_size_so_the_line_never_grows() {
        let req =
            json!({"v": 1, "id": 7, "verb": "unlock", "args": {"password": "é ü ✓ \"quoted\"\n"}});
        let mut n = Count(0);
        serde_json::to_writer(&mut n, &req).unwrap();
        assert_eq!(n.0, serde_json::to_vec(&req).unwrap().len());
    }

    #[test]
    fn slow_verbs_get_the_long_wait() {
        for v in ["init", "open", "unlock", "passwd", "add", "edit", "sync"] {
            assert_eq!(wait_for(v), SLOW, "{v}");
        }
        for v in ["status", "summary", "match", "list", "reveal", "copy"] {
            assert_eq!(wait_for(v), FAST, "{v}");
        }
        assert_eq!(wait_for("import"), IMPORT);
    }
}
