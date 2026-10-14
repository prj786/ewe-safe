//! One request to `ewe-safed` and its reply, over
//! `$XDG_RUNTIME_DIR/ewe-safe.sock` (docs/PROTOCOL.md). The daemon must be
//! this user's: `SO_PEERCRED` is checked from this end too.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroize;

/// `$XDG_RUNTIME_DIR/ewe-safe.sock`; `EWE_SAFE_SOCKET` is a test switch (a
/// sandboxed daemon, while the Wayland display stays the session's).
pub fn socket() -> PathBuf {
    if let Some(p) = std::env::var_os("EWE_SAFE_SOCKET").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // SAFETY: getuid has no failure mode
            PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }))
        });
    dir.join("ewe-safe.sock")
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

/// Send one request; the reply without `v` and `id`. A slow verb (unlock,
/// a save, sync) gets `wait`; nothing waits forever.
pub fn call(verb: &str, args: Value, wait: Duration) -> Value {
    let path = socket();
    let mut s = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => return unavailable(&e.to_string()),
    };
    // SAFETY: getuid has no failure mode
    if peer_uid(&s) != Some(unsafe { libc::getuid() }) {
        return unavailable("the socket belongs to another user");
    }
    let _ = s.set_read_timeout(Some(wait));
    let mut line = json!({"v": 1, "id": 1, "verb": verb, "args": args}).to_string();
    line.push('\n');
    let sent = s.write_all(line.as_bytes()).and_then(|_| s.flush());
    line.zeroize();
    if let Err(e) = sent {
        return unavailable(&e.to_string());
    }
    let mut reply = String::new();
    let got = BufReader::new(&s).read_line(&mut reply);
    let v = match got {
        Ok(n) if n > 0 => serde_json::from_str::<Value>(&reply).ok(),
        _ => None,
    };
    reply.zeroize();
    match v {
        Some(Value::Object(mut m)) => {
            m.remove("v");
            m.remove("id");
            Value::Object(m)
        }
        _ => json!({
            "ok": false,
            "error": "internal",
            "message": "Safe's service didn't answer in time.",
        }),
    }
}
