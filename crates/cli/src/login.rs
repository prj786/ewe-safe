//! `ewe-safe login <status|enable|disable>` (docs/SYSTEM.md §2): turn login
//! unlock on or off on this computer. `enable` checks the login password with
//! `/usr/bin/unix_chkpwd` (the daemon can't — `NoNewPrivileges` blocks the
//! setuid helper), then hands it, and the master password when the safe is
//! locked, to the daemon. The password comes from the terminal (no echo) or a
//! stdin line, never from the command line.

use std::io::Write;
use std::process::{Command, Stdio};

use safe_client as client;
use safe_client::{FAST, SLOW};
use serde_json::{Map, Value, json};

use super::{bad, ok, secret};

const SUBS: &[&str] = &["status", "enable", "disable"];

pub fn run(argv: &[String]) -> Value {
    let sub = argv.first().map(String::as_str).unwrap_or("");
    if argv.len() > 1 {
        return bad(format!("ewe-safe login {sub} takes no more arguments."));
    }
    match sub {
        "status" => client::call("login-status", json!({}), FAST),
        "disable" => client::call("login-disable", json!({}), FAST),
        "enable" => enable(),
        "" => {
            let mut v = bad("Usage: ewe-safe login <status|enable|disable>");
            v["verbs"] = json!(
                SUBS.iter()
                    .map(|s| format!("login {s}"))
                    .collect::<Vec<_>>()
            );
            v
        }
        other => bad(format!("login has no {other:?}.")),
    }
}

fn enable() -> Value {
    let st = client::call("status", json!({}), FAST);
    if !ok(&st) {
        return st;
    }
    if st.get("set_up").and_then(Value::as_bool) != Some(true) {
        return json!({
            "ok": false,
            "error": "not-set-up",
            "message": "There is no safe on this computer yet.",
            "hint": "ewe-safe init --place nextcloud, or ewe-safe open --place nextcloud",
        });
    }
    let login_password = match secret("Your login password: ") {
        Ok(p) => p,
        Err(v) => return v,
    };
    // the daemon can't check it (NoNewPrivileges blocks the setuid helper)
    if let Err(v) = check_login_password(&login_password) {
        return v;
    }
    let mut args = Map::new();
    args.insert("login_password".into(), json!(login_password.as_str()));
    // a locked safe needs the master password to seal it under W
    if st.get("locked").and_then(Value::as_bool) == Some(true) {
        match secret("Master password for Safe: ") {
            Ok(p) => {
                args.insert("password".into(), json!(p.as_str()));
            }
            Err(v) => return v,
        }
    }
    client::call("login-enable", Value::Object(args), SLOW)
}

/// `unix_chkpwd "$USER" nullok` with the password on stdin; exit 0 = right.
/// `EWE_SAFE_CHKPWD` overrides the helper for tests (a fake reading stdin).
pub fn check_login_password(password: &str) -> Result<(), Value> {
    let helper =
        std::env::var("EWE_SAFE_CHKPWD").unwrap_or_else(|_| "/usr/bin/unix_chkpwd".to_string());
    let user = username();
    let mut child = match Command::new(&helper)
        .arg(&user)
        .arg("nullok")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Err(json!({
                "ok": false,
                "error": "internal",
                "message": format!("Couldn't check the login password ({e})."),
            }));
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        // no trailing newline: the helper takes the whole input as the password
        let _ = stdin.write_all(password.as_bytes());
    }
    match child.wait() {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(json!({
            "ok": false,
            "error": "wrong-key",
            "message": "That isn't your login password.",
        })),
        Err(e) => Err(json!({
            "ok": false,
            "error": "internal",
            "message": format!("Couldn't check the login password ({e})."),
        })),
    }
}

/// This user's name for `unix_chkpwd`: `$USER`, else the password database.
fn username() -> String {
    if let Ok(u) = std::env::var("USER").or_else(|_| std::env::var("LOGNAME"))
        && !u.is_empty()
    {
        return u;
    }
    // SAFETY: getpwuid returns a pointer into a static buffer or null; read it
    // at once and copy out. getuid has no failure mode.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if !pw.is_null() && !(*pw).pw_name.is_null() {
            return std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned();
        }
    }
    String::new()
}
