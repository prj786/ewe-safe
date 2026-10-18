//! `ewe-safe login <status|enable|disable>` (docs/SYSTEM.md §2): turn login
//! unlock on or off on this computer. `enable` checks the login password with
//! `/usr/bin/unix_chkpwd` (the daemon can't — `NoNewPrivileges` blocks the
//! setuid helper), then hands it, and the master password when the safe is
//! locked, to the daemon. The password comes from the terminal (no echo) or a
//! stdin line, never from the command line.

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

/// The login password, checked with `unix_chkpwd` the way pam_unix does
/// (`safe_client::chkpwd`: NUL-ended on stdin; `EWE_SAFE_CHKPWD` replaces the
/// helper for tests).
pub fn check_login_password(password: &str) -> Result<(), Value> {
    match safe_client::chkpwd::check(password) {
        Ok(true) => Ok(()),
        Ok(false) => Err(json!({
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
