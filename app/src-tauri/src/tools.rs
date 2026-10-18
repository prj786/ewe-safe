//! The desktop around the window: the ewe tools it reads (`ewe-theme`,
//! `ewe-conf`, `ewe-cloud`), the open windows for "Pick a window…", links,
//! and ewe-sync. Every program runs as argv, never through a shell, with a
//! time limit; none of them ever sees a secret.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
}

/// An ewe tool (Python): a checkout named by `EWE_REPO`, the deployed
/// payload, then `/usr/bin` — the order ewe-sync uses.
fn ewe_tool(name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(repo) = std::env::var_os("EWE_REPO") {
        candidates.push(PathBuf::from(repo).join("bin").join(name));
    }
    candidates.push(home().join(".local/share/ewe/bin").join(name));
    candidates.push(PathBuf::from("/usr/bin").join(name));
    candidates.into_iter().find(|p| p.is_file())
}

/// Run `cmd` with a time limit; its stdout when it ran to the end.
fn run(mut cmd: Command, limit: Duration) -> Option<String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    reader.join().ok()
}

/// The last JSON line an ewe tool printed (the tools print one; a stray
/// warning line must not break the caller).
fn tool_json(name: &str, args: &[&str], limit: Duration) -> Value {
    let Some(path) = ewe_tool(name) else {
        return json!({"ok": false, "error": "missing", "message": format!("{name} is not installed.")});
    };
    let mut cmd = Command::new("python3");
    cmd.arg(path).args(args).env("LANG", "C");
    run(cmd, limit)
        .and_then(|s| {
            s.lines()
                .rev()
                .find_map(|l| serde_json::from_str::<Value>(l).ok())
        })
        .unwrap_or_else(|| json!({"ok": false, "error": "failed", "message": format!("{name} did not answer.")}))
}

/// The look of this machine (`ewe-theme show ewe`): the token map the page
/// lays over its compiled tokens.css, so the window follows the scheme,
/// light or dark, the accent and the accessibility modes.
pub fn theme_tokens() -> Value {
    tool_json("ewe-theme", &["show", "ewe"], Duration::from_secs(10))
}

/// A cheap fingerprint of the files the look comes from; the page asks
/// `theme_tokens` again only when it changes.
pub fn theme_key() -> String {
    let files = [
        config_home().join("quickshell/user-theme.json"),
        config_home().join("quickshell/theme-tokens.json"),
        config_home().join("ewe/ewe.conf"),
    ];
    files
        .iter()
        .map(|p| match std::fs::metadata(p).and_then(|m| m.modified()) {
            Ok(t) => format!("{:?}", t),
            Err(_) => "-".into(),
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// The `[safe]` keys the window may change (ewe-conf is their only writer;
/// ewe-safed reads them again within a minute).
pub const SETTINGS: &[&str] = &[
    "lock_after_minutes",
    "lock_on_screen_lock",
    "lock_on_sleep",
    "clipboard_clear_seconds",
    "generator_length",
    "generator_words",
    // login unlock (docs/SYSTEM.md §2): unlock the safe at login too
    "unlock_at_login",
];

/// `unix_chkpwd "$USER" nullok` with the login password on stdin; `ok: true`
/// when it's right (docs/SYSTEM.md §2). The daemon can't run it
/// (`NoNewPrivileges`), so the window does, like the CLI. `EWE_SAFE_CHKPWD`
/// replaces the helper for tests.
pub fn check_login_password(password: &str) -> Value {
    use std::io::Write;
    use std::process::Stdio;
    let helper =
        std::env::var("EWE_SAFE_CHKPWD").unwrap_or_else(|_| "/usr/bin/unix_chkpwd".to_string());
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
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
            return json!({"ok": false, "error": "internal", "message": format!("Couldn't check the login password ({e}).")});
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        // no trailing newline: the helper takes the whole input as the password
        let _ = stdin.write_all(password.as_bytes());
    }
    match child.wait() {
        Ok(status) if status.success() => json!({"ok": true}),
        Ok(_) => {
            json!({"ok": false, "error": "wrong-key", "message": "That isn't your login password."})
        }
        Err(e) => {
            json!({"ok": false, "error": "internal", "message": format!("Couldn't check the login password ({e}).")})
        }
    }
}

pub fn settings_get() -> Value {
    let v = tool_json("ewe-conf", &["get", "safe"], Duration::from_secs(10));
    if v.is_object() && v.get("error").is_none() {
        json!({"ok": true, "settings": v})
    } else if v.is_null() {
        json!({"ok": true, "settings": {}})
    } else {
        v
    }
}

pub fn settings_set(key: &str, value: &Value) -> Value {
    if !SETTINGS.contains(&key) {
        return json!({"ok": false, "error": "bad-request", "message": format!("Safe doesn't change {key}.")});
    }
    let raw = match value {
        Value::Bool(_) | Value::Number(_) => value.to_string(),
        _ => {
            return json!({"ok": false, "error": "bad-request", "message": "A setting is a number or a switch."});
        }
    };
    let dotted = format!("safe.{key}");
    let r = tool_json("ewe-conf", &["set", &dotted, &raw], Duration::from_secs(15));
    if r.get("ok").and_then(Value::as_bool) == Some(false) || r.get("error").is_some() {
        return r;
    }
    json!({"ok": true})
}

/// The Passwords plugin (`Super+P`) and its `provider` setting.
const PASSWORDS: &str = "ewe.passwords";

/// What `Super+P` fills from: the Passwords plugin's `provider` (`auto`,
/// `ewe`, `1password`, …) through `ewe-plugin get`; not `ok` when the
/// plugin isn't installed.
pub fn passwords_provider() -> Value {
    provider_reply(tool_json(
        "ewe-plugin",
        &["get", PASSWORDS, "provider"],
        Duration::from_secs(10),
    ))
}

/// `ewe-plugin get <id> <key>` prints the value as JSON (`"auto"`); a
/// plugin that isn't installed prints nothing on stdout.
fn provider_reply(v: Value) -> Value {
    match v {
        Value::String(p) => json!({"ok": true, "provider": p}),
        _ => {
            json!({"ok": false, "error": "failed", "message": "The Passwords plugin isn't installed."})
        }
    }
}

/// `Super+P` fills from Safe: `ewe-plugin set ewe.passwords provider ewe`,
/// the plugin-settings path (checked against the plugin's manifest, written
/// through ewe-conf, live). Never `ewe-conf set` on the dotted id.
pub fn use_safe_for_passwords() -> Value {
    let r = tool_json(
        "ewe-plugin",
        &["set", PASSWORDS, "provider", "ewe"],
        Duration::from_secs(30),
    );
    if r.get("ok").and_then(Value::as_bool) == Some(true) {
        return json!({"ok": true, "provider": "ewe"});
    }
    json!({"ok": false, "error": "failed", "message": "Couldn't change what Super+P fills from."})
}

/// The ewe account (`ewe-cloud status`, which never prompts): for "Your
/// ewe account" on the Place step.
pub fn cloud_status() -> Value {
    tool_json("ewe-cloud", &["status"], Duration::from_secs(10))
}

/// The classes of the open windows (Hyprland), for "Pick a window…": the
/// apps Super+P fills a login into. Safe's own windows are left out.
pub fn window_classes() -> Value {
    let mut cmd = Command::new("hyprctl");
    cmd.args(["clients", "-j"]);
    let Some(out) = run(cmd, Duration::from_secs(5)) else {
        return json!({"ok": true, "classes": []});
    };
    let mut classes: Vec<String> = serde_json::from_str::<Value>(&out)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.get("class").and_then(Value::as_str).map(str::to_string))
        .filter(|c| !c.is_empty() && !c.starts_with("ewe-safe"))
        .collect();
    classes.sort_by_key(|c| c.to_lowercase());
    classes.dedup();
    json!({"ok": true, "classes": classes})
}

/// A website from an item, in the user's browser. Only http(s).
pub fn open_url(url: &str) -> Value {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return json!({"ok": false, "error": "bad-request", "message": "Only web addresses open from Safe."});
    }
    spawn(Command::new("xdg-open").arg(url))
}

/// ewe-sync, where the ewe account is signed in (rule 6: one place for
/// the account and sync).
pub fn open_ewe_sync() -> Value {
    spawn(&mut Command::new("ewe-sync"))
}

fn spawn(cmd: &mut Command) -> Value {
    match cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(_) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "error": "failed", "message": e.to_string()}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_safe_settings_change_and_only_as_numbers_or_switches() {
        assert_eq!(
            settings_set("place", &json!("local"))["error"],
            "bad-request"
        );
        assert_eq!(
            settings_set("lock_after_minutes", &json!("thirty"))["error"],
            "bad-request"
        );
    }

    #[test]
    fn the_passwords_provider_is_a_json_string_or_nothing() {
        assert_eq!(
            provider_reply(json!("1password")),
            json!({"ok": true, "provider": "1password"})
        );
        for nothing in [
            json!({"ok": false, "error": "failed"}),
            json!({"ok": false, "error": "missing"}),
            Value::Null,
        ] {
            assert_eq!(provider_reply(nothing)["ok"], false);
        }
    }

    #[test]
    fn only_web_addresses_open() {
        assert_eq!(open_url("file:///etc/passwd")["error"], "bad-request");
        assert_eq!(open_url("javascript:alert(1)")["error"], "bad-request");
    }
}
