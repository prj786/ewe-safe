//! The desktop around the window: the ewe tools it reads (`ewe-theme`,
//! `ewe-conf`, `ewe-cloud`, `ewe-remote`), the open windows for "Pick a
//! window…", links, terminals, and ewe-sync. Every program runs as argv,
//! never through a shell, with a time limit; none of them ever sees a
//! secret.

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
    // filling a card asks for the password again (docs/SYSTEM.md D5)
    "confirm_cards",
];

/// The login password, checked with `unix_chkpwd` the way pam_unix does
/// (`safe_client::chkpwd`: NUL-ended on stdin); `ok: true` when it's right
/// (docs/SYSTEM.md §2). The daemon can't run it (`NoNewPrivileges`), so the
/// window does, like the CLI. `EWE_SAFE_CHKPWD` replaces the helper for tests.
pub fn check_login_password(password: &str) -> Value {
    match safe_client::chkpwd::check(password) {
        Ok(true) => json!({"ok": true}),
        Ok(false) => {
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

/// A program on `PATH`, as a full path.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// A service's page (docs/GATE.md S24: GitHub's "New SSH key", …) in ewe
/// browser (`ewe-browser open <url>`), else the default browser. Only
/// http(s).
pub fn open_page(url: &str) -> Value {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return json!({"ok": false, "error": "bad-request", "message": "Only web addresses open from Safe."});
    }
    match which("ewe-browser") {
        Some(b) => spawn_detached(Command::new(b).args(["open", url])),
        None => spawn_detached(Command::new("xdg-open").arg(url)),
    }
}

/// Your ewe computers (RFC-009), from the account record and the
/// pairings, without asking the network (`ewe-remote status --offline`).
/// Only what the page shows: never this computer's pairing code. No
/// ewe-remote → `{ok: false, code: "missing"}` (the page hides the part).
pub fn remote_status() -> Value {
    remote_reply(tool_json(
        "ewe-remote",
        &["status", "--offline"],
        Duration::from_secs(15),
    ))
}

fn remote_reply(v: Value) -> Value {
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        let mut v = v;
        if let Value::Object(m) = &mut v {
            m.insert("ok".into(), Value::from(false));
            let code = m
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("failed")
                .to_string();
            m.insert("code".into(), Value::from(code));
        }
        return v;
    }
    const KEEP: &[&str] = &[
        "id",
        "name",
        "user",
        "online",
        "paired",
        "allowed",
        "sharing",
        "last_seen",
    ];
    let computers: Vec<Value> = v
        .get("computers")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter_map(Value::as_object)
                .map(|c| {
                    Value::Object(
                        c.iter()
                            .filter(|(k, _)| KEEP.contains(&k.as_str()))
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let this = v.get("this").cloned().unwrap_or(Value::Null);
    json!({
        "ok": true,
        "this": {"name": this.get("name"), "sharing": this.get("sharing")},
        "computers": computers,
    })
}

/// An ewe-remote computer id: 16 hex digits (ewe-remote's `ID_RE`).
fn remote_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A terminal on one of your ewe computers: `ewe-remote terminal <id>`
/// (kitty, already signed in with that computer's own key).
pub fn remote_terminal(id: &str) -> Value {
    if !remote_id(id) {
        return json!({"ok": false, "error": "bad-request", "message": "That isn't an ewe computer."});
    }
    tool_json("ewe-remote", &["terminal", id], Duration::from_secs(30))
}

/// A host alias `ssh` can take as its one argument: no option (`-…`), no
/// space, no pattern.
fn ssh_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 255
        && !alias.starts_with('-')
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@:+[]%".contains(&b))
}

/// A kitty terminal that runs `ssh <alias>`, on its own (closing Safe
/// leaves it open). With the gate on, that ssh asks Safe for the key.
pub fn ssh_terminal(alias: &str) -> Value {
    if !ssh_alias(alias) {
        return json!({"ok": false, "error": "bad-request", "message": "That isn't a host name ssh can open."});
    }
    let Some(kitty) = which("kitty") else {
        return json!({"ok": false, "error": "missing", "message": "kitty is not installed."});
    };
    spawn_detached(Command::new(kitty).args(["--title", alias, "ssh", alias]))
}

/// Start a program in its own process group (it outlives the window) and
/// reap it when it ends.
fn spawn_detached(cmd: &mut Command) -> Value {
    use std::os::unix::process::CommandExt;
    match cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            json!({"ok": true})
        }
        Err(e) => json!({"ok": false, "error": "failed", "message": e.to_string()}),
    }
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
        assert_eq!(open_page("file:///etc/passwd")["error"], "bad-request");
    }

    #[test]
    fn a_terminal_opens_only_a_plain_host() {
        for ok in [
            "github.com",
            "work-proxy",
            "github-work",
            "sam@emoh.lan",
            "10.0.0.2",
        ] {
            assert!(ssh_alias(ok), "{ok}");
        }
        for bad in [
            "",
            "-oProxyCommand=x",
            "a b",
            "*",
            "host?",
            "!x",
            "a;b",
            "$(x)",
        ] {
            assert!(!ssh_alias(bad), "{bad}");
        }
        assert_eq!(ssh_terminal("-oProxyCommand=x")["error"], "bad-request");
        assert!(remote_id("0123456789abcdef"));
        assert!(!remote_id("0123456789ABCDEF") && !remote_id("--help"));
    }

    #[test]
    fn remote_status_keeps_what_the_page_shows() {
        let v = remote_reply(json!({
            "ok": true,
            "this": {"name": "laptop", "sharing": true, "code": "12345678", "code_display": "1234 5678"},
            "computers": [{"id": "0123456789abcdef", "name": "desk", "online": true, "paired": true, "addresses": {"lan": ["10.0.0.2"]}}],
        }));
        assert_eq!(v["ok"], true);
        assert!(v["this"].get("code").is_none() && v["this"].get("code_display").is_none());
        assert_eq!(v["computers"][0]["name"], "desk");
        assert!(v["computers"][0].get("addresses").is_none());
        let m = remote_reply(
            json!({"ok": false, "error": "missing", "message": "ewe-remote is not installed."}),
        );
        assert_eq!(
            (m["ok"].clone(), m["code"].clone()),
            (json!(false), json!("missing"))
        );
    }
}
