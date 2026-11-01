//! The window's SSH key commands (docs/PROTOCOL.md, "SSH keys"; docs/GATE.md
//! S21–S25): one per `ssh-*` verb. A key file is read here (a file bigger
//! than a key is not read at all) and its text sent as `private_key`; it and
//! the key's passphrase are secrets like the master password: moved into
//! the request and wiped once it is sent. `ssh-takeover`'s `passphrases`
//! (one per key file) are secrets too: never in argv, never logged.

use std::time::Duration;

use serde_json::{Map, Value, json};
use zeroize::Zeroize;

use super::{call, call_wait, put_secret, with};

/// The gate's verbs save the safe and talk to `ewe-conf` (and `ssh-test`
/// waits for a server): the slow wait, whatever safe-client knows of them.
const GATE_WAIT: Duration = safe_client::SLOW;
/// `ssh-test`: ssh's own ConnectTimeout is 10 s; a minute covers the rest.
const TEST_WAIT: Duration = Duration::from_secs(60);

/// The same limit as the daemon's (`safe_core::ssh::MAX_KEY_FILE`).
const MAX_KEY_FILE: u64 = 1024 * 1024;

/// A private key file's text; one bigger than a key is not read.
fn read_key(file: &str) -> Result<String, String> {
    use std::io::Read;
    let cant = |e: std::io::Error| format!("ewe Safe can’t read {file}: {e}.");
    let f = std::fs::File::open(file).map_err(cant)?;
    let size = f.metadata().map_err(cant)?.len();
    if size > MAX_KEY_FILE {
        return Err(format!("{file} is too big to be a private key."));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    f.take(MAX_KEY_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(cant)?;
    String::from_utf8(bytes).map_err(|e| {
        let mut b = e.into_bytes();
        zeroize::Zeroize::zeroize(&mut b);
        format!("{file} isn't a private key file: it isn't text.")
    })
}

#[tauri::command]
pub async fn ssh_add(
    file: String,
    title: Option<String>,
    folder: Option<String>,
    passphrase: Option<String>,
) -> Value {
    // a path typed as ~/.ssh/… is the user's home
    let file = match (
        file.strip_prefix("~/").map(str::to_string),
        std::env::var_os("HOME"),
    ) {
        (Some(rest), Some(home)) => std::path::Path::new(&home)
            .join(rest)
            .to_string_lossy()
            .into_owned(),
        _ => file,
    };
    let text = match read_key(&file) {
        Ok(t) => t,
        Err(message) => return json!({"ok": false, "error": "bad-request", "message": message}),
    };
    let name = std::path::Path::new(&file)
        .file_name()
        .map(|n| Value::from(n.to_string_lossy().into_owned()));
    let mut a = with(&[
        ("file_name", name),
        (
            "title",
            title.filter(|t| !t.trim().is_empty()).map(Value::from),
        ),
        ("folder", folder.map(Value::from)),
    ]);
    put_secret(&mut a, "private_key", text);
    if let Some(p) = passphrase.filter(|p| !p.is_empty()) {
        put_secret(&mut a, "passphrase", p);
    }
    call("ssh-add", a).await
}

#[tauri::command]
pub async fn ssh_new(
    title: String,
    key_type: Option<String>,
    bits: Option<u64>,
    folder: Option<String>,
) -> Value {
    let a = with(&[
        ("title", Some(Value::from(title))),
        ("type", key_type.map(Value::from)),
        ("bits", bits.map(Value::from)),
        ("folder", folder.map(Value::from)),
    ]);
    call("ssh-new", a).await
}

#[tauri::command]
pub async fn ssh_adopt(dry_run: Option<bool>) -> Value {
    call("ssh-adopt", with(&[("dry_run", dry_run.map(Value::from))])).await
}

#[tauri::command]
pub async fn ssh_enable(confirm: Option<String>) -> Value {
    call("ssh-enable", with(&[("confirm", confirm.map(Value::from))])).await
}

#[tauri::command]
pub async fn ssh_disable() -> Value {
    call("ssh-disable", Map::new()).await
}

/// The agent's state; `points_here` answers for this window's own
/// `SSH_AUTH_SOCK`.
#[tauri::command]
pub async fn ssh_status() -> Value {
    let sock = std::env::var("SSH_AUTH_SOCK").ok().map(Value::from);
    call("ssh-status", with(&[("ssh_auth_sock", sock)])).await
}

/// `ssh-takeover` (GATE.md S23): moves SSH to Safe — the gate on, the key
/// files in `~/.ssh` into the safe, the ewe.conf hosts that name another
/// agent fixed. `passphrases` maps a key file's path to its passphrase
/// (secrets: an empty one is left out, and every one the page sent is
/// wiped here when it isn't sent on).
#[tauri::command]
pub async fn ssh_takeover(dry_run: Option<bool>, passphrases: Option<Map<String, Value>>) -> Value {
    let mut a = with(&[("dry_run", dry_run.map(Value::from))]);
    let mut pass = Map::new();
    for (file, v) in passphrases.unwrap_or_default() {
        match v {
            Value::String(p) if !p.is_empty() && !file.is_empty() => {
                pass.insert(file, Value::String(p));
            }
            Value::String(mut p) => p.zeroize(),
            _ => {}
        }
    }
    if !pass.is_empty() {
        a.insert("passphrases".into(), Value::Object(pass));
    }
    call_wait("ssh-takeover", a, GATE_WAIT).await
}

/// The services Safe connects to (GATE.md S24): the daemon's one list.
#[tauri::command]
pub async fn ssh_services() -> Value {
    call("ssh-services", Map::new()).await
}

/// `ssh-connect` (GATE.md S24): a key (`key`, or a new one titled
/// `title`), its public file, the host in ewe.conf (git services, and any
/// service given `host`). The window passes `no_open` and opens the page
/// itself when the user asks.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn ssh_connect(
    service: String,
    key: Option<String>,
    title: Option<String>,
    host: Option<String>,
    user: Option<String>,
    port: Option<u64>,
    alias: Option<String>,
    org: Option<String>,
    replace: Option<bool>,
    sign: Option<bool>,
    no_open: Option<bool>,
) -> Value {
    let a = with(&[
        ("service", Some(Value::from(service))),
        ("key", key.map(Value::from)),
        ("title", text(title)),
        ("host", text(host)),
        ("user", text(user)),
        ("port", port.map(Value::from)),
        ("alias", text(alias)),
        ("org", text(org)),
        ("replace", replace.map(Value::from)),
        ("sign", sign.map(Value::from)),
        ("no_open", no_open.map(Value::from)),
    ]);
    call_wait("ssh-connect", a, GATE_WAIT).await
}

/// `ssh-test` (GATE.md S24): does the connection work? `target` is an
/// alias, a service or `user@host[:port]`; `key` limits it to one key.
#[tauri::command]
pub async fn ssh_test(target: String, key: Option<String>) -> Value {
    let a = with(&[
        ("target", Some(Value::from(target))),
        ("key", key.map(Value::from)),
    ]);
    call_wait("ssh-test", a, TEST_WAIT).await
}

/// Every host `ssh` knows: ewe.conf's and the user's own lines.
#[tauri::command]
pub async fn ssh_hosts() -> Value {
    call("ssh-hosts", Map::new()).await
}

/// Add or change an ewe.conf host (never the user's own lines).
#[tauri::command]
pub async fn ssh_host_set(
    alias: String,
    host: Option<String>,
    user: Option<String>,
    port: Option<u64>,
    key: Option<String>,
    no_key: Option<bool>,
) -> Value {
    let a = with(&[
        ("alias", Some(Value::from(alias))),
        ("host", text(host)),
        ("user", text(user)),
        ("port", port.map(Value::from)),
        ("key", key.map(Value::from)),
        ("no_key", no_key.map(Value::from)),
    ]);
    call_wait("ssh-host-set", a, GATE_WAIT).await
}

#[tauri::command]
pub async fn ssh_host_remove(alias: String) -> Value {
    call_wait(
        "ssh-host-remove",
        with(&[("alias", Some(Value::from(alias)))]),
        GATE_WAIT,
    )
    .await
}

/// Sign Git commits with a key (GATE.md S25), or stop (`off`).
#[tauri::command]
pub async fn ssh_sign(item_id: Option<String>, email: Option<String>, off: Option<bool>) -> Value {
    let a = with(&[
        ("item_id", item_id.map(Value::from)),
        ("email", text(email)),
        ("off", off.map(Value::from)),
    ]);
    call_wait("ssh-sign", a, GATE_WAIT).await
}

/// A field the page may send empty: empty is left out.
fn text(v: Option<String>) -> Option<Value> {
    v.map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(Value::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_fields_are_left_out() {
        assert_eq!(text(Some("  ".into())), None);
        assert_eq!(text(None), None);
        assert_eq!(text(Some(" github.com ".into())), Some(json!("github.com")));
    }
}
