//! The window's SSH key commands (docs/PROTOCOL.md, "SSH keys"): one per
//! `ssh-*` verb. A key file is read here (a file bigger than a key is not
//! read at all) and its text sent as `private_key`; it and the key's
//! passphrase are secrets like the master password: moved into the
//! request and wiped once it is sent.

use serde_json::{Map, Value, json};

use super::{call, put_secret, with};

/// The same limit as the daemon's (`safe_core::ssh::MAX_KEY_FILE`).
const MAX_KEY_FILE: u64 = 1024 * 1024;

/// A private key file's text; one bigger than a key is not read.
fn read_key(file: &str) -> Result<String, String> {
    use std::io::Read;
    let cant = |e: std::io::Error| format!("Safe can't read {file}: {e}.");
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
