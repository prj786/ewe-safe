//! The window's SSH key commands (docs/PROTOCOL.md, "SSH keys"): one per
//! `ssh-*` verb. A key file is read by the daemon itself (same uid): the
//! page sends its path. A key's passphrase is a secret like the master
//! password: moved into the request and wiped once it is sent.

use serde_json::{Map, Value};

use super::{call, put_secret, with};

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
    let mut a = with(&[
        ("file", Some(Value::from(file))),
        (
            "title",
            title.filter(|t| !t.trim().is_empty()).map(Value::from),
        ),
        ("folder", folder.map(Value::from)),
    ]);
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
