//! The window's keyring commands (docs/PROTOCOL.md, "The keyring";
//! docs/KEYRING.md): who keeps the apps' passwords, the repair of the
//! prompt at every start, and the list of app secrets (names and dates,
//! never a secret). Taking over the keyring (`adopt`) waits for Safe's
//! login module, so the window has no command for it yet.

use serde_json::{Map, Value};

use super::{call, with};

#[tauri::command]
pub async fn keyring_status() -> Value {
    call("keyring-status", Map::new()).await
}

/// The running keyring's own window may ask for the second keyring's
/// password; the call waits for it (the import wait).
#[tauri::command]
pub async fn keyring_repair(dry_run: Option<bool>) -> Value {
    call(
        "keyring-repair",
        with(&[("dry_run", dry_run.map(Value::from))]),
    )
    .await
}

#[tauri::command]
pub async fn keyring_list() -> Value {
    call("keyring-list", Map::new()).await
}
