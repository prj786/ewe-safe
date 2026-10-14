//! The Safe window's backend: one Tauri command per docs/PROTOCOL.md verb,
//! each a call to `ewe-safed` through safe-client (the CLI's client), and
//! the daemon's events forwarded to the webview.
//!
//! - Every call runs off the UI thread and has the protocol's wait; nothing
//!   waits forever. A daemon that isn't there answers `daemon-unavailable`,
//!   a JSON reply the page shows as it is.
//! - Secrets from the page (`password`, `new_password`, `password_value`,
//!   `notes`) go into the request and are wiped once it is sent
//!   (`safe_client::scrub`). What Tauri's IPC kept of them is out of reach;
//!   the page drops its copy as soon as the call returns.
//! - `reveal` is the only command that returns a secret, and only when the
//!   page asks for that one field.
//! - Events: `safe-event` carries the daemon's events (never a title, a
//!   username or a value); `safe-daemon` says whether the daemon can be
//!   reached, on every change.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroize;

/// The keys each verb may send (PROTOCOL.md); anything else from the page
/// is dropped before it reaches the daemon.
const ITEM_KEYS: &[&str] = &[
    "kind",
    "title",
    "username",
    "url",
    "app",
    "tag",
    "folder",
    "generate",
    "length",
    "words",
    "password_value",
    "notes",
    "clear_url",
    "remove_app",
    "remove_tag",
];
const PLACE_KEYS: &[&str] = &["place", "location", "url", "user"];

/// Whether the daemon answered its event stream last time we looked.
#[derive(Default)]
struct Daemon(Mutex<Value>);

async fn call(verb: &'static str, args: Map<String, Value>) -> Value {
    let wait = safe_client::wait_for(verb);
    tauri::async_runtime::spawn_blocking(move || safe_client::call(verb, Value::Object(args), wait))
        .await
        .unwrap_or_else(|_| {
            json!({"ok": false, "error": "internal", "message": "The call to Safe's service failed."})
        })
}

/// `src` limited to `keys`, the null ones left out; a string that is
/// dropped is wiped first (it may be a secret sent under the wrong key).
fn only(src: Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in src {
        if keys.contains(&k.as_str()) && !v.is_null() {
            out.insert(k, v);
        } else if let Value::String(mut s) = v {
            s.zeroize();
        }
    }
    out
}

fn with(pairs: &[(&str, Option<Value>)]) -> Map<String, Value> {
    pairs
        .iter()
        .filter_map(|(k, v)| v.clone().map(|v| (k.to_string(), v)))
        .collect()
}

/// A secret from the page into the args: moved, never copied; safe-client
/// wipes it once the request is sent (or couldn't be).
fn put_secret(args: &mut Map<String, Value>, key: &str, value: String) {
    args.insert(key.to_string(), Value::String(value));
}

#[tauri::command]
async fn status() -> Value {
    call("status", Map::new()).await
}

#[tauri::command]
async fn summary() -> Value {
    call("summary", Map::new()).await
}

#[tauri::command]
async fn ping() -> Value {
    call("ping", Map::new()).await
}

#[tauri::command]
async fn version() -> Value {
    call("version", Map::new()).await
}

#[tauri::command]
async fn init(place: Map<String, Value>, password: String) -> Value {
    let mut a = only(place, PLACE_KEYS);
    put_secret(&mut a, "password", password);
    call("init", a).await
}

#[tauri::command]
async fn open(place: Map<String, Value>, password: String) -> Value {
    let mut a = only(place, PLACE_KEYS);
    put_secret(&mut a, "password", password);
    call("open", a).await
}

#[tauri::command]
async fn unlock(password: String) -> Value {
    let mut a = Map::new();
    put_secret(&mut a, "password", password);
    call("unlock", a).await
}

#[tauri::command]
async fn lock() -> Value {
    call("lock", Map::new()).await
}

#[tauri::command]
async fn list(kind: Option<String>, tag: Option<String>, deleted: Option<bool>) -> Value {
    let a = with(&[
        ("kind", kind.map(Value::from)),
        ("tag", tag.map(Value::from)),
        ("deleted", deleted.map(Value::from)),
    ]);
    call("list", a).await
}

#[tauri::command]
async fn search(text: String) -> Value {
    call("search", with(&[("text", Some(Value::from(text)))])).await
}

/// `match` (a Rust keyword, hence the name).
#[tauri::command]
async fn match_items(
    class: Option<String>,
    title: Option<String>,
    url: Option<String>,
    query: Option<String>,
    limit: Option<u64>,
) -> Value {
    let a = with(&[
        ("class", class.map(Value::from)),
        ("title", title.map(Value::from)),
        ("url", url.map(Value::from)),
        ("query", query.map(Value::from)),
        ("limit", limit.map(Value::from)),
    ]);
    call("match", a).await
}

#[tauri::command]
async fn show(id: String, reveal_notes: Option<bool>) -> Value {
    let a = with(&[
        ("id", Some(Value::from(id))),
        ("reveal_notes", reveal_notes.map(Value::from)),
    ]);
    call("show", a).await
}

/// The one command that returns a secret: one field of one item, on demand.
#[tauri::command]
async fn reveal(id: String, field: String) -> Value {
    let a = with(&[
        ("id", Some(Value::from(id))),
        ("field", Some(Value::from(field))),
    ]);
    call("reveal", a).await
}

#[tauri::command]
async fn copy(id: String, field: String, clear_after: Option<u64>) -> Value {
    let a = with(&[
        ("id", Some(Value::from(id))),
        ("field", Some(Value::from(field))),
        ("clear_after", clear_after.map(Value::from)),
        // the daemon runs wl-copy on the display this window is on
        (
            "wayland_display",
            std::env::var("WAYLAND_DISPLAY").ok().map(Value::from),
        ),
    ]);
    call("copy", a).await
}

#[tauri::command]
async fn add(item: Map<String, Value>) -> Value {
    call("add", only(item, ITEM_KEYS)).await
}

#[tauri::command]
async fn edit(id: String, item: Map<String, Value>) -> Value {
    let mut a = only(item, ITEM_KEYS);
    a.insert("id".into(), Value::from(id));
    call("edit", a).await
}

#[tauri::command]
async fn rm(id: String) -> Value {
    call("rm", with(&[("id", Some(Value::from(id)))])).await
}

#[tauri::command]
async fn restore(id: String) -> Value {
    call("restore", with(&[("id", Some(Value::from(id)))])).await
}

#[tauri::command]
async fn generate(
    length: Option<u64>,
    words: Option<u64>,
    no_symbols: Option<bool>,
    no_digits: Option<bool>,
) -> Value {
    let a = with(&[
        ("length", length.map(Value::from)),
        ("words", words.map(Value::from)),
        ("no_symbols", no_symbols.map(Value::from)),
        ("no_digits", no_digits.map(Value::from)),
    ]);
    call("generate", a).await
}

#[tauri::command]
async fn sync() -> Value {
    call("sync", Map::new()).await
}

#[tauri::command]
async fn place() -> Value {
    call("place", Map::new()).await
}

/// `password` is the current one, needed only while the safe is locked.
#[tauri::command]
async fn passwd(password: Option<String>, new_password: String) -> Value {
    let mut a = Map::new();
    if let Some(p) = password {
        put_secret(&mut a, "password", p);
    }
    put_secret(&mut a, "new_password", new_password);
    call("passwd", a).await
}

/// The last thing the event stream said about the daemon, for a page that
/// loads after the first `safe-daemon` event was sent.
#[tauri::command]
fn daemon_state(d: tauri::State<'_, Daemon>) -> Value {
    d.0.lock().map(|v| v.clone()).unwrap_or(Value::Null)
}

fn set_daemon(app: &AppHandle, v: Value) {
    let d = app.state::<Daemon>();
    let mut cur = match d.0.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if *cur != v {
        *cur = v.clone();
        let _ = app.emit("safe-daemon", v);
    }
}

/// Subscribe, forward, and when the daemon goes away try again: 1 s, then
/// doubling up to 30 s. Subscribing also starts a socket-activated daemon.
fn forward_events(app: AppHandle) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match safe_client::subscribe() {
            Ok(mut ev) => {
                set_daemon(&app, json!({"available": true}));
                backoff = Duration::from_secs(1);
                loop {
                    match ev.next(Duration::from_secs(30)) {
                        safe_client::Next::Event(v) => {
                            let _ = app.emit("safe-event", v);
                        }
                        safe_client::Next::Quiet => continue,
                        safe_client::Next::Closed => break,
                    }
                }
                set_daemon(
                    &app,
                    json!({
                        "available": false,
                        "error": "daemon-unavailable",
                        "message": "Safe's service stopped. Trying again…",
                    }),
                );
            }
            Err(mut v) => {
                if let Value::Object(m) = &mut v {
                    m.remove("ok");
                    m.insert("available".into(), Value::from(false));
                }
                set_daemon(&app, v);
            }
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // a second launch (the launcher, the picker) brings the window back
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .manage(Daemon::default())
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("safe-events".into())
                .spawn(move || forward_events(handle))?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            summary,
            ping,
            version,
            init,
            open,
            unlock,
            lock,
            list,
            search,
            match_items,
            show,
            reveal,
            copy,
            add,
            edit,
            rm,
            restore,
            generate,
            sync,
            place,
            passwd,
            daemon_state,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Safe window");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_keeps_the_protocol_keys() {
        let m = json!({"title": "A", "password_value": "p", "evil": 1, "notes": null})
            .as_object()
            .cloned()
            .unwrap();
        let a = only(m, ITEM_KEYS);
        assert_eq!(
            Value::Object(a),
            json!({"title": "A", "password_value": "p"})
        );
    }

    #[test]
    fn with_leaves_out_what_is_missing() {
        let a = with(&[("kind", Some(Value::from("login"))), ("tag", None)]);
        assert_eq!(Value::Object(a), json!({"kind": "login"}));
    }

    #[test]
    fn every_secret_key_the_page_can_send_is_one_safe_client_scrubs() {
        for k in ["password", "new_password", "password_value", "notes"] {
            assert!(safe_client::SECRET_KEYS.contains(&k), "{k}");
        }
    }
}
