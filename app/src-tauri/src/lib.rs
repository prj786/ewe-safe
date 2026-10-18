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

//! - Launch: `ewe-safe-app` opens the window (one instance; a second
//!   launch hands its arguments to it as `safe-args`); `--show <id>`,
//!   `--new` and `--import` open those views; `--unlock` is a separate,
//!   compact process that only unlocks (app_id `ewe-safe-unlock`, which
//!   ewe's hyprland.lua floats at 560×200) and exits once the safe is open.
//! - `--approve` is the SSH agent's question, the same kind of compact
//!   process (and app_id, so it floats the same): "Allow ssh (from git) to
//!   use GitHub key?". The daemon names the app and the key in
//!   `EWE_SAFE_APPROVE_APP` and `EWE_SAFE_APPROVE_KEY`; the exit code is the
//!   answer (0 allow, 1 deny).

mod keyring;
mod ssh;
mod tools;

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;
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
    "remove_passkey",
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
        ("wayland_display", wayland_display().map(Value::from)),
    ]);
    call("copy", a).await
}

/// This window's Wayland display as an absolute socket path, so the daemon
/// reaches it whatever its own runtime directory is.
fn wayland_display() -> Option<String> {
    let d = std::env::var("WAYLAND_DISPLAY")
        .ok()
        .filter(|d| !d.is_empty())?;
    if d.starts_with('/') {
        return Some(d);
    }
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(r) if !r.is_empty() => Some(format!("{r}/{d}")),
        _ => Some(d),
    }
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

/// `import` (PROTOCOL.md, docs/IMPORT.md): a file the daemon reads itself
/// (same uid), or `op` (the 1Password app's CLI) with no file. It can take
/// minutes: `op`'s first call waits for the user to approve Safe.
#[tauri::command]
async fn import_items(
    format: String,
    file: Option<String>,
    dry_run: Option<bool>,
    folder: Option<String>,
    skip_duplicates: Option<bool>,
    vault: Option<String>,
) -> Value {
    let a = with(&[
        ("format", Some(Value::from(format))),
        ("file", file.map(Value::from)),
        ("dry_run", dry_run.map(Value::from)),
        ("folder", folder.map(Value::from)),
        ("skip_duplicates", skip_duplicates.map(Value::from)),
        // PROTOCOL.md: `vault` is a list (repeatable on the CLI)
        ("vault", vault.map(|v| Value::from(vec![v]))),
    ]);
    tauri::async_runtime::spawn_blocking(move || {
        safe_client::call("import", Value::Object(a), safe_client::wait_for("import"))
    })
    .await
    .unwrap_or_else(|_| json!({"ok": false, "error": "internal", "message": "The import failed."}))
}

/// The SSH agent's question, from the daemon's environment: the app, the
/// key's name, the app's full paths, and whether both are system programs
/// (a same-uid program can take any name: the paths say which it is).
#[derive(Clone, Debug, Default, PartialEq)]
struct Approve {
    app: String,
    key: String,
    path: String,
    system: bool,
}

/// What this process was started with (see the module notes).
#[derive(Clone, Debug, Default, PartialEq)]
struct Launch {
    unlock: bool,
    /// The SSH agent's question.
    approve: Option<Approve>,
    show: Option<String>,
    new: bool,
    import: bool,
}

impl Launch {
    fn parse<I: IntoIterator<Item = String>>(args: I) -> Launch {
        let mut l = Launch::default();
        let mut it = args.into_iter().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--unlock" => l.unlock = true,
                "--approve" => {
                    let env = |k: &str| std::env::var(k).unwrap_or_default();
                    l.approve = Some(Approve {
                        app: env("EWE_SAFE_APPROVE_APP"),
                        key: env("EWE_SAFE_APPROVE_KEY"),
                        path: env("EWE_SAFE_APPROVE_PATH"),
                        system: env("EWE_SAFE_APPROVE_SYSTEM") == "1",
                    });
                }
                "--new" => l.new = true,
                "--import" => l.import = true,
                "--show" => l.show = it.next().filter(|id| id.len() <= 64),
                _ => {}
            }
        }
        l
    }

    /// A compact process of its own: no single instance, a small window.
    fn compact(&self) -> bool {
        self.unlock || self.approve.is_some()
    }

    fn json(&self) -> Value {
        let mode = if self.approve.is_some() {
            "approve"
        } else if self.unlock {
            "unlock"
        } else {
            "main"
        };
        json!({
            "mode": mode,
            "approve": self.approve.as_ref().map(|a| json!({"app": a.app, "key": a.key, "path": a.path, "system": a.system})),
            "show": self.show,
            "new": self.new,
            "import": self.import,
        })
    }
}

#[tauri::command]
fn launch_args(l: tauri::State<'_, Launch>) -> Value {
    l.json()
}

#[tauri::command]
async fn theme_tokens() -> Value {
    blocking(tools::theme_tokens).await
}

#[tauri::command]
async fn theme_key() -> Value {
    blocking(|| Value::from(tools::theme_key())).await
}

#[tauri::command]
async fn settings_get() -> Value {
    blocking(tools::settings_get).await
}

#[tauri::command]
async fn settings_set(key: String, value: Value) -> Value {
    blocking(move || tools::settings_set(&key, &value)).await
}

#[tauri::command]
async fn passwords_provider() -> Value {
    blocking(tools::passwords_provider).await
}

#[tauri::command]
async fn use_safe_for_passwords() -> Value {
    blocking(tools::use_safe_for_passwords).await
}

#[tauri::command]
async fn cloud_status() -> Value {
    blocking(tools::cloud_status).await
}

#[tauri::command]
async fn window_classes() -> Value {
    blocking(tools::window_classes).await
}

#[tauri::command]
async fn open_url(url: String) -> Value {
    blocking(move || tools::open_url(&url)).await
}

#[tauri::command]
async fn open_ewe_sync() -> Value {
    blocking(tools::open_ewe_sync).await
}

/// A file picker (the desktop portal): a 1Password export, a CSV, a .kdbx.
/// `kind` picks the filter; the path, or null when cancelled.
#[tauri::command]
async fn pick_file(app: AppHandle, kind: String) -> Value {
    let (name, exts): (&str, &[&str]) = match kind.as_str() {
        "1pux" => ("1Password export", &["1pux"]),
        "csv" => ("CSV file", &["csv"]),
        "kdbx" => ("KeePass file", &["kdbx"]),
        // a private key has no extension (id_ed25519): no filter, from ~/.ssh
        "ssh-key" => ("", &[]),
        _ => return json!({"ok": false, "error": "bad-request", "message": "Unknown file kind."}),
    };
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut d = app.dialog().file();
        if exts.is_empty() {
            if let Some(home) = std::env::var_os("HOME") {
                d = d.set_directory(std::path::PathBuf::from(home).join(".ssh"));
            }
        } else {
            d = d.add_filter(name, exts);
        }
        d.blocking_pick_file()
    })
    .await
    .ok()
    .flatten()
    .and_then(|p| p.into_path().ok());
    match picked {
        Some(p) => json!({"ok": true, "path": p.to_string_lossy()}),
        None => json!({"ok": true, "path": null}),
    }
}

/// Print the page (the Emergency Kit); the page's print styles show only
/// the kit.
#[tauri::command]
fn print_page(window: tauri::WebviewWindow) -> Value {
    match window.print() {
        Ok(()) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "error": "failed", "message": e.to_string()}),
    }
}

/// The unlock-only window is done (the safe is open, or the user gave up).
#[tauri::command]
fn quit_app(app: AppHandle, code: i32) {
    app.exit(code);
}

async fn blocking<F: FnOnce() -> Value + Send + 'static>(f: F) -> Value {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .unwrap_or_else(
            |_| json!({"ok": false, "error": "internal", "message": "The call failed."}),
        )
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
    let launch = Launch::parse(std::env::args());
    // The Wayland app_id is GTK's program name, set before GTK starts:
    // `ewe-safe` (ewe-safe.desktop) for the window, `ewe-safe-unlock` for
    // the compact prompt (hyprland.lua floats that class at 560×200).
    gtk::glib::set_prgname(Some(if launch.compact() {
        "ewe-safe-unlock"
    } else {
        "ewe-safe"
    }));

    let mut builder = tauri::Builder::default();
    if !launch.compact() {
        // one window: a second launch (the launcher, the picker, the plugin)
        // brings it back and hands over what it was asked to show
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
            let _ = app.emit("safe-args", Launch::parse(args).json());
        }));
    }
    let unlock_only = launch.unlock;
    let approve = launch.approve.is_some();
    builder
        .plugin(tauri_plugin_dialog::init())
        .manage(Daemon::default())
        .manage(launch)
        .setup(move |app| {
            let w = if approve {
                WebviewWindowBuilder::new(app, "approve", WebviewUrl::App("index.html".into()))
                    .title("Allow the SSH key?")
                    .inner_size(560.0, 200.0)
                    .resizable(false)
                    .decorations(false)
                    .center()
            } else if unlock_only {
                WebviewWindowBuilder::new(app, "unlock", WebviewUrl::App("index.html".into()))
                    .title("Unlock Safe")
                    .inner_size(560.0, 200.0)
                    .resizable(false)
                    .decorations(false)
                    .center()
            } else {
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("Safe")
                    .inner_size(1040.0, 680.0)
                    .min_inner_size(760.0, 520.0)
                    .decorations(false)
                    .center()
            };
            w.build()?;
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("safe-events".into())
                .spawn(move || forward_events(handle))?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            import_items,
            launch_args,
            theme_tokens,
            theme_key,
            settings_get,
            settings_set,
            passwords_provider,
            use_safe_for_passwords,
            cloud_status,
            window_classes,
            open_url,
            open_ewe_sync,
            pick_file,
            print_page,
            quit_app,
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
            ssh::ssh_add,
            ssh::ssh_new,
            ssh::ssh_adopt,
            ssh::ssh_enable,
            ssh::ssh_disable,
            ssh::ssh_status,
            keyring::keyring_status,
            keyring::keyring_repair,
            keyring::keyring_list,
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
    fn launch_reads_the_window_arguments() {
        let p = |a: &[&str]| Launch::parse(a.iter().map(|s| s.to_string()));
        assert_eq!(p(&["ewe-safe-app"]), Launch::default());
        assert!(p(&["ewe-safe-app", "--unlock"]).unlock);
        assert_eq!(
            p(&["ewe-safe-app", "--show", "4f9c0d1e"]).show.as_deref(),
            Some("4f9c0d1e")
        );
        assert!(p(&["ewe-safe-app", "--new"]).new);
        assert!(p(&["ewe-safe-app", "--import"]).import);
        // an over-long id is not an id
        assert_eq!(p(&["ewe-safe-app", "--show", &"x".repeat(65)]).show, None);
        assert_eq!(p(&["ewe-safe-app", "--unlock"]).json()["mode"], "unlock");
        let a = p(&["ewe-safe-app", "--approve"]);
        assert!(a.compact() && !a.unlock);
        assert_eq!(a.json()["mode"], "approve");
    }

    #[test]
    fn every_secret_key_the_page_can_send_is_one_safe_client_scrubs() {
        for k in [
            "password",
            "new_password",
            "password_value",
            "notes",
            "passphrase",
            "private_key",
        ] {
            assert!(safe_client::SECRET_KEYS.contains(&k), "{k}");
        }
    }
}
