//! Safe and the keyring (docs/SYSTEM.md §3, docs/KEYRING.md): the daemon's
//! side of `safe-secrets`.
//!
//! In this release:
//!
//! - `keyring repair` fixes the prompt at every start in the keyring that
//!   runs (gnome-keyring): everything into `login`, `default` → `login`.
//! - `keyring status` and `keyring list` read the keyring that runs, with
//!   no secret and no prompt.
//! - Safe as the keyring itself (`adopt`) waits for Safe's login module
//!   (`pam_ewe_safe.so`): without it the keyring would ask for the login
//!   password at every start, so `adopt` refuses. The server below is built
//!   and tested, and starts only once a user adopted it.
//!
//! - W comes from `daemon.session` (the greeter's handoff, the unlock
//!   window, `keyring unlock`, `adopt`); a thread opens the keyring when it
//!   arrives.
//! - Adopted = `keyring.on` exists. Then the daemon asks for
//!   `org.freedesktop.secrets` at start, never queued: when another keyring
//!   holds it (the login screen's PAM file isn't updated yet), that is
//!   logged and shown in `status`, and Safe takes the name only once it is
//!   free.
//! - A locked keyring's prompt opens `ewe-safe-app --unlock --login`
//!   (`EWE_SAFE_KEYRING_ASK_CMD` replaces it, run with `sh -c`); without
//!   the window, a kitty running `ewe-safe keyring unlock`.
//! - The verbs `keyring-status|import|adopt|release|list|rm|unlock`.
//!
//! Nothing here logs a label, an attribute or a secret.

use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use safe_login::SessionKey;
use safe_secrets::{Asking, Files, Incoming, KeySource, Keyring, NAME, client, store};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::daemon::{Daemon, Fail, lk};
use crate::log;

type Args = Map<String, Value>;

const PAM_FILE: &str = "/etc/pam.d/greetd";
/// Safe's login module; `EWE_SAFE_PAM_MODULE` names another path (tests).
const PAM_MODULE: &str = "/usr/lib/security/pam_ewe_safe.so";
const NEEDS_MODULE: &str = "Safe can take over the keyring once its login module is installed. For now, use `ewe-safe keyring repair`.";
const PAM_HINT: &str = "Update ewe (sudo pacman -Syu), or copy ewe's login screen settings: sudo install -m644 /usr/share/ewe/system/pam.d/greetd /etc/pam.d/greetd";
/// gnome-keyring's own window may wait this long for the user, per
/// collection, during an import or a repair (`EWE_SAFE_PROMPT_SECONDS`
/// shortens it in tests).
fn import_prompt() -> Duration {
    std::env::var("EWE_SAFE_PROMPT_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(120))
}
/// The greeter's handoff may still be on its way this long after start.
const JUST_STARTED: Duration = Duration::from_secs(30);

static STARTED: OnceLock<Instant> = OnceLock::new();
static GLUE: OnceLock<Arc<Glue>> = OnceLock::new();

/// Who owns `org.freedesktop.secrets`, as status says it.
#[derive(Clone, Debug, Default)]
struct Owner {
    /// The session bus could be asked.
    known: bool,
    /// `ewe-safe` | `gnome-keyring` | `kwallet` | `other` | `none`.
    who: String,
    pid: Option<u32>,
}

struct Glue {
    kr: Keyring,
    bus: Mutex<Option<zbus::blocking::Connection>>,
    owner: Mutex<Owner>,
}

/// W from the daemon's session; the window when it isn't there.
struct Keys {
    d: Arc<Daemon>,
}

struct Window(Child);

impl Asking for Window {
    fn finished(&mut self) -> bool {
        !matches!(self.0.try_wait(), Ok(None))
    }

    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl KeySource for Keys {
    fn key(&self) -> Option<SessionKey> {
        self.d.session.key()
    }

    fn wait(&self, timeout: Duration) -> Option<SessionKey> {
        self.d.session.wait(timeout)
    }

    fn just_started(&self) -> bool {
        STARTED.get().is_some_and(|t| t.elapsed() < JUST_STARTED)
    }

    fn ask(&self) -> Option<Box<dyn Asking>> {
        let mut env = crate::agent::display_env(&self.d.paths);
        if let Ok(v) = std::env::var("EWE_SAFE_SOCKET") {
            env.push(("EWE_SAFE_SOCKET".into(), v));
        }
        let mut c = match std::env::var("EWE_SAFE_KEYRING_ASK_CMD") {
            Ok(cmd) => {
                let mut c = Command::new("sh");
                c.arg("-c")
                    .arg(cmd)
                    .envs(env.iter().map(|(k, v)| (k, v)))
                    .stdin(Stdio::null())
                    .stderr(Stdio::null());
                c
            }
            Err(_) => match crate::agent::on_path("ewe-safe-app") {
                Some(app) => crate::agent::prompt(app.as_os_str(), &["--unlock", "--login"], &env),
                None => {
                    let me = crate::agent::cli().to_string_lossy().into_owned();
                    crate::agent::prompt(
                        OsStr::new("kitty"),
                        &[
                            "--class",
                            "ewe-safe-unlock",
                            "--title",
                            "Unlock the keyring",
                            "-e",
                            &me,
                            "keyring",
                            "unlock",
                        ],
                        &env,
                    )
                }
            },
        };
        log("keyring: locked; asking for the login password");
        match c.stdout(Stdio::null()).spawn() {
            Ok(child) => Some(Box::new(Window(child))),
            Err(e) => {
                log(&format!("keyring: can't open the window ({e})"));
                None
            }
        }
    }

    fn ask_timeout(&self) -> Duration {
        std::env::var("EWE_SAFE_PROMPT_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(300))
    }

    fn log(&self, msg: &str) {
        log(msg);
    }
}

fn files(d: &Daemon) -> Files {
    Files {
        sealed: d.paths.keyring(),
        index: d.paths.state.join("keyring.index"),
    }
}

fn glue(d: &Arc<Daemon>) -> &'static Arc<Glue> {
    GLUE.get_or_init(|| {
        Arc::new(Glue {
            kr: Keyring::new(files(d), Arc::new(Keys { d: d.clone() })),
            bus: Mutex::new(None),
            owner: Mutex::new(Owner::default()),
        })
    })
}

fn adopted(d: &Daemon) -> bool {
    std::fs::symlink_metadata(d.paths.keyring_marker()).is_ok_and(|m| m.is_file())
}

/// Safe's login module is installed.
fn module_installed() -> bool {
    let path = std::env::var("EWE_SAFE_PAM_MODULE").unwrap_or_else(|_| PAM_MODULE.to_string());
    Path::new(&path).is_file()
}

/// Safe's login module is installed, and the login screen's PAM file uses
/// it to hand the password over and skip gnome-keyring for users who
/// adopted (docs/SYSTEM.md §2): `-session [success=1 default=ignore]
/// pam_ewe_safe.so`.
pub fn pam_ok() -> bool {
    module_installed() && greetd_ok()
}

fn greetd_ok() -> bool {
    let path = std::env::var("EWE_SAFE_GREETD_PAM").unwrap_or_else(|_| PAM_FILE.to_string());
    std::fs::read_to_string(path).is_ok_and(|text| {
        text.lines().any(|l| {
            let l = l.split('#').next().unwrap_or("").trim();
            (l.starts_with("session") || l.starts_with("-session"))
                && l.contains("success=1")
                && l.split_whitespace().any(|w| w.ends_with("pam_ewe_safe.so"))
        })
    })
}

/// The program's file name for a pid (`gnome-keyring-daemon`), even when
/// pacman replaced the file since it started.
fn exe_name(pid: u32) -> Option<String> {
    let p = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let n = p.file_name()?.to_string_lossy().into_owned();
    Some(n.trim_end_matches(" (deleted)").to_string())
}

fn owner_kind(exe: &str) -> &'static str {
    match exe {
        "gnome-keyring-daemon" => "gnome-keyring",
        "ksecretd" | "kwalletd" | "kwalletd5" | "kwalletd6" => "kwallet",
        "ewe-safed" => "ewe-safe",
        _ => "other",
    }
}

fn my_uid() -> u32 {
    // SAFETY: getuid has no failure mode
    unsafe { libc::getuid() }
}

impl Glue {
    fn connection(&self) -> Option<zbus::blocking::Connection> {
        let mut bus = lk(&self.bus);
        if bus.is_none() {
            // a keyring that hangs must not hold a verb forever (prompts
            // are waited for through signals, never a method call)
            *bus = zbus::blocking::connection::Builder::session()
                .map(|b| b.method_timeout(Duration::from_secs(25)))
                .and_then(|b| b.build())
                .ok();
        }
        bus.clone()
    }

    fn refresh_owner(&self, conn: &zbus::blocking::Connection) -> Owner {
        let o = match client::owner(conn) {
            None => Owner {
                known: true,
                who: "none".into(),
                pid: None,
            },
            Some((unique, pid)) => {
                let ours = conn.unique_name().is_some_and(|u| u.as_str() == unique);
                let who = if ours {
                    "ewe-safe"
                } else {
                    pid.and_then(exe_name)
                        .map(|e| owner_kind(&e))
                        .unwrap_or("other")
                };
                Owner {
                    known: true,
                    who: who.into(),
                    pid,
                }
            }
        };
        *lk(&self.owner) = o.clone();
        o
    }

    /// Ask for the name; another owner keeps it.
    fn take(&self, conn: &zbus::blocking::Connection) -> bool {
        let got = match self.kr.serve(conn) {
            Ok(got) => got,
            Err(e) => {
                log(&format!("keyring: can't serve on the session bus ({e})"));
                false
            }
        };
        let o = self.refresh_owner(conn);
        if !got {
            log(&format!(
                "keyring: {} holds org.freedesktop.secrets; Safe doesn't take it from it (it is Safe's at the next login once the login screen's PAM file is updated)",
                o.who
            ));
        }
        got
    }

    /// The bus: who owns the name now and later; adopted, take it when free.
    fn follow(&self, d: &Arc<Daemon>) {
        let Some(conn) = self.connection() else {
            if adopted(d) {
                log("keyring: no session bus: Safe can't serve the keyring here");
            }
            return;
        };
        self.refresh_owner(&conn);
        if adopted(d) {
            self.take(&conn);
        }
        let Ok(dbus) = zbus::blocking::fdo::DBusProxy::new(&conn) else {
            return;
        };
        let Ok(changes) = dbus.receive_name_owner_changed_with_args(&[(0, NAME)]) else {
            return;
        };
        for _ in changes {
            let o = self.refresh_owner(&conn);
            if o.who == "none" && adopted(d) && !self.kr.serving() {
                self.take(&conn);
            }
        }
    }
}

/// At start: the keyring (locked until W), the bus, and a thread that opens
/// the keyring when W arrives.
pub fn spawn(d: Arc<Daemon>) {
    STARTED.get_or_init(Instant::now);
    let g = glue(&d).clone();
    let (d2, g2) = (d.clone(), g.clone());
    let _ = std::thread::Builder::new()
        .name("keyring-key".into())
        .spawn(move || {
            loop {
                if d2.session.wait(Duration::from_secs(3600)).is_some() {
                    g2.kr.wake();
                    return;
                }
            }
        });
    let _ = std::thread::Builder::new()
        .name("keyring-bus".into())
        .spawn(move || g.follow(&d));
}

/// `status.keyring` (docs/PROTOCOL.md): from memory and two small files.
pub fn status_json(d: &Daemon) -> Value {
    let Some(g) = GLUE.get() else {
        return json!({"adopted": adopted(d), "serving": false, "open": false,
                      "items": 0, "owner": null, "pam": pam_ok()});
    };
    let o = lk(&g.owner).clone();
    let mut v = json!({
        "adopted": adopted(d),
        "serving": g.kr.serving(),
        "open": d.session.is_open(),
        "items": g.kr.count(),
        "owner": if o.known { json!(o.who) } else { Value::Null },
        "pam": pam_ok(),
    });
    if let Some(e) = g.kr.error() {
        v["error"] = json!(e);
    }
    v
}

fn secret(a: &mut Args, k: &str) -> Option<Zeroizing<String>> {
    match a.remove(k) {
        Some(Value::String(x)) => Some(Zeroizing::new(x)),
        _ => None,
    }
}

fn keyring_locked() -> Fail {
    Fail::new("keyring-locked", "Safe's keyring is locked.").hint("ewe-safe keyring unlock")
}

fn no_bus() -> Fail {
    Fail::new(
        "internal",
        "There is no session bus here, so Safe can't be the keyring.",
    )
}

/// `$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service`: user
/// service files win over /usr/share's (gnome-keyring's).
fn override_path() -> PathBuf {
    let data = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".local/share")
        });
    data.join("dbus-1/services/org.freedesktop.secrets.service")
}

fn write_override(path: &Path) -> std::io::Result<()> {
    let exe = std::env::current_exe()
        .ok()
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("/usr/bin/ewe-safed"));
    let body = format!(
        "# Safe is this user's keyring (ewe-safe keyring adopt). `ewe-safe keyring\n\
         # release` removes this file; gnome-keyring's file in /usr/share then\n\
         # applies again.\n\
         [D-BUS Service]\n\
         Name={NAME}\n\
         Exec={}\n\
         SystemdService=ewe-safe.service\n",
        exe.display()
    );
    safe_login::write_atomic(path, body.as_bytes())
}

/// dbus-broker doesn't watch its service folders: ask it (and dbus-daemon)
/// to read them again.
fn reload(conn: &zbus::blocking::Connection) {
    let r = conn.call_method(
        Some("org.freedesktop.DBus"),
        "/org/freedesktop/DBus",
        Some("org.freedesktop.DBus"),
        "ReloadConfig",
        &(),
    );
    if let Err(e) = r {
        log(&format!(
            "keyring: the bus didn't reload its service files ({e})"
        ));
    }
}

/// SIGTERM to the name's owner, only when it is this user's
/// gnome-keyring-daemon; then wait for the name to be free.
fn stop_gnome_keyring(conn: &zbus::blocking::Connection, pid: u32) -> bool {
    if exe_name(pid).as_deref() != Some("gnome-keyring-daemon") {
        return false;
    }
    if !std::fs::metadata(format!("/proc/{pid}")).is_ok_and(|m| m.uid() == my_uid()) {
        return false;
    }
    let Ok(p) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: a signal to one process of this user's, checked just above
    if unsafe { libc::kill(p, libc::SIGTERM) } != 0 {
        return false;
    }
    log(&format!("keyring: stopped gnome-keyring-daemon ({pid})"));
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if client::owner(conn).is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

/// Copy the current owner's items here (through its own API).
fn import_from(g: &Glue, conn: &zbus::blocking::Connection, dry_run: bool) -> Result<Value, Fail> {
    let read = client::read_all(conn, import_prompt()).map_err(|e| {
        Fail::new(
            "source-error",
            format!("The keyring that runs now can't be read: {e}"),
        )
    })?;
    let mut incoming = Vec::new();
    for c in &read.collections {
        // gnome-keyring's `login` and the one `default` names (on the
        // owner's machine, a second keyring) both become Safe's `login`
        let (name, label) = if c.default || c.name == "login" {
            (store::DEFAULT_COLLECTION.to_string(), "Login".to_string())
        } else {
            (store::path_name(&c.name), c.label.clone())
        };
        for i in &c.items {
            incoming.push(Incoming {
                collection: name.clone(),
                collection_label: label.clone(),
                label: i.label.clone(),
                attributes: i.attributes.clone(),
                secret: i.secret.clone(),
                content_type: i.content_type.clone(),
                created: i.created,
                modified: i.modified,
            });
        }
    }
    let items = incoming.len();
    let merged = if dry_run {
        g.kr.preview(incoming)
    } else {
        g.kr.merge(incoming).map_err(|e| {
            if e == "locked" {
                keyring_locked()
            } else {
                Fail::new("internal", e)
            }
        })?
    };
    log(&format!(
        "keyring: import{}: {items} items from {} collections ({} duplicates, {} skipped)",
        if dry_run { " (dry run)" } else { "" },
        read.collections.len(),
        merged.duplicates,
        read.skipped
    ));
    Ok(json!({
        "collections": read.collections.len(),
        "items": items,
        "added": merged.added,
        "updated": merged.updated,
        "duplicates": merged.duplicates,
        "skipped": read.skipped,
        "locked": read.locked,
    }))
}

/// The bus, and the owner unless it is Safe (or nobody, with our D-Bus
/// file in place: asking would only start Safe).
fn source(g: &Glue) -> Result<(zbus::blocking::Connection, Owner), Fail> {
    let conn = g.connection().ok_or_else(no_bus)?;
    let o = g.refresh_owner(&conn);
    Ok((conn, o))
}

fn import(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    let g = glue(d);
    let dry_run = a.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
    let (conn, o) = source(g)?;
    if o.who == "ewe-safe" {
        return Err(Fail::bad(
            "Safe already is the keyring: there is no other keyring to import from.",
        ));
    }
    if o.who == "none" && override_path().exists() {
        return Err(Fail::new("source-error", "No other keyring runs now."));
    }
    if !dry_run && !g.kr.wake() {
        return Err(keyring_locked());
    }
    let report = import_from(g, &conn, dry_run)?;
    let mut v = json!({"report": report});
    if dry_run {
        v["dry_run"] = json!(true);
    }
    Ok(v)
}

fn open_login_key(d: &Arc<Daemon>, pw: &Zeroizing<String>, create: bool) -> Result<(), Fail> {
    match crate::session::open_or_create(&d.paths.login_key(), pw.as_bytes(), create) {
        Ok(w) => {
            d.session.set(w);
            Ok(())
        }
        Err(safe_login::Error::WrongKey) => Err(Fail::new(
            "wrong-key",
            "That login password doesn't open this computer's key.",
        )),
        Err(safe_login::Error::Missing) => Err(Fail::new(
            "not-adopted",
            "Safe isn't this computer's keyring yet.",
        )
        .hint("ewe-safe keyring adopt")),
        Err(e) => Err(Fail::new("internal", e.to_string())),
    }
}

fn opened(g: &Glue) -> Result<(), Fail> {
    if g.kr.wake() {
        return Ok(());
    }
    Err(Fail::new(
        "internal",
        match g.kr.error().as_deref() {
            Some("wrong-key") => {
                "This computer's key doesn't open Safe's keyring file (it was made with another login key)."
            }
            _ => "Safe's keyring file can't be read.",
        },
    ))
}

fn adopt(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    let pw =
        secret(a, "login_password").ok_or_else(|| Fail::bad("The login password is missing."))?;
    if !module_installed() {
        return Err(Fail::new("needs-login-module", NEEDS_MODULE).hint("ewe-safe keyring repair"));
    }
    if !greetd_ok() {
        return Err(Fail::new(
            "pam-missing",
            "Your login screen doesn't give your password to Safe yet, so the keyring would ask for it after every start.",
        )
        .hint(PAM_HINT));
    }
    let g = glue(d);
    let (conn, before) = source(g)?;
    open_login_key(d, &pw, true)?;
    drop(pw);
    opened(g)?;
    let report = match before.who.as_str() {
        "ewe-safe" => None,
        "none" if override_path().exists() => None,
        _ => Some(import_from(g, &conn, false)?),
    };
    g.kr.save().map_err(|e| Fail::new("internal", e))?;
    let marker = json!({"v": 1, "adopted_at": safe_secrets::store::iso(store::now())});
    safe_login::write_atomic(&d.paths.keyring_marker(), format!("{marker}\n").as_bytes())?;
    let file = override_path();
    write_override(&file)?;
    reload(&conn);
    let stopped = match (before.who.as_str(), before.pid) {
        ("gnome-keyring", Some(pid)) => stop_gnome_keyring(&conn, pid),
        _ => false,
    };
    let serving = g.take(&conn);
    let now = lk(&g.owner).clone();
    log(&format!(
        "keyring: adopted ({})",
        if serving {
            "serving"
        } else {
            "not serving yet"
        }
    ));
    let mut v = json!({
        "adopted": true,
        "serving": serving,
        "owner": now.who,
        "import": report,
        "stopped": if stopped { json!("gnome-keyring") } else { Value::Null },
        "restart_apps": stopped,
        "service_file": file.display().to_string(),
    });
    if !serving {
        v["message"] = json!(format!(
            "Another keyring ({}) serves apps now. Safe takes over at the next login.",
            now.who
        ));
    }
    Ok(v)
}

fn release(d: &Arc<Daemon>) -> Result<Value, Fail> {
    let g = glue(d);
    let was_serving = g.kr.serving();
    let was_adopted = adopted(d);
    if let Err(e) = g.kr.release() {
        log(&format!("keyring: can't give the name back ({e})"));
    }
    safe_login::remove(&override_path())?;
    safe_login::remove(&d.paths.keyring_marker())?;
    if let Some(conn) = g.connection() {
        reload(&conn);
        g.refresh_owner(&conn);
    }
    log("keyring: released");
    Ok(json!({
        "released": was_adopted || was_serving,
        "serving": false,
        "restart_apps": was_serving,
        "kept": d.paths.keyring().display().to_string(),
        "hint": "gnome-keyring takes over again when an app asks for a secret, or at the next login.",
    }))
}

/// The app secrets: Safe's own while it is the keyring, otherwise the
/// running keyring's (names and dates only, no prompt).
fn list(d: &Arc<Daemon>) -> Result<Value, Fail> {
    let g = glue(d);
    if !g.kr.serving() {
        return list_running(g);
    }
    g.kr.wake();
    let items = g.kr.list().ok_or_else(keyring_locked)?;
    let items: Vec<Value> = items
        .iter()
        .map(|i| {
            json!({
                "id": i.id,
                "label": i.label,
                "collection": i.collection,
                "app": i.app,
                "created": store::iso(i.created),
                "modified": store::iso(i.modified),
            })
        })
        .collect();
    Ok(json!({"items": items, "locked": [], "source": "ewe-safe"}))
}

fn list_running(g: &Glue) -> Result<Value, Fail> {
    let conn = g.connection().ok_or_else(no_bus)?;
    let o = g.refresh_owner(&conn);
    if o.who == "none" {
        return Ok(json!({"items": [], "locked": [], "source": "none"}));
    }
    let (items, locked) = client::list(&conn).map_err(|e| {
        Fail::new(
            "source-error",
            format!("The keyring that runs now can't be read: {e}"),
        )
    })?;
    let mut items: Vec<Value> = items
        .iter()
        .map(|i| {
            json!({
                "id": i.path,
                "label": i.meta.label,
                "collection": i.collection,
                "app": store::app_of(&i.meta.attributes),
                "created": store::iso(i.meta.created),
                "modified": store::iso(i.meta.modified),
            })
        })
        .collect();
    items.sort_by_key(|v| v["label"].as_str().unwrap_or("").to_lowercase());
    let locked: Vec<Value> = locked
        .iter()
        .map(|c| json!({"collection": c.name, "label": c.label, "items": c.items}))
        .collect();
    Ok(json!({"items": items, "locked": locked, "source": o.who}))
}

/// `keyring status`: `status.keyring`, and what the keyring that runs says
/// about itself: which collection `default` names, and whether the
/// repair is needed (`default` isn't `login`). Never a prompt.
fn status_full(d: &Arc<Daemon>) -> Value {
    let g = glue(d);
    let mut v = status_json(d);
    let (mut default, mut collections, mut needs) = (Value::Null, Vec::new(), false);
    if let Some(conn) = g.connection() {
        let o = g.refresh_owner(&conn);
        v["owner"] = json!(o.who);
        if o.who != "none"
            && let Ok(r) = client::Remote::open(&conn, false)
        {
            let cols = r.collections().unwrap_or_default();
            let alias = r.alias("default").ok().flatten();
            let has_login = cols.iter().any(|c| c.as_str() == client::LOGIN_PATH);
            needs = has_login
                && alias
                    .as_ref()
                    .is_none_or(|a| a.as_str() != client::LOGIN_PATH);
            default = alias
                .map(|a| json!(client::name_of(a.as_str())))
                .unwrap_or(Value::Null);
            collections = cols.iter().map(|c| client::name_of(c.as_str())).collect();
        }
    }
    v["default"] = default;
    v["collections"] = json!(collections);
    v["needs_repair"] = json!(needs);
    v
}

/// `keyring repair` (safe_secrets::repair): in the keyring that runs.
fn repair(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    use safe_secrets::repair::Error;
    let dry_run = a.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
    let g = glue(d);
    let conn = g.connection().ok_or_else(no_bus)?;
    let o = g.refresh_owner(&conn);
    if o.who == "ewe-safe" {
        return Err(Fail::bad(
            "Safe is the keyring itself: there is nothing to repair.",
        ));
    }
    let r = safe_secrets::repair::repair(&conn, dry_run, import_prompt()).map_err(|e| match e {
        Error::NoKeyring => Fail::new("source-error", "No keyring runs now."),
        Error::NoLogin => Fail::new(
            "no-login-keyring",
            "Your keyring has no “login” part, so there is nowhere to move your passwords to.",
        )
        .hint("Log out and back in once: the login screen makes it with your login password. Then run ewe-safe keyring repair again. ewe's TROUBLESHOOTING, “Sign-in: no keyring prompt”, has more."),
        Error::LoginLocked => Fail::new("keyring-locked", "The login keyring stayed locked.")
            .hint("Run it again, and type your login password when the keyring asks."),
        Error::Bus(e) => Fail::new(
            "source-error",
            format!("The keyring didn't answer as expected: {e}"),
        ),
    })?;
    log(&format!(
        "keyring: repair{}: {} moved, {} duplicates, {} conflicts ({} replaced), {} skipped",
        if dry_run { " (dry run)" } else { "" },
        r.moved,
        r.duplicates,
        r.conflicts,
        r.replaced,
        r.skipped
    ));
    let mut v = json!({
        "default_was": r.default_was,
        "already": r.already,
        "moved": r.moved,
        "duplicates": r.duplicates,
        "conflicts": r.conflicts,
        "replaced": r.replaced,
        "skipped": r.skipped,
        "locked": r.locked,
        "sources": r.sources,
        "fixed": r.fixed,
    });
    if dry_run {
        v["dry_run"] = json!(true);
    }
    if r.already {
        v["message"] = json!("The keyring is fine: “default” already is your login keyring.");
    } else if r.fixed && !r.sources.is_empty() {
        let names = r.sources.join(", ");
        let files: Vec<String> = r
            .sources
            .iter()
            .map(|n| format!("~/.local/share/keyrings/{n}.keyring"))
            .collect();
        v["hint"] = json!(format!(
            "The old keyring ({names}) stays as a backup. To delete it later: Passwords and Keys (seahorse) → right-click it → Delete, or remove {} and log out and back in.",
            files.join(" and ")
        ));
    }
    if !r.locked.is_empty() {
        v["message"] = json!(format!(
            "{} stayed locked, so nothing was changed. Run the repair again and type that keyring's password when it asks.",
            r.locked.join(", ")
        ));
    }
    Ok(v)
}

pub fn dispatch(d: &Arc<Daemon>, verb: &str, a: &mut Args) -> Result<Value, Fail> {
    match verb {
        "keyring-status" => Ok(status_full(d)),
        "keyring-repair" => repair(d, a),
        "keyring-list" => list(d),
        "keyring-rm" => {
            let id = a
                .get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .ok_or_else(|| Fail::bad("Which app secret? Give its id."))?
                .to_string();
            let g = glue(d);
            if !g.kr.serving() {
                return Err(Fail::bad(
                    "Removing an app secret works here only while Safe is the keyring.",
                ));
            }
            match g.kr.remove(&id) {
                Ok(true) => Ok(json!({"removed": true})),
                Ok(false) => Err(Fail::new("not-found", format!("No app secret {id}."))),
                Err(e) if e == "locked" => Err(keyring_locked()),
                Err(e) => Err(Fail::new("internal", e)),
            }
        }
        "keyring-unlock" => {
            let pw = secret(a, "login_password")
                .ok_or_else(|| Fail::bad("The login password is missing."))?;
            open_login_key(d, &pw, false)?;
            drop(pw);
            let g = glue(d);
            opened(g)?;
            Ok(json!({"open": true, "items": g.kr.count()}))
        }
        "keyring-import" => import(d, a),
        "keyring-adopt" => adopt(d, a),
        "keyring-release" => release(d),
        other => Err(Fail::bad(format!("There is no verb {other:?}."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_are_named_by_their_program() {
        assert_eq!(owner_kind("gnome-keyring-daemon"), "gnome-keyring");
        assert_eq!(owner_kind("ksecretd"), "kwallet");
        assert_eq!(owner_kind("keepassxc"), "other");
        assert!(exe_name(std::process::id()).is_some());
    }

    #[test]
    fn the_pam_check_wants_the_skip_line() {
        let d = std::env::temp_dir().join(format!("ewe-safe-pam-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("greetd");
        let check = |text: &str| {
            std::fs::write(&f, text).unwrap();
            // SAFETY: the only test that reads this variable
            unsafe { std::env::set_var("EWE_SAFE_GREETD_PAM", &f) };
            let ok = greetd_ok();
            unsafe { std::env::remove_var("EWE_SAFE_GREETD_PAM") };
            ok
        };
        let old = "auth include system-login\n-session optional pam_gnome_keyring.so auto_start\n";
        assert!(!check(old));
        let new = "-auth optional pam_ewe_safe.so\n-session [success=1 default=ignore] pam_ewe_safe.so\n-session optional pam_gnome_keyring.so auto_start\n";
        assert!(check(new));
        assert!(!check(
            "# -session [success=1 default=ignore] pam_ewe_safe.so\n"
        ));
        assert!(!check("-auth optional pam_ewe_safe.so\n"));
        // `pam` also wants the module itself installed
        std::fs::write(&f, new).unwrap();
        let module = d.join("pam_ewe_safe.so");
        // SAFETY: the only test that reads these variables
        unsafe {
            std::env::set_var("EWE_SAFE_GREETD_PAM", &f);
            std::env::set_var("EWE_SAFE_PAM_MODULE", &module);
        }
        assert!(!pam_ok() && !module_installed());
        std::fs::write(&module, b"").unwrap();
        assert!(pam_ok());
        unsafe {
            std::env::remove_var("EWE_SAFE_GREETD_PAM");
            std::env::remove_var("EWE_SAFE_PAM_MODULE");
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
