//! The daemon's state: the place's sync engine, the unlocked safe, and the
//! snapshot the fast verbs answer from (docs/PROTOCOL.md, "Calls that must
//! stay fast").
//!
//! Three locks, always taken in this order:
//!
//! - `syncer` while talking to the place and for every save, so an edit
//!   queues behind an exchange that is under way;
//! - `held`, the unlocked safe. Readers (`show`, `reveal`, `copy`) never
//!   wait for the place: the worker exchanges a clone and swaps it back;
//! - `snap`, what `status`, `summary`, `list`, `search` and `match` read.
//!
//! `lock` takes only `held` and `snap`, so a place that hangs never delays
//! a lock.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use keepass::DatabaseKey;
use keepass::config::KdfConfig;
use safe_core::{Safe, Summary, kdf};
use safe_store::{Local, Place, PlaceInfo, Probe, SyncStatus, Syncer, WebDav};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::clip;
use crate::config::{self, Machine, Paths, Settings};
use crate::hygiene::Pinned;
use crate::log;

/// Every place `ewe.conf` may name (PLAN.md §6); this version opens two.
pub const KINDS: [&str; 7] = [
    "local",
    "nextcloud",
    "webdav",
    "folder",
    "sftp",
    "dropbox",
    "gdrive",
];
pub const NEXTCLOUD_DEFAULT: &str = "ewe/safe/passwords.kdbx";

pub fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn rd<T>(m: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|p| p.into_inner())
}

pub fn wr<T>(m: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|p| p.into_inner())
}

/// The safe while it is unlocked. Dropping it wipes the key (keepass-rs's
/// `DatabaseKey` zeroizes itself).
pub struct Held {
    pub safe: Safe,
    pub key: DatabaseKey,
}

pub struct Snapshot {
    pub set_up: bool,
    pub locked: bool,
    /// Some = read-only, and why.
    pub reasons: Option<Vec<String>>,
    pub upgrade_from: Option<String>,
    pub place: Option<PlaceInfo>,
    pub sync: Option<SyncStatus>,
    pub sync_message: Option<String>,
    pub probe: Option<Probe>,
    pub items: Vec<Summary>,
    pub deleted: Vec<Summary>,
}

pub enum Wake {
    /// An edit is in the cache: take it to the place.
    Push,
}

/// A PROTOCOL.md error reply.
#[derive(Debug)]
pub struct Fail {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub reasons: Option<Vec<String>>,
}

impl Fail {
    pub fn new(code: &'static str, message: impl Into<String>) -> Fail {
        Fail {
            code,
            message: sentence(message.into()),
            hint: None,
            reasons: None,
        }
    }

    pub fn hint(mut self, h: &str) -> Fail {
        self.hint = Some(h.to_string());
        self
    }

    pub fn bad(message: impl Into<String>) -> Fail {
        Fail::new("bad-request", message)
    }

    pub fn locked() -> Fail {
        Fail::new("locked", "Safe is locked.").hint("ewe-safe unlock")
    }

    pub fn not_set_up() -> Fail {
        Fail::new("not-set-up", "There is no safe on this computer yet.")
            .hint("ewe-safe init --place nextcloud, or ewe-safe open --place nextcloud")
    }

    pub fn to_json(&self) -> Value {
        let mut v = json!({"ok": false, "error": self.code, "message": self.message});
        if let Some(h) = &self.hint {
            v["hint"] = json!(h);
        }
        if let Some(r) = &self.reasons {
            v["reasons"] = json!(r);
        }
        v
    }
}

/// "the place can't be reached" → "The place can't be reached."
fn sentence(s: String) -> String {
    let mut c = s.chars();
    let mut out = match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => return s,
    };
    if !out.ends_with(['.', '!', '?', ':']) {
        out.push('.');
    }
    out
}

impl From<safe_core::Error> for Fail {
    fn from(e: safe_core::Error) -> Fail {
        match e {
            safe_core::Error::Open(_) => {
                Fail::new("wrong-key", "That password doesn't open the safe.")
            }
            safe_core::Error::ReadOnly(why) => {
                let mut f = Fail::new(
                    "read-only",
                    "Safe can't save this file without losing something another app put in it.",
                );
                f.reasons = Some(why);
                f
            }
            safe_core::Error::NotFound(id) => Fail::new("not-found", format!("No item {id}.")),
            other => Fail::new("internal", other.to_string()),
        }
    }
}

impl From<safe_store::Error> for Fail {
    fn from(e: safe_store::Error) -> Fail {
        match e {
            safe_store::Error::Safe(inner) => inner.into(),
            safe_store::Error::KeyChanged => {
                Fail::new("key-changed", e.to_string()).hint("ewe-safe unlock")
            }
            safe_store::Error::Missing => {
                Fail::new("not-set-up", "There is no safe there yet.").hint("ewe-safe init")
            }
            other => {
                let code = other.code();
                let msg = other.to_string();
                let f = Fail::new(code, msg.clone());
                if msg.contains("ewe-sync") {
                    f.hint("Sign in to your ewe account in ewe-sync")
                } else {
                    f
                }
            }
        }
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Fail {
        Fail::new("internal", e.to_string())
    }
}

pub struct Daemon {
    pub paths: Paths,
    settings: RwLock<Settings>,
    machine: Mutex<Option<Machine>>,
    pub syncer: Mutex<Option<Syncer>>,
    pub held: RwLock<Option<Held>>,
    pub snap: RwLock<Snapshot>,
    subscribers: Mutex<Vec<Sender<String>>>,
    last_use: Mutex<Instant>,
    wake: Mutex<Option<Sender<Wake>>>,
    pub clip: Mutex<Option<clip::Job>>,
}

impl Daemon {
    pub fn new(paths: Paths) -> Daemon {
        Daemon {
            paths,
            settings: RwLock::new(Settings::default()),
            machine: Mutex::new(None),
            syncer: Mutex::new(None),
            held: RwLock::new(None),
            snap: RwLock::new(Snapshot {
                set_up: false,
                locked: true,
                reasons: None,
                upgrade_from: None,
                place: None,
                sync: None,
                sync_message: None,
                probe: None,
                items: Vec::new(),
                deleted: Vec::new(),
            }),
            subscribers: Mutex::new(Vec::new()),
            last_use: Mutex::new(Instant::now()),
            wake: Mutex::new(None),
            clip: Mutex::new(None),
        }
    }

    /// Read the settings and this machine's record; a set-up machine gets
    /// its sync engine (still locked).
    pub fn start(&self) {
        self.reload_settings();
        let Some(m) = Machine::read(&self.paths.machine()) else {
            return;
        };
        match place_for(&m.kind, &m.location).and_then(|p| {
            Syncer::new(p, &self.paths.state, &safe_store::machine_name()).map_err(Fail::from)
        }) {
            Ok(s) => {
                *lk(&self.machine) = Some(m);
                let mut sy = lk(&self.syncer);
                *sy = Some(s);
                self.refresh_sync(sy.as_ref());
            }
            Err(f) => log(&format!(
                "this machine's safe can't be opened here: {}",
                f.message
            )),
        }
    }

    pub fn reload_settings(&self) {
        let s = Settings::read();
        *wr(&self.settings) = s;
    }

    pub fn settings(&self) -> Settings {
        rd(&self.settings).clone()
    }

    pub fn set_wake(&self, tx: Sender<Wake>) {
        *lk(&self.wake) = Some(tx);
    }

    fn wake(&self, w: Wake) {
        if let Some(tx) = lk(&self.wake).as_ref() {
            let _ = tx.send(w);
        }
    }

    pub fn mark_use(&self) {
        *lk(&self.last_use) = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        lk(&self.last_use).elapsed()
    }

    pub fn is_set_up(&self) -> bool {
        lk(&self.machine).is_some()
    }

    // ── events ──────────────────────────────────────────────────────────

    pub fn subscribe(&self) -> Receiver<String> {
        let (tx, rx) = mpsc::channel();
        lk(&self.subscribers).push(tx);
        rx
    }

    /// One event line to every subscriber. Events never carry a title, a
    /// username or a value.
    pub fn emit(&self, event: Value) {
        let mut line = event.to_string();
        line.push('\n');
        lk(&self.subscribers).retain(|tx| tx.send(line.clone()).is_ok());
    }

    fn emit_sync(&self) {
        let sync = sync_json(&rd(&self.snap));
        self.emit(json!({"v": 1, "event": "sync", "sync": sync}));
    }

    // ── the snapshot ────────────────────────────────────────────────────

    pub fn refresh_sync(&self, sy: Option<&Syncer>) {
        let set_up = self.is_set_up();
        let mut s = wr(&self.snap);
        s.set_up = set_up;
        s.place = sy.map(Syncer::place_info);
        s.sync = sy.map(Syncer::status);
        s.sync_message = sy.and_then(|x| x.last_error().map(str::to_string));
        s.probe = sy.and_then(|x| x.probe_result().cloned());
    }

    pub fn refresh_held(&self, h: Option<&Held>) {
        let mut s = wr(&self.snap);
        match h {
            Some(h) => {
                s.locked = false;
                s.items = h.safe.items();
                s.deleted = h.safe.deleted();
                s.reasons = match h.safe.writable() {
                    Err(safe_core::Error::ReadOnly(why)) => Some(why),
                    _ => None,
                };
                s.upgrade_from = h.safe.upgrade_from();
            }
            None => {
                s.locked = true;
                s.items = Vec::new();
                s.deleted = Vec::new();
                s.reasons = None;
                s.upgrade_from = None;
            }
        }
    }

    // ── lock and unlock ─────────────────────────────────────────────────

    /// Drop the key and the safe. Never waits for the place.
    pub fn lock(&self, reason: &str) -> bool {
        let was = wr(&self.held).take().is_some();
        if was {
            self.refresh_held(None);
            clip::clear_if_ours(self);
            log(&format!("locked ({reason})"));
            self.emit(json!({"v": 1, "event": "locked", "reason": reason}));
        }
        was
    }

    pub fn unlock(&self, password: &Zeroizing<String>) -> Result<usize, Fail> {
        if !self.is_set_up() {
            return Err(Fail::not_set_up());
        }
        if let Some(h) = rd(&self.held).as_ref() {
            return Ok(h.safe.items().len());
        }
        let key = make_key(password)?;
        let mut sy = lk(&self.syncer);
        let syncer = sy.as_mut().ok_or_else(Fail::not_set_up)?;
        let loaded = syncer.load(&key);
        self.refresh_sync(Some(syncer));
        let (safe, _) = loaded?;
        let n = safe.items().len();
        {
            let mut held = wr(&self.held);
            *held = Some(Held { safe, key });
            self.refresh_held(held.as_ref());
        }
        drop(sy);
        self.mark_use();
        log("unlocked");
        self.emit(json!({"v": 1, "event": "unlocked"}));
        self.emit_sync();
        Ok(n)
    }

    // ── setting a machine up ────────────────────────────────────────────

    /// A new safe in a place; this machine is set up with it, unlocked.
    pub fn init(
        &self,
        kind: &str,
        location: Option<&str>,
        password: &Zeroizing<String>,
    ) -> Result<Value, Fail> {
        if self.is_set_up() {
            return Err(Fail::new(
                "place-error",
                "This computer already has a safe.",
            ));
        }
        let location = self.normalize(kind, location)?;
        if kind == "local"
            && let Some(dir) = Path::new(&location).parent()
        {
            mkdir_private(dir)?;
        }
        let place = place_for(kind, &location)?;
        let mut sy = lk(&self.syncer);
        let mut syncer = Syncer::new(place, &self.paths.state, &safe_store::machine_name())?;
        if syncer.has_cache() {
            return Err(Fail::new(
                "place-error",
                format!(
                    "Safe's state folder already holds a safe: {}",
                    self.paths.state.display()
                ),
            ));
        }
        let key = make_key(password)?;
        let mut safe = Safe::create("Safe", new_kdf());
        syncer.create(&mut safe, &key)?;
        if kind != "local" {
            // a server that writes over a stale version is a single-writer place
            if let Err(e) = syncer.probe() {
                log(&format!("the guard probe didn't run: {}", e.code()));
            }
        }
        self.adopt(kind, &location)?;
        let place = syncer.place_info();
        self.refresh_sync(Some(&syncer));
        *sy = Some(syncer);
        {
            let mut held = wr(&self.held);
            *held = Some(Held { safe, key });
            self.refresh_held(held.as_ref());
        }
        drop(sy);
        self.mark_use();
        log(&format!("a new safe in {kind}"));
        self.emit(json!({"v": 1, "event": "unlocked"}));
        self.emit_sync();
        Ok(json!({"place": place_json(&place), "sync": sync_json(&rd(&self.snap))}))
    }

    /// A safe that already exists in a place (made on another machine, or
    /// a KeePass file); this machine is set up with it, unlocked.
    pub fn open(
        &self,
        kind: &str,
        location: Option<&str>,
        password: &Zeroizing<String>,
    ) -> Result<Value, Fail> {
        if self.is_set_up() {
            return Err(Fail::new(
                "place-error",
                "This computer already has a safe.",
            ));
        }
        let location = self.normalize(kind, location)?;
        let place = place_for(kind, &location)?;
        let mut sy = lk(&self.syncer);
        let fresh = !self.paths.state.join("sync.json").exists();
        let mut syncer = Syncer::new(place, &self.paths.state, &safe_store::machine_name())?;
        let key = make_key(password)?;
        let (safe, _) = match syncer.load(&key) {
            Ok(x) => x,
            Err(e) => {
                drop(syncer);
                if fresh {
                    forget_state(&self.paths.state);
                }
                return Err(e.into());
            }
        };
        if kind != "local"
            && let Err(e) = syncer.probe()
        {
            log(&format!("the guard probe didn't run: {}", e.code()));
        }
        self.adopt(kind, &location)?;
        let place = syncer.place_info();
        let n = safe.items().len();
        self.refresh_sync(Some(&syncer));
        *sy = Some(syncer);
        {
            let mut held = wr(&self.held);
            *held = Some(Held { safe, key });
            self.refresh_held(held.as_ref());
        }
        drop(sy);
        self.mark_use();
        log(&format!("opened a safe in {kind}"));
        self.emit(json!({"v": 1, "event": "unlocked"}));
        self.emit_sync();
        Ok(json!({"place": place_json(&place), "items": n}))
    }

    /// Record the place: `machine.json` for this machine, ewe.conf for the
    /// others (through ewe-conf, house rule 1).
    fn adopt(&self, kind: &str, location: &str) -> Result<(), Fail> {
        let m = Machine {
            kind: kind.to_string(),
            location: location.to_string(),
            set_up_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        };
        m.write(&self.paths.machine())?;
        *lk(&self.machine) = Some(m);
        config::conf_set("place", kind);
        config::conf_set("location", location);
        Ok(())
    }

    fn normalize(&self, kind: &str, location: Option<&str>) -> Result<String, Fail> {
        let loc = location.map(str::trim).filter(|l| !l.is_empty());
        match kind {
            "local" => {
                let p = loc
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.paths.default_local());
                if !p.is_absolute() {
                    return Err(Fail::bad("A This-computer location must be a full path."));
                }
                Ok(p.to_string_lossy().into_owned())
            }
            "nextcloud" => Ok(loc
                .unwrap_or(NEXTCLOUD_DEFAULT)
                .trim_start_matches('/')
                .to_string()),
            _ => place_for(kind, "").map(|_| String::new()),
        }
    }

    // ── reading and editing ─────────────────────────────────────────────

    /// Read the unlocked safe; never waits for the place.
    pub fn with_held<T>(&self, f: impl FnOnce(&Held) -> Result<T, Fail>) -> Result<T, Fail> {
        if !self.is_set_up() {
            return Err(Fail::not_set_up());
        }
        let held = rd(&self.held);
        let h = held.as_ref().ok_or_else(Fail::locked)?;
        let out = f(h);
        drop(held);
        self.mark_use();
        out
    }

    /// Edit the safe: the change and the cache now (verified), the place
    /// shortly after (the worker). `f` says whether anything changed; an
    /// edit that changes nothing saves nothing. Answers with the sync object.
    pub fn mutate<T>(
        &self,
        f: impl FnOnce(&mut Safe) -> Result<(T, bool), Fail>,
    ) -> Result<(T, Value), Fail> {
        let mut sy = lk(&self.syncer);
        let syncer = sy.as_mut().ok_or_else(Fail::not_set_up)?;
        let mut held = wr(&self.held);
        let h = held.as_mut().ok_or_else(Fail::locked)?;
        h.safe.writable().map_err(Fail::from)?;
        let (out, changed) = f(&mut h.safe)?;
        if !changed {
            drop(held);
            drop(sy);
            self.mark_use();
            return Ok((out, sync_json(&rd(&self.snap))));
        }
        let saved = syncer.save_local(&mut h.safe, &h.key);
        self.refresh_held(Some(h));
        drop(held);
        self.refresh_sync(Some(syncer));
        drop(sy);
        saved?;
        self.mark_use();
        self.emit(json!({"v": 1, "event": "changed"}));
        self.wake(Wake::Push);
        Ok((out, sync_json(&rd(&self.snap))))
    }

    /// One exchange with the place (the worker, `sync`). Unlocked, a clone
    /// travels and comes back, so readers don't wait.
    pub fn sync_once(&self) {
        let mut sy = lk(&self.syncer);
        let Some(syncer) = sy.as_mut() else {
            return;
        };
        let copy = rd(&self.held)
            .as_ref()
            .map(|h| (h.safe.clone(), h.key.clone()));
        let changed = match copy {
            Some((mut safe, key)) => match syncer.poll(Some((&mut safe, &key))) {
                Ok(p) => {
                    if p.changed {
                        // edits queue on `syncer`, so nothing changed meanwhile;
                        // a lock meanwhile just drops the copy
                        let mut held = wr(&self.held);
                        if let Some(h) = held.as_mut() {
                            h.safe = safe;
                            self.refresh_held(Some(h));
                        }
                    }
                    p.changed
                }
                Err(e) => {
                    log(&format!("sync: {}", e.code()));
                    false
                }
            },
            None => match syncer.poll(None) {
                Ok(_) => false,
                Err(e) => {
                    log(&format!("sync (locked): {}", e.code()));
                    false
                }
            },
        };
        self.refresh_sync(Some(syncer));
        drop(sy);
        if changed {
            self.emit(json!({"v": 1, "event": "changed"}));
        }
        self.emit_sync();
    }

    /// A new master password: the place's changes come in under the old
    /// one, then the safe is saved under the new one. Needs the place (a
    /// change made offline would leave the other machines' copy under the
    /// old password with this machine's under the new).
    pub fn passwd(&self, new: &Zeroizing<String>) -> Result<Value, Fail> {
        let mut sy = lk(&self.syncer);
        let syncer = sy.as_mut().ok_or_else(Fail::not_set_up)?;
        let mut held = wr(&self.held);
        let h = held.as_mut().ok_or_else(Fail::locked)?;
        h.safe.writable().map_err(Fail::from)?;
        let polled = syncer.poll(Some((&mut h.safe, &h.key)));
        self.refresh_sync(Some(syncer));
        polled?;
        let st = syncer.status();
        if st.pending || !(st.state == "in-sync" || st.state == "local") {
            return Err(Fail::new(
                "place-error",
                "Change the password while Safe can reach its place.",
            ));
        }
        let key = make_key(new)?;
        let saved = syncer.save(&mut h.safe, &key);
        h.key = key;
        self.refresh_held(Some(h));
        drop(held);
        self.refresh_sync(Some(syncer));
        drop(sy);
        saved?;
        self.mark_use();
        log("the master password changed");
        self.emit_sync();
        Ok(json!({"sync": sync_json(&rd(&self.snap))}))
    }
}

/// The place a kind and location name; this version opens two kinds.
pub fn place_for(kind: &str, location: &str) -> Result<Box<dyn Place>, Fail> {
    match kind {
        "local" => Ok(Box::new(Local::new(PathBuf::from(location)))),
        "nextcloud" => Ok(Box::new(WebDav::nextcloud(location))),
        k if KINDS.contains(&k) => Err(Fail::bad(
            "Safe can't use that place yet: this version has This computer (local) and your ewe account (nextcloud).",
        )),
        _ => Err(Fail::bad(format!("place = {}", KINDS.join(" | ")))),
    }
}

fn make_key(password: &Zeroizing<String>) -> Result<DatabaseKey, Fail> {
    if password.is_empty() {
        return Err(Fail::bad("The master password is empty."));
    }
    let _pin = Pinned::new(password.as_bytes());
    safe_core::safe::key(password, None).map_err(Fail::from)
}

/// The key derivation a new safe gets: calibrated to about a second here
/// (PLAN.md §5). `EWE_SAFE_KDF_ITERATIONS` is a test switch.
fn new_kdf() -> KdfConfig {
    match std::env::var("EWE_SAFE_KDF_ITERATIONS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(n) => kdf::argon2id(n.max(1)),
        None => kdf::argon2id(kdf::calibrate(kdf::TARGET)),
    }
}

fn mkdir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// A failed `open` leaves nothing behind for the next attempt to trip on.
fn forget_state(dir: &Path) {
    let _ = std::fs::remove_file(dir.join("sync.json"));
    let _ = std::fs::remove_file(dir.join("sync.json.broken"));
    if let Ok(entries) = std::fs::read_dir(dir.join("cache")) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

pub fn place_json(p: &PlaceInfo) -> Value {
    json!({"kind": p.kind, "location": p.location, "guarded": p.guarded})
}

/// PROTOCOL.md's sync object, plus `message` when the last exchange failed.
pub fn sync_json(s: &Snapshot) -> Value {
    match &s.sync {
        Some(st) => {
            let mut v = json!({
                "state": st.state,
                "last": st.last,
                "by_machine": st.by_machine,
                "pending": st.pending,
                "warning": st.warning,
            });
            if let Some(m) = &s.sync_message
                && (st.state == "error" || st.state == "offline")
            {
                v["message"] = json!(m);
            }
            v
        }
        None => Value::Null,
    }
}

/// PROTOCOL.md's item summary.
pub fn item_json(s: &Summary) -> Value {
    json!({
        "id": s.id,
        "kind": s.kind.as_str(),
        "title": s.title,
        "username": s.username,
        "urls": s.websites,
        "apps": s.apps,
        "tags": s.tags,
        "folder": s.folder,
        "has_password": s.has_password,
        "has_otp": s.has_otp,
        "modified": s.modified.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        "passkey": s.passkey.as_ref().map(|p| json!({"rp_id": p.rp_id, "username": p.username})),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_read_as_sentences() {
        let f: Fail = safe_store::Error::Offline("no route".into()).into();
        assert_eq!(f.code, "offline");
        assert_eq!(f.message, "The place can't be reached: no route.");
        let f: Fail = safe_core::Error::Open("x".into()).into();
        assert_eq!(f.code, "wrong-key");
        let f: Fail = safe_core::Error::ReadOnly(vec!["an element".into()]).into();
        assert_eq!(f.to_json()["reasons"][0], "an element");
        let f: Fail =
            safe_store::Error::Place("not signed in: sign in with ewe-sync".into()).into();
        assert!(f.hint.is_some());
    }

    #[test]
    fn only_two_places_open_in_this_version() {
        assert!(place_for("local", "/tmp/x.kdbx").is_ok());
        assert!(place_for("nextcloud", NEXTCLOUD_DEFAULT).is_ok());
        assert_eq!(
            place_for("webdav", "").err().map(|f| f.code),
            Some("bad-request")
        );
        assert_eq!(
            place_for("ftp", "").err().map(|f| f.code),
            Some("bad-request")
        );
    }
}
