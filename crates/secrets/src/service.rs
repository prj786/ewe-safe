//! The Secret Service objects (freedesktop Secret Service API 0.2) on the
//! session bus:
//!
//! | path | interface |
//! |---|---|
//! | `/org/freedesktop/secrets` | `org.freedesktop.Secret.Service` |
//! | `/org/freedesktop/secrets/collection/<name>` | `…Secret.Collection` |
//! | `/org/freedesktop/secrets/aliases/<alias>` | the same collection, by alias (libsecret writes to `aliases/default`) |
//! | `/org/freedesktop/secrets/collection/<name>/<n>` | `…Secret.Item` |
//! | `/org/freedesktop/secrets/session/s<n>` | `…Secret.Session` |
//! | `/org/freedesktop/secrets/prompt/p<n>` | `…Secret.Prompt` |
//!
//! The keyring is open while W is known (docs/SYSTEM.md §3: the whole
//! login session). Without W it is locked: searches answer from the index
//! (the same item paths, as locked), and `Unlock` returns a prompt whose
//! `Prompt` waits for W — a few seconds first when the daemon has only just
//! started (the greeter's handoff may be on its way), then the
//! [`KeySource`]'s window. One window at a time: two apps asking at once
//! (what crashed gnome-keyring on the owner's machine) share it.
//!
//! `Lock` only marks collections locked; while W is known, `Unlock` opens
//! them again without a question (the login session already proved who is
//! there). Sessions belong to the connection that opened them and close
//! when it goes. Nothing here logs a label, an attribute or a secret.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use safe_login::SessionKey;
use serde::{Deserialize, Serialize};
use zbus::fdo::{RequestNameFlags, RequestNameReply};
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Type, Value};
use zbus::{ObjectServer, fdo, interface};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::store::{self, Files, Incoming, Index, Merged, Store};

pub const NAME: &str = "org.freedesktop.secrets";
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection/";
pub const ALIAS_PREFIX: &str = "/org/freedesktop/secrets/aliases/";
const SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/";
const PROMPT_PREFIX: &str = "/org/freedesktop/secrets/prompt/";
pub const NO_PROMPT: &str = "/";

pub const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
pub const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
pub const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
pub const PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";
const PROPS_IFACE: &str = "org.freedesktop.DBus.Properties";

pub const LABEL_PROP: &str = "org.freedesktop.Secret.Item.Label";
pub const ATTRIBUTES_PROP: &str = "org.freedesktop.Secret.Item.Attributes";
pub const COLLECTION_LABEL_PROP: &str = "org.freedesktop.Secret.Collection.Label";

/// The greeter's handoff may still be on its way this long.
const GRACE: Duration = Duration::from_secs(5);
/// A window closed without W: the next prompt within this is dismissed
/// at once instead of opening a new window (a loop of requests).
const QUIET_AFTER_NO: Duration = Duration::from_secs(3);

/// Where W comes from: the daemon's session (docs/SYSTEM.md §2). Tests
/// give a stand-in.
pub trait KeySource: Send + Sync + 'static {
    /// W, if it is in memory now.
    fn key(&self) -> Option<SessionKey>;
    /// W, waiting up to `timeout` for it.
    fn wait(&self, timeout: Duration) -> Option<SessionKey>;
    /// The daemon started moments ago (the greeter's handoff may come).
    fn just_started(&self) -> bool {
        false
    }
    /// Open the window that asks for the login password; `None` when there
    /// is no way to ask.
    fn ask(&self) -> Option<Box<dyn Asking>>;
    /// How long a window may stay open.
    fn ask_timeout(&self) -> Duration {
        Duration::from_secs(300)
    }
    fn log(&self, msg: &str) {
        eprintln!("ewe-safed: {msg}");
    }
}

/// A window asking for the login password.
pub trait Asking: Send {
    /// It is gone (answered or closed).
    fn finished(&mut self) -> bool;
    /// Close it: time is up.
    fn stop(&mut self);
}

/// `(oayays)`: a secret on the wire, as plain bytes or AES-encrypted for
/// the session. Wiped when dropped.
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct Secret {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretError {
    #[zbus(error)]
    ZBus(zbus::Error),
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
}

fn locked_err() -> SecretError {
    SecretError::IsLocked("The keyring is locked.".into())
}

fn failed(why: &str) -> SecretError {
    SecretError::ZBus(zbus::Error::Failure(why.to_string()))
}

fn op(s: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(s.to_string())
        .unwrap_or_else(|_| OwnedObjectPath::try_from("/").expect("/ is a path"))
}

fn root() -> OwnedObjectPath {
    op(NO_PROMPT)
}

fn owned(v: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(v).expect("a value without file descriptors")
}

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// One of the keyring's objects, by what its path names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Obj {
    Collection(String),
    Alias(String),
    Item(String, u64),
}

fn collection_path(name: &str) -> String {
    format!("{COLLECTION_PREFIX}{name}")
}

fn item_path(collection: &str, n: u64) -> String {
    format!("{COLLECTION_PREFIX}{collection}/{n}")
}

fn obj_path(o: &Obj) -> String {
    match o {
        Obj::Collection(c) => collection_path(c),
        Obj::Alias(a) => format!("{ALIAS_PREFIX}{a}"),
        Obj::Item(c, n) => item_path(c, *n),
    }
}

fn parse_path(p: &str) -> Option<Obj> {
    if let Some(rest) = p.strip_prefix(COLLECTION_PREFIX) {
        return match rest.split_once('/') {
            None => store::valid_name(rest).then(|| Obj::Collection(rest.to_string())),
            Some((c, n)) => {
                let n: u64 = n.parse().ok()?;
                store::valid_name(c).then(|| Obj::Item(c.to_string(), n))
            }
        };
    }
    p.strip_prefix(ALIAS_PREFIX)
        .filter(|a| store::valid_name(a))
        .map(|a| Obj::Alias(a.to_string()))
}

struct Session {
    owner: String,
    aes: Option<Zeroizing<[u8; 16]>>,
}

enum Pending {
    Unlock(Vec<OwnedObjectPath>),
    CreateItem {
        collection: String,
        label: String,
        attributes: BTreeMap<String, String>,
        secret: Zeroizing<Vec<u8>>,
        content_type: String,
        replace: bool,
    },
    CreateCollection {
        label: String,
        alias: String,
    },
}

impl Pending {
    /// What `Completed` carries when nothing was done.
    fn nothing(&self) -> OwnedValue {
        match self {
            Pending::Unlock(_) => owned(Value::from(Vec::<OwnedObjectPath>::new())),
            _ => owned(Value::from(root())),
        }
    }
}

struct PromptState {
    owner: String,
    pending: Option<Pending>,
    started: bool,
    dismissed: Arc<AtomicBool>,
}

struct State {
    /// Some = `keyring.safe` is open.
    w: Option<SessionKey>,
    /// Open: everything. Locked: the collections and aliases from the index.
    store: Store,
    index: Index,
    /// Collections `Lock` marked.
    soft: HashSet<String>,
    error: Option<String>,
    sessions: HashMap<String, Session>,
    prompts: HashMap<String, PromptState>,
    next: u64,
    /// Collection, alias and item objects registered now.
    objects: BTreeSet<Obj>,
}

impl State {
    fn is_locked(&self, collection: &str) -> bool {
        self.w.is_none() || self.soft.contains(collection)
    }

    /// The collection a path names (an alias followed), if it exists.
    fn collection_of(&self, p: &str) -> Option<String> {
        match parse_path(p)? {
            Obj::Collection(c) => self.store.collection(&c).map(|_| c),
            Obj::Alias(a) => self
                .store
                .aliases
                .get(&a)
                .filter(|c| self.store.collection(c).is_some())
                .cloned(),
            Obj::Item(c, n) => self.item_exists(&c, n).then_some(c),
        }
    }

    fn item_exists(&self, c: &str, n: u64) -> bool {
        if self.w.is_some() {
            self.store.item(c, n).is_some()
        } else {
            self.index
                .items
                .iter()
                .any(|s| s.collection == c && s.n == n)
        }
    }

    fn item_paths(&self, collection: &str) -> Vec<OwnedObjectPath> {
        if self.w.is_some() {
            self.store
                .items
                .iter()
                .filter(|i| i.collection == collection)
                .map(|i| op(&item_path(&i.collection, i.n)))
                .collect()
        } else {
            self.index
                .items
                .iter()
                .filter(|s| s.collection == collection)
                .map(|s| op(&item_path(&s.collection, s.n)))
                .collect()
        }
    }

    fn wanted(&self) -> BTreeSet<Obj> {
        let mut out = BTreeSet::new();
        for c in &self.store.collections {
            out.insert(Obj::Collection(c.name.clone()));
        }
        for (a, c) in &self.store.aliases {
            if self.store.collection(c).is_some() {
                out.insert(Obj::Alias(a.clone()));
            }
        }
        if self.w.is_some() {
            for i in &self.store.items {
                out.insert(Obj::Item(i.collection.clone(), i.n));
            }
        } else {
            for s in &self.index.items {
                out.insert(Obj::Item(s.collection.clone(), s.n));
            }
        }
        out
    }

    fn new_path(&mut self, prefix: &str, letter: char) -> String {
        self.next += 1;
        format!("{prefix}{letter}{}", self.next)
    }
}

/// What changes on the bus after a change in the state: objects to add and
/// to remove.
#[derive(Default)]
struct Plan {
    add: Vec<Obj>,
    remove: Vec<Obj>,
}

enum Sig {
    /// A signal whose one argument is an object path.
    Path {
        path: String,
        iface: &'static str,
        member: &'static str,
        arg: String,
    },
    Props {
        path: String,
        iface: &'static str,
        changed: Vec<(&'static str, OwnedValue)>,
    },
    Completed {
        path: String,
        dismissed: bool,
        result: OwnedValue,
    },
}

pub(crate) struct Core {
    files: Files,
    source: Arc<dyn KeySource>,
    st: Mutex<State>,
    conn: OnceLock<zbus::blocking::Connection>,
    signals: OnceLock<Mutex<Sender<Sig>>>,
    serving: AtomicBool,
    /// One window at a time; when the last one ended without W.
    asking: Mutex<Option<Instant>>,
    /// Refuse the dh session (tests: libsecret's fallback to plain).
    no_dh: bool,
}

impl Core {
    fn st(&self) -> MutexGuard<'_, State> {
        lk(&self.st)
    }

    fn log(&self, msg: &str) {
        self.source.log(msg);
    }

    fn emit(&self, s: Sig) {
        if let Some(tx) = self.signals.get() {
            let _ = lk(tx).send(s);
        }
    }

    fn emit_path(&self, path: String, iface: &'static str, member: &'static str, arg: String) {
        self.emit(Sig::Path {
            path,
            iface,
            member,
            arg,
        });
    }

    fn collections_changed(&self, st: &State) {
        let paths: Vec<OwnedObjectPath> = st
            .store
            .collections
            .iter()
            .map(|c| op(&collection_path(&c.name)))
            .collect();
        self.emit(Sig::Props {
            path: SERVICE_PATH.into(),
            iface: SERVICE_IFACE,
            changed: vec![("Collections", owned(Value::from(paths)))],
        });
    }

    fn items_changed(&self, st: &State, collection: &str) {
        self.emit(Sig::Props {
            path: collection_path(collection),
            iface: COLLECTION_IFACE,
            changed: vec![("Items", owned(Value::from(st.item_paths(collection))))],
        });
    }

    fn locked_changed(&self, st: &State, collection: &str) {
        let locked = st.is_locked(collection);
        self.emit(Sig::Props {
            path: collection_path(collection),
            iface: COLLECTION_IFACE,
            changed: vec![("Locked", owned(Value::from(locked)))],
        });
        self.emit_path(
            SERVICE_PATH.into(),
            SERVICE_IFACE,
            "CollectionChanged",
            collection_path(collection),
        );
    }

    /// The objects to (un)register so the bus shows the state.
    fn plan(&self, st: &mut State) -> Plan {
        if self.conn.get().is_none() {
            return Plan::default();
        }
        let wanted = st.wanted();
        let plan = Plan {
            add: wanted.difference(&st.objects).cloned().collect(),
            remove: st.objects.difference(&wanted).cloned().collect(),
        };
        st.objects = wanted;
        plan
    }

    /// Open `keyring.safe` with W. A file W doesn't open stays locked (and
    /// untouched); status says why.
    fn open_with(self: &Arc<Self>, st: &mut State, w: SessionKey) -> bool {
        if st.w.as_ref().is_some_and(|k| *k == w) {
            return true;
        }
        match Store::load(&self.files, &w) {
            Ok(store) => {
                let fresh = !self.files.sealed.exists();
                st.store = store;
                st.w = Some(w.clone());
                st.error = None;
                if !fresh && Index::read(&self.files.index).is_none() {
                    // the index went missing: write it again
                    if let Err(e) = st.store.save(&self.files, &w) {
                        self.log(&format!("keyring: can't write its index ({e})"));
                    }
                }
                st.index = Index::read(&self.files.index).unwrap_or_default();
                self.log("keyring: open");
                let names: Vec<String> = st
                    .store
                    .collections
                    .iter()
                    .map(|c| c.name.clone())
                    .collect();
                for c in names {
                    self.locked_changed(st, &c);
                }
                true
            }
            Err(e) => {
                let code = match e {
                    store::LoadError::WrongKey => "wrong-key",
                    _ => "unreadable",
                };
                if st.error.as_deref() != Some(code) {
                    self.log(&format!("keyring: stays locked: {e}"));
                }
                st.error = Some(code.into());
                false
            }
        }
    }

    /// Open, if W is known now.
    fn ensure_open(self: &Arc<Self>, st: &mut State) -> bool {
        if st.w.is_some() {
            return true;
        }
        match self.source.key() {
            Some(w) => self.open_with(st, w),
            None => false,
        }
    }

    /// Change the store and save it; nothing changes when the save fails.
    fn mutate<T>(
        &self,
        st: &mut State,
        f: impl FnOnce(&mut Store) -> Result<T, SecretError>,
    ) -> Result<T, SecretError> {
        let w = st.w.clone().ok_or_else(locked_err)?;
        let before = st.store.clone();
        let out = match f(&mut st.store) {
            Ok(x) => x,
            Err(e) => {
                st.store = before;
                return Err(e);
            }
        };
        if let Err(e) = st.store.save(&self.files, &w) {
            st.store = before;
            self.log(&format!("keyring: can't save ({e})"));
            return Err(failed("The keyring can't be saved."));
        }
        if let Some(i) = Index::read(&self.files.index) {
            st.index = i;
        }
        Ok(out)
    }

    // ── secrets on the wire ─────────────────────────────────────────────

    fn encode(
        &self,
        st: &State,
        session: &str,
        owner: &str,
        plain: &[u8],
        content_type: &str,
    ) -> Result<Secret, SecretError> {
        let s = st
            .sessions
            .get(session)
            .filter(|s| s.owner == owner)
            .ok_or_else(|| SecretError::NoSession("No such session.".into()))?;
        let (parameters, value) = match &s.aes {
            Some(k) => crypto::encrypt(k, plain),
            None => (Vec::new(), plain.to_vec()),
        };
        Ok(Secret {
            session: op(session),
            parameters,
            value,
            content_type: content_type.to_string(),
        })
    }

    fn decode(
        &self,
        st: &State,
        s: &Secret,
        owner: &str,
    ) -> Result<(Zeroizing<Vec<u8>>, String), SecretError> {
        let sess = st
            .sessions
            .get(s.session.as_str())
            .filter(|x| x.owner == owner)
            .ok_or_else(|| SecretError::NoSession("No such session.".into()))?;
        let plain = match &sess.aes {
            Some(k) => crypto::decrypt(k, &s.parameters, &s.value)
                .ok_or_else(|| failed("The secret can't be decrypted."))?,
            None => Zeroizing::new(s.value.clone()),
        };
        Ok((plain, s.content_type.clone()))
    }

    // ── changes shared by the bus and the daemon ────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn create_item(
        &self,
        st: &mut State,
        collection: &str,
        label: &str,
        attributes: BTreeMap<String, String>,
        secret: Zeroizing<Vec<u8>>,
        content_type: &str,
        replace: bool,
    ) -> Result<String, SecretError> {
        st.soft.remove(collection);
        let (n, new) = self.mutate(st, |s| {
            s.put(
                collection,
                label,
                attributes,
                secret,
                content_type,
                replace,
                None,
            )
            .ok_or_else(|| SecretError::NoSuchObject("No such collection.".into()))
        })?;
        let path = item_path(collection, n);
        let member = if new { "ItemCreated" } else { "ItemChanged" };
        self.emit_path(
            collection_path(collection),
            COLLECTION_IFACE,
            member,
            path.clone(),
        );
        if new {
            self.items_changed(st, collection);
        }
        Ok(path)
    }

    fn create_collection(
        &self,
        st: &mut State,
        label: &str,
        alias: &str,
    ) -> Result<String, SecretError> {
        let alias = alias.to_string();
        let name = self.mutate(st, |s| {
            let name = s.add_collection(label);
            if store::valid_name(&alias) {
                s.aliases.insert(alias.clone(), name.clone());
            }
            Ok(name)
        })?;
        let path = collection_path(&name);
        self.emit_path(
            SERVICE_PATH.into(),
            SERVICE_IFACE,
            "CollectionCreated",
            path.clone(),
        );
        self.collections_changed(st);
        Ok(path)
    }

    /// Unlock what `paths` name (collections, aliases, items): only the
    /// marks `Lock` left, since W is known.
    fn unlock_known(&self, st: &mut State, paths: &[OwnedObjectPath]) -> Vec<OwnedObjectPath> {
        let mut out = Vec::new();
        for p in paths {
            if let Some(c) = st.collection_of(p.as_str()) {
                if st.soft.remove(&c) {
                    self.locked_changed(st, &c);
                }
                out.push(p.clone());
            }
        }
        out
    }

    fn perform(&self, st: &mut State, p: Pending) -> OwnedValue {
        match p {
            Pending::Unlock(paths) => owned(Value::from(self.unlock_known(st, &paths))),
            Pending::CreateItem {
                collection,
                label,
                attributes,
                secret,
                content_type,
                replace,
            } => {
                let coll = st.store.resolve(&collection).unwrap_or(collection);
                match self.create_item(
                    st,
                    &coll,
                    &label,
                    attributes,
                    secret,
                    &content_type,
                    replace,
                ) {
                    Ok(path) => owned(Value::from(op(&path))),
                    Err(_) => owned(Value::from(root())),
                }
            }
            Pending::CreateCollection { label, alias } => {
                if let Some(c) = store::valid_name(&alias)
                    .then(|| st.store.resolve(&alias))
                    .flatten()
                {
                    return owned(Value::from(op(&collection_path(&c))));
                }
                match self.create_collection(st, &label, &alias) {
                    Ok(path) => owned(Value::from(op(&path))),
                    Err(_) => owned(Value::from(root())),
                }
            }
        }
    }

    fn new_prompt(&self, st: &mut State, owner: &str, pending: Pending) -> String {
        let path = st.new_path(PROMPT_PREFIX, 'p');
        st.prompts.insert(
            path.clone(),
            PromptState {
                owner: owner.to_string(),
                pending: Some(pending),
                started: false,
                dismissed: Arc::new(AtomicBool::new(false)),
            },
        );
        path
    }

    /// W, for a prompt: now, after the grace, or from the window.
    fn acquire(&self, dismissed: &AtomicBool) -> Option<SessionKey> {
        if let Some(w) = self.source.key() {
            return Some(w);
        }
        if self.source.just_started()
            && let Some(w) = self.source.wait(GRACE)
        {
            return Some(w);
        }
        let mut last_no = lk(&self.asking);
        if let Some(w) = self.source.key() {
            return Some(w);
        }
        if dismissed.load(Ordering::SeqCst) {
            return None;
        }
        if last_no.is_some_and(|t| t.elapsed() < QUIET_AFTER_NO) {
            return None;
        }
        let Some(mut window) = self.source.ask() else {
            self.log("keyring: locked, and there is no window to ask for the login password");
            *last_no = Some(Instant::now());
            return None;
        };
        let start = Instant::now();
        let limit = self.source.ask_timeout();
        let got = loop {
            if let Some(w) = self.source.wait(Duration::from_millis(200)) {
                break Some(w);
            }
            if dismissed.load(Ordering::SeqCst) {
                break None;
            }
            if window.finished() {
                // the window may have sent the password just before closing
                break self.source.wait(Duration::from_millis(500));
            }
            if start.elapsed() > limit {
                window.stop();
                break None;
            }
        };
        if got.is_none() {
            *last_no = Some(Instant::now());
        }
        got
    }

    fn drop_client(&self, name: &str) {
        let (sessions, prompts) = {
            let mut st = self.st();
            let sessions: Vec<String> = st
                .sessions
                .iter()
                .filter(|(_, s)| s.owner == name)
                .map(|(p, _)| p.clone())
                .collect();
            for p in &sessions {
                st.sessions.remove(p);
            }
            let prompts: Vec<String> = st
                .prompts
                .iter()
                .filter(|(_, p)| p.owner == name)
                .map(|(path, p)| {
                    p.dismissed.store(true, Ordering::SeqCst);
                    path.clone()
                })
                .collect();
            (sessions, prompts)
        };
        if let Some(conn) = self.conn.get() {
            let server = conn.object_server();
            for p in sessions {
                let _ = server.remove::<SessionObj, _>(p.as_str());
            }
            // a prompt nobody started ends here; a running one ends itself
            for p in prompts {
                let idle = self.st().prompts.get(&p).is_some_and(|x| !x.started);
                if idle {
                    self.st().prompts.remove(&p);
                    let _ = server.remove::<PromptObj, _>(p.as_str());
                }
            }
        }
    }
}

fn add_obj(core: &Arc<Core>, o: &Obj) -> Option<(String, ObjKind)> {
    let path = obj_path(o);
    let kind = match o {
        Obj::Collection(c) => ObjKind::Collection(CollectionObj {
            core: core.clone(),
            target: Target::Name(c.clone()),
        }),
        Obj::Alias(a) => ObjKind::Collection(CollectionObj {
            core: core.clone(),
            target: Target::Alias(a.clone()),
        }),
        Obj::Item(c, n) => ObjKind::Item(ItemObj {
            core: core.clone(),
            collection: c.clone(),
            n: *n,
        }),
    };
    Some((path, kind))
}

enum ObjKind {
    Collection(CollectionObj),
    Item(ItemObj),
}

async fn apply(core: &Arc<Core>, server: &ObjectServer, plan: Plan) {
    for o in &plan.remove {
        let path = obj_path(o);
        let _ = match o {
            Obj::Item(..) => server.remove::<ItemObj, _>(path.as_str()).await,
            _ => server.remove::<CollectionObj, _>(path.as_str()).await,
        };
    }
    for o in &plan.add {
        if let Some((path, kind)) = add_obj(core, o) {
            let _ = match kind {
                ObjKind::Collection(c) => server.at(path.as_str(), c).await,
                ObjKind::Item(i) => server.at(path.as_str(), i).await,
            };
        }
    }
}

fn apply_blocking(core: &Arc<Core>, plan: Plan) {
    let Some(conn) = core.conn.get() else {
        return;
    };
    let server = conn.object_server();
    for o in &plan.remove {
        let path = obj_path(o);
        let _ = match o {
            Obj::Item(..) => server.remove::<ItemObj, _>(path.as_str()),
            _ => server.remove::<CollectionObj, _>(path.as_str()),
        };
    }
    for o in &plan.add {
        if let Some((path, kind)) = add_obj(core, o) {
            let _ = match kind {
                ObjKind::Collection(c) => server.at(path.as_str(), c),
                ObjKind::Item(i) => server.at(path.as_str(), i),
            };
        }
    }
}

fn sender(h: &Header<'_>) -> String {
    h.sender().map(|s| s.to_string()).unwrap_or_default()
}

fn string_prop(props: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    props
        .get(key)
        .and_then(|v| <&str>::try_from(&**v).ok().map(str::to_string))
}

fn attrs_prop(props: &HashMap<String, OwnedValue>) -> BTreeMap<String, String> {
    props
        .get(ATTRIBUTES_PROP)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| HashMap::<String, String>::try_from(v).ok())
        .map(|m| m.into_iter().collect())
        .unwrap_or_default()
}

// ── org.freedesktop.Secret.Service ──────────────────────────────────────

struct ServiceObj {
    core: Arc<Core>,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceObj {
    async fn open_session(
        &self,
        algorithm: String,
        input: OwnedValue,
        #[zbus(header)] h: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let (output, aes) = match algorithm.as_str() {
            crypto::PLAIN => (owned(Value::from("")), None),
            crypto::DH if !self.core.no_dh => {
                let peer = Vec::<u8>::try_from(input)
                    .map_err(|_| fdo::Error::InvalidArgs("The input must be bytes.".into()))?;
                let pair = crypto::KeyPair::generate();
                let key = pair
                    .aes_key(&peer)
                    .ok_or_else(|| fdo::Error::InvalidArgs("Not a public key.".into()))?;
                (owned(Value::from(pair.public.clone())), Some(key))
            }
            _ => {
                return Err(fdo::Error::NotSupported(format!(
                    "Safe speaks {} and {}.",
                    crypto::PLAIN,
                    crypto::DH
                )));
            }
        };
        let path = {
            let mut st = self.core.st();
            let path = st.new_path(SESSION_PREFIX, 's');
            st.sessions.insert(
                path.clone(),
                Session {
                    owner: sender(&h),
                    aes,
                },
            );
            path
        };
        server
            .at(
                path.as_str(),
                SessionObj {
                    core: self.core.clone(),
                    path: path.clone(),
                },
            )
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        Ok((output, op(&path)))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(header)] h: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let label = string_prop(&properties, COLLECTION_LABEL_PROP)
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| "Untitled".into());
        // the prompt (locked) or the new collection's path and objects
        let (made, prompt, plan) = {
            let mut st = self.core.st();
            if let Some(c) = store::valid_name(&alias)
                .then(|| st.store.resolve(&alias))
                .flatten()
            {
                return Ok((op(&collection_path(&c)), root()));
            }
            if self.core.ensure_open(&mut st) {
                let path = self.core.create_collection(&mut st, &label, &alias)?;
                (Some(path), None, self.core.plan(&mut st))
            } else {
                let p = self.core.new_prompt(
                    &mut st,
                    &sender(&h),
                    Pending::CreateCollection { label, alias },
                );
                (None, Some(p), Plan::default())
            }
        };
        apply(&self.core, server, plan).await;
        match (made, prompt) {
            (Some(path), _) => Ok((op(&path), root())),
            (None, Some(p)) => {
                register_prompt(&self.core, server, &p).await;
                Ok((root(), op(&p)))
            }
            _ => Err(failed("Nothing was made.")),
        }
    }

    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let attrs: BTreeMap<String, String> = attributes.into_iter().collect();
        let mut st = self.core.st();
        let (mut unlocked, mut locked) = (Vec::new(), Vec::new());
        if self.core.ensure_open(&mut st) {
            for i in st.store.search(None, &attrs) {
                let p = op(&item_path(&i.collection, i.n));
                if st.soft.contains(&i.collection) {
                    locked.push(p);
                } else {
                    unlocked.push(p);
                }
            }
        } else {
            for s in st.index.search(None, &attrs) {
                locked.push(op(&item_path(&s.collection, s.n)));
            }
        }
        (unlocked, locked)
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] h: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        // open: what was unlocked; locked: a prompt
        let (done, prompt, plan) = {
            let mut st = self.core.st();
            if self.core.ensure_open(&mut st) {
                let done = self.core.unlock_known(&mut st, &objects);
                (done, None, self.core.plan(&mut st))
            } else {
                let known: Vec<OwnedObjectPath> = objects
                    .into_iter()
                    .filter(|p| st.collection_of(p.as_str()).is_some())
                    .collect();
                if known.is_empty() {
                    return Ok((Vec::new(), root()));
                }
                let p = self
                    .core
                    .new_prompt(&mut st, &sender(&h), Pending::Unlock(known));
                (Vec::new(), Some(p), Plan::default())
            }
        };
        apply(&self.core, server, plan).await;
        match prompt {
            Some(p) => {
                register_prompt(&self.core, server, &p).await;
                Ok((Vec::new(), op(&p)))
            }
            None => Ok((done, root())),
        }
    }

    fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let mut st = self.core.st();
        if st.w.is_none() {
            return (objects, root());
        }
        let mut done = Vec::new();
        for p in objects {
            if let Some(c) = st.collection_of(p.as_str()) {
                if st.soft.insert(c.clone()) {
                    self.core.locked_changed(&st, &c);
                }
                done.push(p);
            }
        }
        (done, root())
    }

    fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] h: Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, Secret>, SecretError> {
        let owner = sender(&h);
        let mut st = self.core.st();
        self.core.ensure_open(&mut st);
        if !st
            .sessions
            .get(session.as_str())
            .is_some_and(|s| s.owner == owner)
        {
            return Err(SecretError::NoSession("No such session.".into()));
        }
        let mut out = HashMap::new();
        for p in items {
            let Some(Obj::Item(c, n)) = parse_path(p.as_str()) else {
                continue;
            };
            if st.is_locked(&c) {
                continue;
            }
            if let Some(i) = st.store.item(&c, n) {
                let s =
                    self.core
                        .encode(&st, session.as_str(), &owner, &i.secret, &i.content_type)?;
                out.insert(p, s);
            }
        }
        Ok(out)
    }

    fn read_alias(&self, name: String) -> OwnedObjectPath {
        let st = self.core.st();
        match st.store.aliases.get(&name) {
            Some(c) if st.store.collection(c).is_some() => op(&collection_path(c)),
            _ => root(),
        }
    }

    async fn set_alias(
        &self,
        name: String,
        collection: OwnedObjectPath,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(), SecretError> {
        if !store::valid_name(&name) {
            return Err(failed("An alias is letters, digits and _."));
        }
        let plan = {
            let mut st = self.core.st();
            if !self.core.ensure_open(&mut st) {
                return Err(locked_err());
            }
            let target = if collection.as_str() == NO_PROMPT {
                None
            } else {
                Some(
                    st.collection_of(collection.as_str())
                        .ok_or_else(|| SecretError::NoSuchObject("No such collection.".into()))?,
                )
            };
            self.core.mutate(&mut st, |s| {
                match target {
                    Some(c) => s.aliases.insert(name.clone(), c),
                    None => s.aliases.remove(&name),
                };
                Ok(())
            })?;
            self.core.plan(&mut st)
        };
        apply(&self.core, server, plan).await;
        Ok(())
    }

    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        self.core
            .st()
            .store
            .collections
            .iter()
            .map(|c| op(&collection_path(&c.name)))
            .collect()
    }

    #[zbus(signal)]
    async fn collection_created(
        e: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(
        e: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_changed(
        e: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

async fn register_prompt(core: &Arc<Core>, server: &ObjectServer, path: &str) {
    let _ = server
        .at(
            path,
            PromptObj {
                core: core.clone(),
                path: path.to_string(),
            },
        )
        .await;
}

// ── org.freedesktop.Secret.Collection ───────────────────────────────────

enum Target {
    Name(String),
    Alias(String),
}

struct CollectionObj {
    core: Arc<Core>,
    target: Target,
}

impl CollectionObj {
    fn name(&self, st: &State) -> Option<String> {
        match &self.target {
            Target::Name(n) => st.store.collection(n).map(|_| n.clone()),
            Target::Alias(a) => st
                .store
                .aliases
                .get(a)
                .filter(|c| st.store.collection(c).is_some())
                .cloned(),
        }
    }

    fn gone() -> SecretError {
        SecretError::NoSuchObject("No such collection.".into())
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionObj {
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<OwnedObjectPath, SecretError> {
        let plan = {
            let mut st = self.core.st();
            let name = self.name(&st).ok_or_else(Self::gone)?;
            if !self.core.ensure_open(&mut st) {
                return Err(locked_err());
            }
            self.core.mutate(&mut st, |s| {
                s.remove_collection(&name);
                Ok(())
            })?;
            st.soft.remove(&name);
            self.core.emit_path(
                SERVICE_PATH.into(),
                SERVICE_IFACE,
                "CollectionDeleted",
                collection_path(&name),
            );
            self.core.collections_changed(&st);
            self.core.plan(&mut st)
        };
        apply(&self.core, server, plan).await;
        Ok(root())
    }

    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, SecretError> {
        let attrs: BTreeMap<String, String> = attributes.into_iter().collect();
        let mut st = self.core.st();
        let name = self.name(&st).ok_or_else(Self::gone)?;
        let found = if self.core.ensure_open(&mut st) {
            st.store
                .search(Some(&name), &attrs)
                .into_iter()
                .map(|i| op(&item_path(&i.collection, i.n)))
                .collect()
        } else {
            st.index
                .search(Some(&name), &attrs)
                .into_iter()
                .map(|s| op(&item_path(&s.collection, s.n)))
                .collect()
        };
        Ok(found)
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
        #[zbus(header)] h: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let owner = sender(&h);
        let label = string_prop(&properties, LABEL_PROP).unwrap_or_default();
        let attributes = attrs_prop(&properties);
        let (item, prompt, plan) = {
            let mut st = self.core.st();
            let name = self.name(&st).ok_or_else(Self::gone)?;
            let (plain, content_type) = self.core.decode(&st, &secret, &owner)?;
            drop(secret);
            if !self.core.ensure_open(&mut st) {
                let p = self.core.new_prompt(
                    &mut st,
                    &owner,
                    Pending::CreateItem {
                        collection: name,
                        label,
                        attributes,
                        secret: plain,
                        content_type,
                        replace,
                    },
                );
                (None, Some(p), Plan::default())
            } else {
                let path = self.core.create_item(
                    &mut st,
                    &name,
                    &label,
                    attributes,
                    plain,
                    &content_type,
                    replace,
                )?;
                (Some(path), None, self.core.plan(&mut st))
            }
        };
        apply(&self.core, server, plan).await;
        match (item, prompt) {
            (Some(i), _) => Ok((op(&i), root())),
            (None, Some(p)) => {
                register_prompt(&self.core, server, &p).await;
                Ok((root(), op(&p)))
            }
            _ => Err(failed("Nothing was made.")),
        }
    }

    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        let st = self.core.st();
        match self.name(&st) {
            Some(n) => st.item_paths(&n),
            None => Vec::new(),
        }
    }

    #[zbus(property)]
    fn label(&self) -> String {
        let st = self.core.st();
        self.name(&st)
            .and_then(|n| st.store.collection(&n).map(|c| c.label.clone()))
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn set_label(&mut self, label: String) -> fdo::Result<()> {
        let mut st = self.core.st();
        let name = self
            .name(&st)
            .ok_or_else(|| fdo::Error::UnknownObject("No such collection.".into()))?;
        if !self.core.ensure_open(&mut st) {
            return Err(fdo::Error::AccessDenied("The keyring is locked.".into()));
        }
        self.core
            .mutate(&mut st, |s| {
                if let Some(c) = s.collection_mut(&name) {
                    c.label = label;
                    c.modified = store::now();
                }
                Ok(())
            })
            .map_err(|_| fdo::Error::Failed("The keyring can't be saved.".into()))?;
        self.core.emit_path(
            SERVICE_PATH.into(),
            SERVICE_IFACE,
            "CollectionChanged",
            collection_path(&name),
        );
        Ok(())
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        let mut st = self.core.st();
        self.core.ensure_open(&mut st);
        match self.name(&st) {
            Some(n) => st.is_locked(&n),
            None => true,
        }
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        let st = self.core.st();
        self.name(&st)
            .and_then(|n| st.store.collection(&n).map(|c| c.created))
            .unwrap_or(0)
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        let st = self.core.st();
        self.name(&st)
            .and_then(|n| st.store.collection(&n).map(|c| c.modified))
            .unwrap_or(0)
    }

    #[zbus(signal)]
    async fn item_created(e: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(e: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(e: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
}

// ── org.freedesktop.Secret.Item ─────────────────────────────────────────

struct ItemObj {
    core: Arc<Core>,
    collection: String,
    n: u64,
}

impl ItemObj {
    fn gone() -> SecretError {
        SecretError::NoSuchObject("No such item.".into())
    }

    fn path(&self) -> String {
        item_path(&self.collection, self.n)
    }

    /// The state, open, with this item in it.
    fn open<'a>(&self, st: &mut MutexGuard<'a, State>) -> Result<(), SecretError> {
        if !st.item_exists(&self.collection, self.n) {
            return Err(Self::gone());
        }
        if !self.core.ensure_open(st) || st.is_locked(&self.collection) {
            return Err(locked_err());
        }
        if st.store.item(&self.collection, self.n).is_none() {
            return Err(Self::gone());
        }
        Ok(())
    }

    fn changed(&self) {
        self.core.emit_path(
            collection_path(&self.collection),
            COLLECTION_IFACE,
            "ItemChanged",
            self.path(),
        );
    }

    fn edit(&self, f: impl FnOnce(&mut store::Item)) -> fdo::Result<()> {
        let mut st = self.core.st();
        self.open(&mut st)
            .map_err(|_| fdo::Error::AccessDenied("The keyring is locked.".into()))?;
        let (c, n) = (self.collection.clone(), self.n);
        self.core
            .mutate(&mut st, |s| {
                if let Some(i) = s.item_mut(&c, n) {
                    f(i);
                    i.modified = store::now();
                }
                s.touch(&c);
                Ok(())
            })
            .map_err(|_| fdo::Error::Failed("The keyring can't be saved.".into()))?;
        drop(st);
        self.changed();
        Ok(())
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemObj {
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<OwnedObjectPath, SecretError> {
        let plan = {
            let mut st = self.core.st();
            self.open(&mut st)?;
            let (c, n) = (self.collection.clone(), self.n);
            self.core.mutate(&mut st, |s| {
                s.remove_item(&c, n);
                Ok(())
            })?;
            self.core.emit_path(
                collection_path(&c),
                COLLECTION_IFACE,
                "ItemDeleted",
                self.path(),
            );
            self.core.items_changed(&st, &c);
            self.core.plan(&mut st)
        };
        apply(&self.core, server, plan).await;
        Ok(root())
    }

    fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] h: Header<'_>,
    ) -> Result<(Secret,), SecretError> {
        let mut st = self.core.st();
        self.open(&mut st)?;
        let i = st
            .store
            .item(&self.collection, self.n)
            .ok_or_else(Self::gone)?;
        let s = self.core.encode(
            &st,
            session.as_str(),
            &sender(&h),
            &i.secret,
            &i.content_type,
        )?;
        Ok((s,))
    }

    fn set_secret(&self, secret: Secret, #[zbus(header)] h: Header<'_>) -> Result<(), SecretError> {
        let mut st = self.core.st();
        self.open(&mut st)?;
        let (plain, content_type) = self.core.decode(&st, &secret, &sender(&h))?;
        drop(secret);
        let (c, n) = (self.collection.clone(), self.n);
        self.core.mutate(&mut st, |s| {
            if let Some(i) = s.item_mut(&c, n) {
                i.secret = plain;
                if !content_type.is_empty() {
                    i.content_type = content_type;
                }
                i.modified = store::now();
            }
            s.touch(&c);
            Ok(())
        })?;
        drop(st);
        self.changed();
        Ok(())
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        let mut st = self.core.st();
        self.core.ensure_open(&mut st);
        st.is_locked(&self.collection)
    }

    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        let st = self.core.st();
        if st.is_locked(&self.collection) {
            return HashMap::new();
        }
        st.store
            .item(&self.collection, self.n)
            .map(|i| i.attributes.clone().into_iter().collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn set_attributes(&mut self, attributes: HashMap<String, String>) -> fdo::Result<()> {
        self.edit(|i| i.attributes = attributes.into_iter().collect())
    }

    #[zbus(property)]
    fn label(&self) -> String {
        let st = self.core.st();
        if st.is_locked(&self.collection) {
            return String::new();
        }
        st.store
            .item(&self.collection, self.n)
            .map(|i| i.label.clone())
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn set_label(&mut self, label: String) -> fdo::Result<()> {
        self.edit(|i| i.label = label)
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        let st = self.core.st();
        st.store
            .item(&self.collection, self.n)
            .map(|i| i.created)
            .unwrap_or(0)
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        let st = self.core.st();
        st.store
            .item(&self.collection, self.n)
            .map(|i| i.modified)
            .unwrap_or(0)
    }
}

// ── org.freedesktop.Secret.Session ──────────────────────────────────────

struct SessionObj {
    core: Arc<Core>,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionObj {
    async fn close(&self, #[zbus(object_server)] server: &ObjectServer) -> fdo::Result<()> {
        self.core.st().sessions.remove(&self.path);
        let _ = server.remove::<SessionObj, _>(self.path.as_str()).await;
        Ok(())
    }
}

// ── org.freedesktop.Secret.Prompt ───────────────────────────────────────

struct PromptObj {
    core: Arc<Core>,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObj {
    fn prompt(&self, window_id: String) -> fdo::Result<()> {
        let _ = window_id;
        let dismissed = {
            let mut st = self.core.st();
            let p = st
                .prompts
                .get_mut(&self.path)
                .ok_or_else(|| fdo::Error::UnknownObject("No such prompt.".into()))?;
            if p.started {
                return Ok(());
            }
            p.started = true;
            p.dismissed.clone()
        };
        let core = self.core.clone();
        let path = self.path.clone();
        std::thread::Builder::new()
            .name("keyring-prompt".into())
            .spawn(move || {
                // the caller hears Completed after Prompt's own reply
                std::thread::sleep(Duration::from_millis(50));
                let w = core.acquire(&dismissed);
                finish(&core, &path, w);
            })
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }

    fn dismiss(&self) -> fdo::Result<()> {
        let idle = {
            let st = self.core.st();
            let p = st
                .prompts
                .get(&self.path)
                .ok_or_else(|| fdo::Error::UnknownObject("No such prompt.".into()))?;
            p.dismissed.store(true, Ordering::SeqCst);
            !p.started
        };
        if idle {
            let core = self.core.clone();
            let path = self.path.clone();
            std::thread::spawn(move || finish(&core, &path, None));
        }
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        e: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

/// A prompt is done: with W, what it was for happens; without, it is
/// dismissed. `Completed` goes out, the prompt object goes away.
fn finish(core: &Arc<Core>, path: &str, w: Option<SessionKey>) {
    let (dismissed, result, plan) = {
        let mut st = core.st();
        let Some(mut p) = st.prompts.remove(path) else {
            return;
        };
        let Some(pending) = p.pending.take() else {
            return;
        };
        let cancelled = p.dismissed.load(Ordering::SeqCst);
        match w {
            Some(w) if !cancelled && core.open_with(&mut st, w.clone()) => {
                let result = core.perform(&mut st, pending);
                (false, result, core.plan(&mut st))
            }
            _ => (true, pending.nothing(), Plan::default()),
        }
    };
    apply_blocking(core, plan);
    core.emit(Sig::Completed {
        path: path.to_string(),
        dismissed,
        result,
    });
    if let Some(conn) = core.conn.get() {
        let _ = conn.object_server().remove::<PromptObj, _>(path);
    }
}

fn emit_one(conn: &zbus::blocking::Connection, s: Sig) -> zbus::Result<()> {
    let none = None::<zbus::names::BusName<'_>>;
    match s {
        Sig::Path {
            path,
            iface,
            member,
            arg,
        } => {
            let arg = ObjectPath::try_from(arg.as_str())?;
            conn.emit_signal(none, path.as_str(), iface, member, &(arg,))
        }
        Sig::Props {
            path,
            iface,
            changed,
        } => {
            let map: HashMap<&str, &Value<'_>> = changed.iter().map(|(k, v)| (*k, &**v)).collect();
            conn.emit_signal(
                none,
                path.as_str(),
                PROPS_IFACE,
                "PropertiesChanged",
                &(iface, map, Vec::<&str>::new()),
            )
        }
        Sig::Completed {
            path,
            dismissed,
            result,
        } => conn.emit_signal(
            none,
            path.as_str(),
            PROMPT_IFACE,
            "Completed",
            &(dismissed, &*result),
        ),
    }
}

// ── the daemon's handle ─────────────────────────────────────────────────

/// One app secret, for `keyring list` (never its secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemInfo {
    pub id: String,
    pub label: String,
    pub collection: String,
    pub app: String,
    pub created: u64,
    pub modified: u64,
}

/// Safe's keyring: the store, and its objects once [`Keyring::serve`]
/// put them on a bus.
#[derive(Clone)]
pub struct Keyring {
    core: Arc<Core>,
}

impl Keyring {
    pub fn new(files: Files, source: Arc<dyn KeySource>) -> Keyring {
        let index = Index::read(&files.index);
        let store = match &index {
            Some(i) => i.shell(),
            None => Store::fresh(),
        };
        let no_dh = std::env::var_os("EWE_SAFE_SECRETS_NO_DH").is_some();
        Keyring {
            core: Arc::new(Core {
                files,
                source,
                st: Mutex::new(State {
                    w: None,
                    store,
                    index: index.unwrap_or_default(),
                    soft: HashSet::new(),
                    error: None,
                    sessions: HashMap::new(),
                    prompts: HashMap::new(),
                    next: 0,
                    objects: BTreeSet::new(),
                }),
                conn: OnceLock::new(),
                signals: OnceLock::new(),
                serving: AtomicBool::new(false),
                asking: Mutex::new(None),
                no_dh,
            }),
        }
    }

    /// Put the objects on `conn` (once) and ask for `org.freedesktop.secrets`
    /// without queueing: `true` = we serve it now, `false` = another
    /// keyring holds it (never fought over).
    pub fn serve(&self, conn: &zbus::blocking::Connection) -> zbus::Result<bool> {
        let core = &self.core;
        if core.conn.set(conn.clone()).is_ok() {
            let (tx, rx) = channel::<Sig>();
            let _ = core.signals.set(Mutex::new(tx));
            let c = conn.clone();
            std::thread::Builder::new()
                .name("keyring-signals".into())
                .spawn(move || {
                    for s in rx {
                        let _ = emit_one(&c, s);
                    }
                })
                .map_err(|e| zbus::Error::Failure(e.to_string()))?;
            conn.object_server()
                .at(SERVICE_PATH, ServiceObj { core: core.clone() })?;
            let plan = {
                let mut st = core.st();
                core.ensure_open(&mut st);
                // nothing was on a bus before: put everything there now
                st.objects.clear();
                core.plan(&mut st)
            };
            apply_blocking(core, plan);
            // a client that leaves takes its sessions with it
            let proxy = zbus::blocking::fdo::DBusProxy::new(conn)?;
            let gone = proxy.receive_name_owner_changed()?;
            let c2 = core.clone();
            std::thread::Builder::new()
                .name("keyring-clients".into())
                .spawn(move || {
                    for sig in gone {
                        if let Ok(a) = sig.args()
                            && a.new_owner().is_none()
                            && a.name().starts_with(':')
                        {
                            c2.drop_client(a.name().as_str());
                        }
                    }
                })
                .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        }
        let reply = conn.request_name_with_flags(NAME, RequestNameFlags::DoNotQueue.into())?;
        let ours = matches!(
            reply,
            RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner
        );
        core.serving.store(ours, Ordering::SeqCst);
        if reply == RequestNameReply::PrimaryOwner {
            core.log("keyring: serving org.freedesktop.secrets");
        }
        Ok(ours)
    }

    /// Give `org.freedesktop.secrets` back (`keyring release`).
    pub fn release(&self) -> zbus::Result<()> {
        if let Some(conn) = self.core.conn.get() {
            conn.release_name(NAME)?;
        }
        self.core.serving.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn serving(&self) -> bool {
        self.core.serving.load(Ordering::SeqCst)
    }

    /// W may have arrived: open the keyring. `true` = open.
    pub fn wake(&self) -> bool {
        let (open, plan) = {
            let mut st = self.core.st();
            let open = self.core.ensure_open(&mut st);
            (open, self.core.plan(&mut st))
        };
        apply_blocking(&self.core, plan);
        open
    }

    pub fn is_open(&self) -> bool {
        self.core.st().w.is_some()
    }

    /// Why W didn't open `keyring.safe` (`wrong-key`, `unreadable`).
    pub fn error(&self) -> Option<String> {
        self.core.st().error.clone()
    }

    /// How many items (known from the index while locked).
    pub fn count(&self) -> usize {
        let st = self.core.st();
        if st.w.is_some() {
            st.store.items.len()
        } else {
            st.index.items.len()
        }
    }

    /// Every item, by label; `None` while locked.
    pub fn list(&self) -> Option<Vec<ItemInfo>> {
        let st = self.core.st();
        st.w.as_ref()?;
        let mut out: Vec<ItemInfo> = st
            .store
            .items
            .iter()
            .map(|i| ItemInfo {
                id: i.id.clone(),
                label: i.label.clone(),
                collection: i.collection.clone(),
                app: store::app_of(&i.attributes),
                created: i.created,
                modified: i.modified,
            })
            .collect();
        out.sort_by_key(|a| a.label.to_lowercase());
        Some(out)
    }

    /// Remove one item by its id: `Ok(false)` when there is none.
    pub fn remove(&self, id: &str) -> Result<bool, String> {
        let plan = {
            let mut st = self.core.st();
            if !self.core.ensure_open(&mut st) {
                return Err("locked".into());
            }
            let Some((c, n)) = st
                .store
                .items
                .iter()
                .find(|i| i.id == id)
                .map(|i| (i.collection.clone(), i.n))
            else {
                return Ok(false);
            };
            self.core
                .mutate(&mut st, |s| {
                    s.remove_item(&c, n);
                    Ok(())
                })
                .map_err(|_| "The keyring can't be saved.".to_string())?;
            self.core.emit_path(
                collection_path(&c),
                COLLECTION_IFACE,
                "ItemDeleted",
                item_path(&c, n),
            );
            self.core.items_changed(&st, &c);
            self.core.plan(&mut st)
        };
        apply_blocking(&self.core, plan);
        Ok(true)
    }

    /// Add an import (newest wins per collection and attributes).
    pub fn merge(&self, incoming: Vec<Incoming>) -> Result<Merged, String> {
        let plan = {
            let mut st = self.core.st();
            if !self.core.ensure_open(&mut st) {
                return Err("locked".into());
            }
            let before: BTreeSet<String> = st
                .store
                .collections
                .iter()
                .map(|c| c.name.clone())
                .collect();
            let merged = self
                .core
                .mutate(&mut st, |s| Ok(s.merge(incoming)))
                .map_err(|_| "The keyring can't be saved.".to_string())?;
            let names: Vec<String> = st
                .store
                .collections
                .iter()
                .map(|c| c.name.clone())
                .collect();
            for c in &names {
                if !before.contains(c) {
                    self.core.emit_path(
                        SERVICE_PATH.into(),
                        SERVICE_IFACE,
                        "CollectionCreated",
                        collection_path(c),
                    );
                }
                self.core.items_changed(&st, c);
            }
            self.core.collections_changed(&st);
            let plan = self.core.plan(&mut st);
            (merged, plan)
        };
        let (merged, plan) = plan;
        apply_blocking(&self.core, plan);
        Ok(merged)
    }

    /// What [`Keyring::merge`] would do, changing nothing (`import
    /// --dry-run`). Locked, it counts against an empty keyring.
    pub fn preview(&self, incoming: Vec<Incoming>) -> Merged {
        let st = self.core.st();
        let mut copy = if st.w.is_some() {
            st.store.clone()
        } else {
            Store::fresh()
        };
        drop(st);
        copy.merge(incoming)
    }

    /// Write `keyring.safe` (and its index) now, even unchanged: adopt makes
    /// the files exist.
    pub fn save(&self) -> Result<(), String> {
        let mut st = self.core.st();
        if !self.core.ensure_open(&mut st) {
            return Err("locked".into());
        }
        self.core
            .mutate(&mut st, |_| Ok(()))
            .map_err(|_| "The keyring can't be saved.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_name_their_objects() {
        assert_eq!(
            parse_path("/org/freedesktop/secrets/collection/login"),
            Some(Obj::Collection("login".into()))
        );
        assert_eq!(
            parse_path("/org/freedesktop/secrets/collection/login/12"),
            Some(Obj::Item("login".into(), 12))
        );
        assert_eq!(
            parse_path("/org/freedesktop/secrets/aliases/default"),
            Some(Obj::Alias("default".into()))
        );
        assert_eq!(parse_path("/org/freedesktop/secrets/collection/a-b"), None);
        assert_eq!(
            parse_path("/org/freedesktop/secrets/collection/login/x"),
            None
        );
        assert_eq!(parse_path("/"), None);
        for o in [
            Obj::Collection("login".into()),
            Obj::Alias("default".into()),
            Obj::Item("work".into(), 3),
        ] {
            assert_eq!(parse_path(&obj_path(&o)), Some(o));
        }
    }
}
