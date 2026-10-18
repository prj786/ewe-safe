//! The keyring's two files in `$XDG_STATE_HOME/ewe/safe/` (docs/SYSTEM.md
//! §3, as built in docs/KEYRING.md):
//!
//! - `keyring.safe`, sealed by W (safe-login's `KIND_KEYRING` blob): every
//!   collection, alias and item, secrets included —
//!   `{"v": 1, "collections": [{name, label, created, modified, next}],
//!   "aliases": {"default": "login"}, "items": [{id, collection, n, label,
//!   attributes, secret (b64), content_type, created, modified}]}`.
//! - `keyring.index`, not sealed, so a locked keyring can still say which
//!   items match a search (gnome-keyring keeps hashed attributes for the
//!   same reason): the collections and aliases, and per item its collection,
//!   its number and a salted SHA-256 of each attribute. Never a label, a
//!   value of an attribute or a secret.
//!
//! An item's object path is `…/collection/<collection>/<n>`; `n` is never
//! reused in a collection, so paths stay the same across restarts. Both
//! files are written whole (temp, fsync, rename) on every change.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use safe_login::SessionKey;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_COLLECTION: &str = "login";
pub const DEFAULT_ALIAS: &str = "default";
const VERSION: u64 = 1;
const KIND_INDEX: &str = "ewe-safe-keyring-index";

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    /// The last part of its object path: `[A-Za-z0-9_]+`.
    pub name: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    /// The next item number.
    pub next: u64,
}

#[derive(Clone)]
pub struct Item {
    /// Stable, for `keyring list` and `keyring rm`.
    pub id: String,
    pub collection: String,
    pub n: u64,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("collection", &self.collection)
            .field("n", &self.n)
            .finish_non_exhaustive()
    }
}

/// What a locked keyring knows of an item (from `keyring.index`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stub {
    pub collection: String,
    pub n: u64,
    pub hashes: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Store {
    pub collections: Vec<Collection>,
    pub aliases: BTreeMap<String, String>,
    pub items: Vec<Item>,
}

/// The two files.
#[derive(Clone, Debug)]
pub struct Files {
    pub sealed: PathBuf,
    pub index: PathBuf,
}

#[derive(Debug)]
pub enum LoadError {
    /// W doesn't open `keyring.safe` (it was sealed by another login key).
    WrongKey,
    Corrupt(String),
    Io(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::WrongKey => write!(f, "this computer's key doesn't open keyring.safe"),
            LoadError::Corrupt(why) => write!(f, "keyring.safe can't be read: {why}"),
            LoadError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// `[A-Za-z0-9_]+` from a label: what a new collection's path is called.
pub fn path_name(label: &str) -> String {
    let mut s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    s = s.trim_matches('_').to_string();
    if s.is_empty() { "collection".into() } else { s }
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A random id in the UUID v4 shape, like Safe's item ids.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("the system's random source");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn hash(salt: &[u8], name: &str, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(name.as_bytes());
    h.update([0u8]);
    h.update(value.as_bytes());
    h.finalize()[..16]
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Every string in `v` wiped (a parsed or built copy of the sealed file).
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => m.values_mut().for_each(wipe),
        _ => {}
    }
}

fn num(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn collections_json(cs: &[Collection]) -> Value {
    cs.iter()
        .map(|c| {
            json!({"name": c.name, "label": c.label, "created": c.created,
                   "modified": c.modified, "next": c.next})
        })
        .collect()
}

fn collections_from(v: Option<&Value>) -> Vec<Collection> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|c| {
                    let name = text(c, "name");
                    valid_name(&name).then(|| Collection {
                        label: text(c, "label"),
                        created: num(c, "created"),
                        modified: num(c, "modified"),
                        next: num(c, "next").max(1),
                        name,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn aliases_from(v: Option<&Value>) -> BTreeMap<String, String> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .filter(|(k, v)| valid_name(k) && valid_name(v))
                .collect()
        })
        .unwrap_or_default()
}

impl Store {
    /// A new keyring: the collection `login`, which `default` names.
    pub fn fresh() -> Store {
        let t = now();
        Store {
            collections: vec![Collection {
                name: DEFAULT_COLLECTION.into(),
                label: "Login".into(),
                created: t,
                modified: t,
                next: 1,
            }],
            aliases: BTreeMap::from([(DEFAULT_ALIAS.into(), DEFAULT_COLLECTION.into())]),
            items: Vec::new(),
        }
    }

    pub fn collection(&self, name: &str) -> Option<&Collection> {
        self.collections.iter().find(|c| c.name == name)
    }

    pub fn collection_mut(&mut self, name: &str) -> Option<&mut Collection> {
        self.collections.iter_mut().find(|c| c.name == name)
    }

    /// A collection's name, or the collection an alias names.
    pub fn resolve(&self, name_or_alias: &str) -> Option<String> {
        if self.collection(name_or_alias).is_some() {
            return Some(name_or_alias.to_string());
        }
        self.aliases
            .get(name_or_alias)
            .filter(|c| self.collection(c).is_some())
            .cloned()
    }

    pub fn item(&self, collection: &str, n: u64) -> Option<&Item> {
        self.items
            .iter()
            .find(|i| i.collection == collection && i.n == n)
    }

    pub fn item_mut(&mut self, collection: &str, n: u64) -> Option<&mut Item> {
        self.items
            .iter_mut()
            .find(|i| i.collection == collection && i.n == n)
    }

    /// Items of `collection` (every collection when `None`) that have every
    /// attribute asked for.
    pub fn search(&self, collection: Option<&str>, attrs: &BTreeMap<String, String>) -> Vec<&Item> {
        self.items
            .iter()
            .filter(|i| collection.is_none_or(|c| i.collection == c))
            .filter(|i| attrs.iter().all(|(k, v)| i.attributes.get(k) == Some(v)))
            .collect()
    }

    /// A new collection named after `label`; its name is free.
    pub fn add_collection(&mut self, label: &str) -> String {
        let base = path_name(label);
        let mut name = base.clone();
        let mut k = 2;
        while self.collection(&name).is_some() {
            name = format!("{base}_{k}");
            k += 1;
        }
        let t = now();
        self.collections.push(Collection {
            name: name.clone(),
            label: label.to_string(),
            created: t,
            modified: t,
            next: 1,
        });
        name
    }

    pub fn remove_collection(&mut self, name: &str) -> Vec<u64> {
        let gone: Vec<u64> = self
            .items
            .iter()
            .filter(|i| i.collection == name)
            .map(|i| i.n)
            .collect();
        self.items.retain(|i| i.collection != name);
        self.collections.retain(|c| c.name != name);
        self.aliases.retain(|_, c| c != name);
        gone
    }

    /// `CreateItem`: with `replace`, an item of the collection with exactly
    /// these attributes gets the new secret and label (spec 0.2). Answers
    /// the item's number and whether it is new.
    #[allow(clippy::too_many_arguments)]
    pub fn put(
        &mut self,
        collection: &str,
        label: &str,
        attributes: BTreeMap<String, String>,
        secret: Zeroizing<Vec<u8>>,
        content_type: &str,
        replace: bool,
        times: Option<(u64, u64)>,
    ) -> Option<(u64, bool)> {
        let t = now();
        let content_type = if content_type.is_empty() {
            "text/plain".to_string()
        } else {
            content_type.to_string()
        };
        if replace
            && let Some(i) = self
                .items
                .iter_mut()
                .find(|i| i.collection == collection && i.attributes == attributes)
        {
            i.label = label.to_string();
            i.secret = secret;
            i.content_type = content_type;
            i.modified = times.map_or(t, |x| x.1);
            let n = i.n;
            self.touch(collection);
            return Some((n, false));
        }
        let c = self.collection_mut(collection)?;
        let n = c.next;
        c.next += 1;
        let (created, modified) = times.unwrap_or((t, t));
        self.items.push(Item {
            id: new_id(),
            collection: collection.to_string(),
            n,
            label: label.to_string(),
            attributes,
            secret,
            content_type,
            created,
            modified,
        });
        self.touch(collection);
        Some((n, true))
    }

    pub fn touch(&mut self, collection: &str) {
        if let Some(c) = self.collection_mut(collection) {
            c.modified = now();
        }
    }

    pub fn remove_item(&mut self, collection: &str, n: u64) -> bool {
        let before = self.items.len();
        self.items
            .retain(|i| !(i.collection == collection && i.n == n));
        let gone = self.items.len() != before;
        if gone {
            self.touch(collection);
        }
        gone
    }

    // ── the files ─────────────────────────────────────────────────────

    fn to_json(&self) -> Value {
        let items: Vec<Value> = self
            .items
            .iter()
            .map(|i| {
                json!({
                    "id": i.id,
                    "collection": i.collection,
                    "n": i.n,
                    "label": i.label,
                    "attributes": i.attributes,
                    "secret": STANDARD.encode(&*i.secret),
                    "content_type": i.content_type,
                    "created": i.created,
                    "modified": i.modified,
                })
            })
            .collect();
        json!({
            "v": VERSION,
            "collections": collections_json(&self.collections),
            "aliases": self.aliases,
            "items": items,
        })
    }

    fn from_json(v: &Value) -> Result<Store, LoadError> {
        if v.get("v").and_then(Value::as_u64) != Some(VERSION) {
            return Err(LoadError::Corrupt("unknown version".into()));
        }
        let collections = collections_from(v.get("collections"));
        let mut store = Store {
            aliases: aliases_from(v.get("aliases")),
            collections,
            items: Vec::new(),
        };
        for i in v
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let collection = text(i, "collection");
            let n = num(i, "n");
            if store.collection(&collection).is_none()
                || n == 0
                || store.item(&collection, n).is_some()
            {
                continue;
            }
            let secret = i
                .get("secret")
                .and_then(Value::as_str)
                .and_then(|s| STANDARD.decode(s).ok())
                .map(Zeroizing::new)
                .unwrap_or_default();
            let attributes = i
                .get("attributes")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let id = Some(text(i, "id"))
                .filter(|x| !x.is_empty())
                .unwrap_or_else(new_id);
            if let Some(c) = store.collection_mut(&collection) {
                c.next = c.next.max(n + 1);
            }
            store.items.push(Item {
                id,
                collection,
                n,
                label: text(i, "label"),
                attributes,
                secret,
                content_type: Some(text(i, "content_type"))
                    .filter(|x| !x.is_empty())
                    .unwrap_or_else(|| "text/plain".into()),
                created: num(i, "created"),
                modified: num(i, "modified"),
            });
        }
        Ok(store)
    }

    /// Seal it under W and write the index beside it.
    pub fn save(&self, files: &Files, w: &SessionKey) -> Result<(), String> {
        let mut v = self.to_json();
        let mut bytes = Zeroizing::new(Vec::new());
        let made = serde_json::to_writer(&mut *bytes, &v);
        wipe(&mut v);
        made.map_err(|e| e.to_string())?;
        safe_login::seal(&files.sealed, safe_login::KIND_KEYRING, w, &bytes)
            .map_err(|e| e.to_string())?;
        self.write_index(&files.index).map_err(|e| e.to_string())
    }

    /// `keyring.safe` opened with W; a keyring that was never written is a
    /// fresh one.
    pub fn load(files: &Files, w: &SessionKey) -> Result<Store, LoadError> {
        let bytes = match safe_login::open(&files.sealed, safe_login::KIND_KEYRING, w) {
            Ok(b) => b,
            Err(safe_login::Error::Missing) => return Ok(Store::fresh()),
            Err(safe_login::Error::WrongKey) => return Err(LoadError::WrongKey),
            Err(safe_login::Error::Corrupt(why)) => return Err(LoadError::Corrupt(why)),
            Err(safe_login::Error::Io(e)) => return Err(LoadError::Io(e.to_string())),
        };
        let mut v: Value =
            serde_json::from_slice(&bytes).map_err(|_| LoadError::Corrupt("not JSON".into()))?;
        let out = Store::from_json(&v);
        wipe(&mut v);
        out
    }

    fn write_index(&self, path: &Path) -> std::io::Result<()> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).expect("the system's random source");
        let items: Vec<Value> = self
            .items
            .iter()
            .map(|i| {
                let h: Vec<String> = i
                    .attributes
                    .iter()
                    .map(|(k, v)| hash(&salt, k, v))
                    .collect();
                json!({"c": i.collection, "n": i.n, "h": h})
            })
            .collect();
        let v = json!({
            "v": VERSION,
            "kind": KIND_INDEX,
            "salt": STANDARD.encode(salt),
            "collections": collections_json(&self.collections),
            "aliases": self.aliases,
            "items": items,
        });
        safe_login::write_atomic(path, v.to_string().as_bytes())
    }
}

/// What a locked keyring serves: from `keyring.index`.
#[derive(Clone, Debug, Default)]
pub struct Index {
    pub salt: Vec<u8>,
    pub collections: Vec<Collection>,
    pub aliases: BTreeMap<String, String>,
    pub items: Vec<Stub>,
}

impl Index {
    /// The index, or nothing (no keyring yet, or a file that isn't one).
    pub fn read(path: &Path) -> Option<Index> {
        let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        if v.get("v").and_then(Value::as_u64) != Some(VERSION)
            || v.get("kind").and_then(Value::as_str) != Some(KIND_INDEX)
        {
            return None;
        }
        let salt = STANDARD.decode(v.get("salt")?.as_str()?).ok()?;
        let collections = collections_from(v.get("collections"));
        let items = v
            .get("items")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|i| {
                        let collection = text(i, "c");
                        let n = num(i, "n");
                        let hashes = i
                            .get("h")
                            .and_then(Value::as_array)
                            .map(|h| {
                                h.iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect()
                            })
                            .unwrap_or_default();
                        (n > 0 && collections.iter().any(|c| c.name == collection)).then_some(
                            Stub {
                                collection,
                                n,
                                hashes,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Index {
            salt,
            aliases: aliases_from(v.get("aliases")),
            collections,
            items,
        })
    }

    /// The items with every attribute asked for (compared by hash).
    pub fn search(&self, collection: Option<&str>, attrs: &BTreeMap<String, String>) -> Vec<&Stub> {
        let want: Vec<String> = attrs.iter().map(|(k, v)| hash(&self.salt, k, v)).collect();
        self.items
            .iter()
            .filter(|s| collection.is_none_or(|c| s.collection == c))
            .filter(|s| want.iter().all(|h| s.hashes.contains(h)))
            .collect()
    }

    /// The collections and aliases as a store with no items (locked).
    pub fn shell(&self) -> Store {
        Store {
            collections: self.collections.clone(),
            aliases: self.aliases.clone(),
            items: Vec::new(),
        }
    }
}

/// One item from another keyring (an import).
#[derive(Clone)]
pub struct Incoming {
    /// The collection it goes to here (`login`, or a name made from the
    /// other keyring's collection).
    pub collection: String,
    pub collection_label: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Merged {
    pub added: usize,
    pub updated: usize,
    /// Copies left out: the same attributes in the same collection (here
    /// or twice in the import); the newest is kept.
    pub duplicates: usize,
    pub collections_added: usize,
}

impl Store {
    /// Add an import: per collection, items with the same (non-empty)
    /// attributes are one item, and the newest wins.
    pub fn merge(&mut self, incoming: Vec<Incoming>) -> Merged {
        let mut out = Merged::default();
        // the newest of each (collection, attributes) in the import itself
        let mut keep: Vec<Incoming> = Vec::new();
        for i in incoming {
            if i.attributes.is_empty() {
                keep.push(i);
                continue;
            }
            match keep
                .iter_mut()
                .find(|k| k.collection == i.collection && k.attributes == i.attributes)
            {
                Some(k) => {
                    out.duplicates += 1;
                    if i.modified > k.modified {
                        *k = i;
                    }
                }
                None => keep.push(i),
            }
        }
        for i in keep {
            if self.collection(&i.collection).is_none() {
                let t = now();
                self.collections.push(Collection {
                    name: i.collection.clone(),
                    label: i.collection_label.clone(),
                    created: t,
                    modified: t,
                    next: 1,
                });
                out.collections_added += 1;
            }
            let existing = (!i.attributes.is_empty())
                .then(|| {
                    self.items
                        .iter_mut()
                        .find(|x| x.collection == i.collection && x.attributes == i.attributes)
                })
                .flatten();
            match existing {
                Some(x) => {
                    out.duplicates += 1;
                    if i.modified > x.modified {
                        x.label = i.label;
                        x.secret = i.secret;
                        x.content_type = i.content_type;
                        x.modified = i.modified;
                        out.updated += 1;
                    }
                }
                None => {
                    let created = i.created;
                    let modified = i.modified.max(created);
                    self.put(
                        &i.collection,
                        &i.label,
                        i.attributes,
                        i.secret,
                        &i.content_type,
                        false,
                        Some((created, modified)),
                    );
                    out.added += 1;
                }
            }
        }
        out
    }
}

/// The app an item belongs to, for `keyring list`: libsecret's
/// `application` (Chromium, Electron), else `service` (ewe's tools:
/// ewe-cloud, ewe-companion…), else the schema.
pub fn app_of(attrs: &BTreeMap<String, String>) -> String {
    ["application", "service", "xdg:schema"]
        .iter()
        .find_map(|k| attrs.get(*k).filter(|v| !v.is_empty()).cloned())
        .unwrap_or_default()
}

/// For tests and `keyring list`: unix seconds as `2026-10-14T16:02:11Z`.
pub fn iso(t: u64) -> Option<String> {
    if t == 0 {
        return None;
    }
    let days = (t / 86400) as i64;
    let secs = t % 86400;
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    ))
}

pub fn attrs_from(m: &Map<String, Value>) -> BTreeMap<String, String> {
    m.iter()
        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(d: &tempfile::TempDir) -> Files {
        Files {
            sealed: d.path().join("keyring.safe"),
            index: d.path().join("keyring.index"),
        }
    }

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn secret(s: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    #[test]
    fn a_store_round_trips_sealed_and_its_paths_stay() {
        let d = tempfile::tempdir().unwrap();
        let f = files(&d);
        let w = SessionKey::generate();
        let mut s = Store::fresh();
        let a = attrs(&[("service", "ewe-cloud"), ("user", "sam")]);
        let (n1, new) = s
            .put(
                "login",
                "ewe cloud",
                a.clone(),
                secret("pw1"),
                "",
                true,
                None,
            )
            .unwrap();
        assert!(new && n1 == 1);
        let (n2, _) = s
            .put(
                "login",
                "other",
                attrs(&[("x", "y")]),
                secret("pw2"),
                "",
                true,
                None,
            )
            .unwrap();
        assert!(s.remove_item("login", n1));
        s.save(&f, &w).unwrap();
        let back = Store::load(&f, &w).unwrap();
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.items[0].n, n2);
        assert_eq!(&back.items[0].secret[..], b"pw2");
        assert_eq!(back.resolve("default").as_deref(), Some("login"));
        // a number is never handed out twice
        let mut back = back;
        let (n3, _) = back
            .put("login", "z", attrs(&[]), secret("3"), "", false, None)
            .unwrap();
        assert_eq!(n3, 3);
        assert!(matches!(
            Store::load(&f, &SessionKey::generate()),
            Err(LoadError::WrongKey)
        ));
        // the index holds no label, no value and no secret
        let index = std::fs::read_to_string(&f.index).unwrap();
        for word in ["other", "pw2", "\"y\"", "ewe cloud"] {
            assert!(!index.contains(word), "{word} in the index");
        }
    }

    #[test]
    fn replace_takes_the_item_with_the_same_attributes() {
        let mut s = Store::fresh();
        let a = attrs(&[("service", "s"), ("user", "u")]);
        let (n, _) = s
            .put("login", "one", a.clone(), secret("1"), "", true, None)
            .unwrap();
        let (m, new) = s
            .put("login", "two", a.clone(), secret("2"), "", true, None)
            .unwrap();
        assert_eq!((m, new), (n, false));
        assert_eq!(s.items.len(), 1);
        assert_eq!(&s.items[0].secret[..], b"2");
        // without replace, a second item
        let (k, new) = s
            .put("login", "three", a, secret("3"), "", false, None)
            .unwrap();
        assert!(new && k != n);
    }

    #[test]
    fn a_locked_search_finds_the_same_items_by_hash() {
        let d = tempfile::tempdir().unwrap();
        let f = files(&d);
        let w = SessionKey::generate();
        let mut s = Store::fresh();
        let a = attrs(&[("service", "ewe-cloud"), ("user", "sam")]);
        s.put("login", "l", a.clone(), secret("p"), "", true, None)
            .unwrap();
        s.put(
            "login",
            "m",
            attrs(&[("service", "mail")]),
            secret("q"),
            "",
            true,
            None,
        )
        .unwrap();
        s.save(&f, &w).unwrap();
        let idx = Index::read(&f.index).unwrap();
        let hits = idx.search(None, &attrs(&[("service", "ewe-cloud")]));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].n, 1);
        assert_eq!(idx.search(None, &attrs(&[])).len(), 2);
        assert!(idx.search(None, &attrs(&[("service", "nope")])).is_empty());
        assert_eq!(idx.shell().resolve("default").as_deref(), Some("login"));
    }

    #[test]
    fn a_merge_keeps_the_newest_of_the_same_attributes() {
        let mut s = Store::fresh();
        let a = attrs(&[("service", "ewe-cloud")]);
        s.put(
            "login",
            "old",
            a.clone(),
            secret("old"),
            "",
            true,
            Some((10, 10)),
        )
        .unwrap();
        let inc = |label: &str, sec: &str, t: u64, coll: &str| Incoming {
            collection: coll.into(),
            collection_label: coll.into(),
            label: label.into(),
            attributes: a.clone(),
            secret: secret(sec),
            content_type: "text/plain".into(),
            created: t,
            modified: t,
        };
        let r = s.merge(vec![
            inc("a", "mid", 20, "login"),
            inc("b", "new", 30, "login"),
            inc("c", "work", 5, "work"),
        ]);
        assert_eq!(r.duplicates, 2);
        assert_eq!(r.updated, 1);
        assert_eq!(r.added, 1);
        assert_eq!(r.collections_added, 1);
        let login: Vec<_> = s.search(Some("login"), &a);
        assert_eq!(login.len(), 1);
        assert_eq!(&login[0].secret[..], b"new");
        assert_eq!(s.search(Some("work"), &a).len(), 1);
        // an older copy changes nothing
        let r = s.merge(vec![inc("d", "older", 1, "login")]);
        assert_eq!((r.duplicates, r.updated), (1, 0));
    }

    #[test]
    fn names_and_times_read_well() {
        assert_eq!(path_name("Default keyring"), "default_keyring");
        assert_eq!(path_name("!!"), "collection");
        assert_eq!(iso(0), None);
        assert_eq!(iso(1_760_457_731).as_deref(), Some("2025-10-14T16:02:11Z"));
        let id = new_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert_eq!(app_of(&attrs(&[("service", "ewe-cloud")])), "ewe-cloud");
        assert_eq!(
            app_of(&attrs(&[("application", "chrome"), ("service", "x")])),
            "chrome"
        );
    }
}
