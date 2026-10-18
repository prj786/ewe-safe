//! Talking to the Secret Service that runs now (gnome-keyring, KWallet's
//! bridge, KeePassXC, or Safe itself) through its own API: `keyring
//! import`, `keyring list`, `keyring repair` and the carrier.
//!
//! One connection for everything, the session opened first: gnome-keyring
//! keys its per-client state on the connection, and a property read from
//! a connection with no session aborted it (ewe's ewe-cloud notes,
//! 2026-09-08). Only [`Remote::unlock`] may show a prompt (the other
//! keyring's own window); nothing else here ever calls `Unlock`.
//! Nothing here logs a label or a secret.

use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::channel;
use std::time::Duration;

use zbus::blocking::{Connection, Proxy};
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use crate::service::{
    ATTRIBUTES_PROP, COLLECTION_IFACE, ITEM_IFACE, LABEL_PROP, NAME, NO_PROMPT, PROMPT_IFACE,
    SERVICE_IFACE, SERVICE_PATH, Secret,
};

/// `/org/freedesktop/secrets/collection/login`: the keyring PAM unlocks.
pub const LOGIN_PATH: &str = "/org/freedesktop/secrets/collection/login";
const SESSION_IFACE: &str = "org.freedesktop.Secret.Session";

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The last part of an object path (`login`, `Default_5fkeyring`…).
pub fn tail(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

/// A collection's name as its file has it: gnome-keyring escapes every
/// byte but letters and digits as `_XX` in object paths (GLib's
/// `g_dbus_escape_object_path`), so `Default_5fkeyring` is
/// `Default_keyring.keyring`. An `_` not followed by two hex digits stays.
pub fn unescape(name: &str) -> String {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'_'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
            && let Ok(x) = u8::from_str_radix(&name[i + 1..i + 3], 16)
        {
            out.push(x);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A collection's name from its path, unescaped (for people and files).
pub fn name_of(path: &str) -> String {
    unescape(&tail(path))
}

/// Who owns `org.freedesktop.secrets` now: its unique name and its pid.
/// Never starts a keyring (no method call goes to the name).
pub fn owner(conn: &Connection) -> Option<(String, Option<u32>)> {
    let dbus = zbus::blocking::fdo::DBusProxy::new(conn).ok()?;
    let name = zbus::names::BusName::try_from(NAME).ok()?;
    let unique = dbus.get_name_owner(name).ok()?;
    let pid = dbus
        .get_connection_unix_process_id(zbus::names::BusName::from(unique.clone()))
        .ok();
    Some((unique.to_string(), pid))
}

/// Item → (secret, content type).
pub type Secrets = HashMap<OwnedObjectPath, (Zeroizing<Vec<u8>>, String)>;

/// An item's description (never its secret).
#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub created: u64,
    pub modified: u64,
}

/// The running keyring, through one connection with a `plain` session
/// (closed when dropped).
pub struct Remote<'c> {
    conn: &'c Connection,
    session: OwnedObjectPath,
}

impl<'c> Remote<'c> {
    /// A session with whoever owns the name. With `start`, a keyring that
    /// isn't running is started by the bus (D-Bus activation).
    pub fn open(conn: &'c Connection, start: bool) -> Result<Remote<'c>, String> {
        if !start && owner(conn).is_none() {
            return Err("no keyring runs now".into());
        }
        let svc = proxy(conn, SERVICE_PATH, SERVICE_IFACE)?;
        let (_, session): (OwnedValue, OwnedObjectPath) = svc
            .call("OpenSession", &(crate::crypto::PLAIN, Value::from("")))
            .map_err(err)?;
        Ok(Remote { conn, session })
    }

    fn proxy(&self, path: &str, iface: &'static str) -> Result<Proxy<'static>, String> {
        proxy(self.conn, path, iface)
    }

    fn svc(&self) -> Result<Proxy<'static>, String> {
        self.proxy(SERVICE_PATH, SERVICE_IFACE)
    }

    pub fn collections(&self) -> Result<Vec<OwnedObjectPath>, String> {
        self.svc()?.get_property("Collections").map_err(err)
    }

    /// The collection an alias names, if any.
    pub fn alias(&self, name: &str) -> Result<Option<OwnedObjectPath>, String> {
        let p: OwnedObjectPath = self.svc()?.call("ReadAlias", &(name,)).map_err(err)?;
        Ok((p.as_str() != NO_PROMPT).then_some(p))
    }

    pub fn set_alias(&self, name: &str, collection: &str) -> Result<(), String> {
        let c = OwnedObjectPath::try_from(collection.to_string()).map_err(err)?;
        let () = self.svc()?.call("SetAlias", &(name, c)).map_err(err)?;
        Ok(())
    }

    pub fn locked(&self, collection: &str) -> Result<bool, String> {
        self.proxy(collection, COLLECTION_IFACE)?
            .get_property("Locked")
            .map_err(err)
    }

    pub fn label(&self, collection: &str) -> String {
        self.proxy(collection, COLLECTION_IFACE)
            .and_then(|p| p.get_property::<String>("Label").map_err(err))
            .unwrap_or_default()
    }

    pub fn items(&self, collection: &str) -> Result<Vec<OwnedObjectPath>, String> {
        self.proxy(collection, COLLECTION_IFACE)?
            .get_property("Items")
            .map_err(err)
    }

    /// Items of one collection with exactly these attributes among theirs.
    pub fn search(
        &self,
        collection: &str,
        attrs: &HashMap<&str, &str>,
    ) -> Result<Vec<OwnedObjectPath>, String> {
        self.proxy(collection, COLLECTION_IFACE)?
            .call("SearchItems", &(attrs,))
            .map_err(err)
    }

    pub fn meta(&self, item: &str) -> Meta {
        let Ok(i) = self.proxy(item, ITEM_IFACE) else {
            return Meta::default();
        };
        let attributes: HashMap<String, String> = i.get_property("Attributes").unwrap_or_default();
        Meta {
            label: i.get_property("Label").unwrap_or_default(),
            attributes: attributes.into_iter().collect(),
            created: i.get_property("Created").unwrap_or(0),
            modified: i.get_property("Modified").unwrap_or(0),
        }
    }

    /// The secrets of unlocked items (locked ones are left out).
    pub fn secrets(&self, items: &[OwnedObjectPath]) -> Result<Secrets, String> {
        if items.is_empty() {
            return Ok(HashMap::new());
        }
        let got: HashMap<OwnedObjectPath, Secret> = self
            .svc()?
            .call("GetSecrets", &(items.to_vec(), &self.session))
            .map_err(err)?;
        Ok(got
            .into_iter()
            .map(|(p, s)| (p, (Zeroizing::new(s.value.clone()), s.content_type.clone())))
            .collect())
    }

    /// A new item (or, with `replace`, the one with the same attributes)
    /// in an unlocked collection. A locked one answers with a prompt: that
    /// is an error here, never shown.
    pub fn create(
        &self,
        collection: &str,
        label: &str,
        attrs: &BTreeMap<String, String>,
        secret: &[u8],
        content_type: &str,
        replace: bool,
    ) -> Result<OwnedObjectPath, String> {
        let attrs: HashMap<&str, &str> = attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut props: HashMap<&str, Value<'_>> = HashMap::new();
        props.insert(LABEL_PROP, Value::from(label));
        props.insert(ATTRIBUTES_PROP, Value::from(attrs));
        let s = Secret {
            session: self.session.clone(),
            parameters: Vec::new(),
            value: secret.to_vec(),
            content_type: content_type.to_string(),
        };
        let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = self
            .proxy(collection, COLLECTION_IFACE)?
            .call("CreateItem", &(props, s, replace))
            .map_err(err)?;
        if prompt.as_str() != NO_PROMPT || item.as_str() == NO_PROMPT {
            if prompt.as_str() != NO_PROMPT
                && let Ok(p) = self.proxy(prompt.as_str(), PROMPT_IFACE)
            {
                let _ = p.call_method("Dismiss", &());
            }
            return Err("the collection is locked".into());
        }
        Ok(item)
    }

    /// Delete an item of an unlocked collection; never shows a prompt.
    pub fn delete(&self, item: &str) -> Result<(), String> {
        let prompt: OwnedObjectPath = self
            .proxy(item, ITEM_IFACE)?
            .call("Delete", &())
            .map_err(err)?;
        if prompt.as_str() != NO_PROMPT {
            if let Ok(p) = self.proxy(prompt.as_str(), PROMPT_IFACE) {
                let _ = p.call_method("Dismiss", &());
            }
            return Err("the collection is locked".into());
        }
        Ok(())
    }

    /// Unlock one collection; the other keyring may show its own window
    /// (waiting up to `wait`). `true` when it is open.
    pub fn unlock(&self, collection: &str, wait: Duration) -> Result<bool, String> {
        let path = OwnedObjectPath::try_from(collection.to_string()).map_err(err)?;
        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = self
            .svc()?
            .call("Unlock", &(vec![path.clone()],))
            .map_err(err)?;
        if unlocked.contains(&path) {
            return Ok(true);
        }
        if prompt.as_str() == NO_PROMPT {
            return Ok(!self.locked(collection)?);
        }
        let p = self.proxy(prompt.as_str(), PROMPT_IFACE)?;
        // listen before asking: Completed may come at once
        let mut completed = p.receive_signal("Completed").map_err(err)?;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            if let Some(m) = completed.next() {
                let dismissed = m
                    .body()
                    .deserialize::<(bool, OwnedValue)>()
                    .map(|(d, _)| d)
                    .unwrap_or(true);
                let _ = tx.send(dismissed);
            }
        });
        p.call_method("Prompt", &("",)).map_err(err)?;
        let answered = match rx.recv_timeout(wait) {
            Ok(dismissed) => !dismissed,
            Err(_) => {
                let _ = p.call_method("Dismiss", &());
                false
            }
        };
        Ok(answered && !self.locked(collection).unwrap_or(true))
    }
}

impl Drop for Remote<'_> {
    fn drop(&mut self) {
        if let Ok(s) = proxy(self.conn, self.session.as_str(), SESSION_IFACE) {
            let _ = s.call_method("Close", &());
        }
    }
}

fn proxy(conn: &Connection, path: &str, iface: &'static str) -> Result<Proxy<'static>, String> {
    zbus::blocking::proxy::Builder::new(conn)
        .destination(NAME)
        .and_then(|b| b.path(path.to_string()))
        .and_then(|b| b.interface(iface))
        .map(|b| b.cache_properties(CacheProperties::No))
        .and_then(|b| b.build())
        .map_err(err)
}

// ── reading everything (import) ─────────────────────────────────────────

pub struct Read {
    pub collections: Vec<ReadCollection>,
    /// Collections left locked (their prompt was dismissed or not answered).
    pub locked: usize,
    /// Items not read: in a locked collection, in the temporary `session`
    /// collection, or with no secret given.
    pub skipped: usize,
}

pub struct ReadCollection {
    /// The last part of its path (`login`, `Default_keyring`…).
    pub name: String,
    pub path: String,
    pub label: String,
    /// The collection the `default` alias names.
    pub default: bool,
    pub items: Vec<ReadItem>,
}

pub struct ReadItem {
    pub path: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

/// One collection, secrets included; `None` when it stays locked.
pub fn read_collection(
    r: &Remote<'_>,
    path: &str,
    wait: Duration,
) -> Result<Option<Vec<ReadItem>>, String> {
    if r.locked(path)? && !r.unlock(path, wait)? {
        return Ok(None);
    }
    let items = r.items(path)?;
    let mut secrets = r.secrets(&items)?;
    let mut out = Vec::new();
    for item in items {
        let Some((secret, content_type)) = secrets.remove(&item) else {
            continue;
        };
        let m = r.meta(item.as_str());
        out.push(ReadItem {
            path: item.to_string(),
            label: m.label,
            attributes: m.attributes,
            secret,
            content_type,
            created: m.created,
            modified: m.modified,
        });
    }
    Ok(Some(out))
}

/// Every collection and item the owner of `org.freedesktop.secrets` has,
/// secrets included. Each locked collection is unlocked first (its own
/// prompt, waiting up to `wait`).
pub fn read_all(conn: &Connection, wait: Duration) -> Result<Read, String> {
    let r = Remote::open(conn, true)?;
    let default = r.alias("default")?;
    let mut read = Read {
        collections: Vec::new(),
        locked: 0,
        skipped: 0,
    };
    for path in r.collections()? {
        let name = name_of(path.as_str());
        let count = r.items(path.as_str()).map(|i| i.len()).unwrap_or(0);
        // gnome-keyring's in-memory collection: gone at logout by design
        if tail(path.as_str()) == "session" {
            read.skipped += count;
            continue;
        }
        match read_collection(&r, path.as_str(), wait)? {
            None => {
                read.locked += 1;
                read.skipped += count;
            }
            Some(items) => {
                read.skipped += count.saturating_sub(items.len());
                read.collections.push(ReadCollection {
                    default: default.as_ref() == Some(&path),
                    label: r.label(path.as_str()),
                    path: path.to_string(),
                    name,
                    items,
                });
            }
        }
    }
    Ok(read)
}

// ── listing without secrets and without prompts (keyring list) ──────────

pub struct Listed {
    pub path: String,
    pub collection: String,
    pub meta: Meta,
}

pub struct LockedCollection {
    pub name: String,
    pub label: String,
    pub items: usize,
}

/// The items of every unlocked collection (no secrets), and which
/// collections are locked. Never unlocks anything, never starts a keyring.
pub fn list(conn: &Connection) -> Result<(Vec<Listed>, Vec<LockedCollection>), String> {
    let r = Remote::open(conn, false)?;
    let (mut items, mut locked) = (Vec::new(), Vec::new());
    for path in r.collections()? {
        let name = name_of(path.as_str());
        if tail(path.as_str()) == "session" {
            continue;
        }
        let these = r.items(path.as_str()).unwrap_or_default();
        if r.locked(path.as_str()).unwrap_or(true) {
            locked.push(LockedCollection {
                label: r.label(path.as_str()),
                name,
                items: these.len(),
            });
            continue;
        }
        for i in these {
            items.push(Listed {
                meta: r.meta(i.as_str()),
                path: i.to_string(),
                collection: name.clone(),
            });
        }
    }
    Ok((items, locked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnome_keyring_names_are_unescaped() {
        assert_eq!(unescape("Default_5fkeyring"), "Default_keyring");
        assert_eq!(unescape("login"), "login");
        assert_eq!(unescape("my_20keys_21"), "my keys!");
        // an underscore that isn't an escape stays (Safe's own names)
        assert_eq!(unescape("default_keyring"), "default_keyring");
        assert_eq!(unescape("a_"), "a_");
        assert_eq!(
            name_of("/org/freedesktop/secrets/collection/Default_5fkeyring"),
            "Default_keyring"
        );
    }
}
