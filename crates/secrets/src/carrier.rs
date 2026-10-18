//! The carrier: W kept in the keyring PAM already unlocks at login
//! (gnome-keyring's `login` collection), so Safe can open at login with no
//! PAM code of its own (docs/KEYRING.md). One item per computer:
//!
//! - label "Safe — unlock key for this computer";
//! - attributes `{"application": "ewe-safe", "ewe-safe": "session-key",
//!   "machine": <machine id>}`;
//! - the secret: W's 32 bytes, `application/octet-stream`.
//!
//! None of these ever shows a prompt or starts a keyring: a locked `login`
//! (or none running) is `None` / an error. Nothing here logs W.

use std::collections::{BTreeMap, HashMap};

use safe_login::SessionKey;
use zbus::blocking::Connection;

use crate::client::{LOGIN_PATH, Remote};

pub const LABEL: &str = "Safe — unlock key for this computer";
const CONTENT_TYPE: &str = "application/octet-stream";

fn attrs(machine: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("application".to_string(), "ewe-safe".to_string()),
        ("ewe-safe".to_string(), "session-key".to_string()),
        ("machine".to_string(), machine.to_string()),
    ])
}

/// The session bus; a keyring that hangs answers nothing within 10 s.
fn session() -> Result<Connection, String> {
    zbus::blocking::connection::Builder::session()
        .map(|b| b.method_timeout(std::time::Duration::from_secs(10)))
        .and_then(|b| b.build())
        .map_err(|e| e.to_string())
}

/// `login`, open, through a session with the keyring that runs.
fn login(conn: &Connection) -> Result<Remote<'_>, String> {
    let r = Remote::open(conn, false)?;
    if r.locked(LOGIN_PATH)? {
        return Err("the login keyring is locked".into());
    }
    Ok(r)
}

fn found(r: &Remote<'_>, machine: &str) -> Result<Vec<zbus::zvariant::OwnedObjectPath>, String> {
    let a = attrs(machine);
    let q: HashMap<&str, &str> = a.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    r.search(LOGIN_PATH, &q)
}

/// Make (or replace) this computer's carrier item in `login`.
pub fn store_on(conn: &Connection, w: &SessionKey, machine: &str) -> Result<(), String> {
    let r = login(conn)?;
    r.create(
        LOGIN_PATH,
        LABEL,
        &attrs(machine),
        w.as_bytes(),
        CONTENT_TYPE,
        true,
    )
    .map(|_| ())
}

/// W from this computer's carrier item, if `login` is open and has it.
/// Never prompts: no `Unlock` call.
pub fn fetch_on(conn: &Connection, machine: &str) -> Option<SessionKey> {
    let r = login(conn).ok()?;
    let items = found(&r, machine).ok()?;
    let got = r.secrets(&items).ok()?;
    items
        .iter()
        .find_map(|p| got.get(p))
        .and_then(|(s, _)| SessionKey::from_bytes(s))
}

/// Remove this computer's carrier item(s): `Ok(true)` when one was there.
pub fn delete_on(conn: &Connection, machine: &str) -> Result<bool, String> {
    let r = login(conn)?;
    let items = found(&r, machine)?;
    for p in &items {
        r.delete(p.as_str())?;
    }
    Ok(!items.is_empty())
}

/// [`store_on`] over the session bus.
pub fn carrier_store(w: &SessionKey, machine: &str) -> Result<(), String> {
    store_on(&session()?, w, machine)
}

/// [`fetch_on`] over the session bus.
pub fn carrier_fetch(machine: &str) -> Option<SessionKey> {
    fetch_on(&session().ok()?, machine)
}

/// [`delete_on`] over the session bus.
pub fn carrier_delete(machine: &str) -> Result<bool, String> {
    delete_on(&session()?, machine)
}
