//! What the store tests share: a mock WebDAV server, switchable
//! credentials (a machine going offline), cheap keys and small safes.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use keepass::DatabaseKey;
use keepass::config::KdfConfig;
use safe_core::{Draft, Kind, Safe};
use safe_store::{Credentials, Error, Login, Syncer, WebDav};
pub use safe_testkit::*;
use zeroize::Zeroizing;

/// Credentials whose server can be switched off: a machine going offline.
#[derive(Clone)]
pub struct Switch {
    base: Arc<Mutex<String>>,
    online: String,
    password: Arc<Mutex<String>>,
}

impl Switch {
    pub fn new(base: &str) -> Switch {
        Switch {
            base: Arc::new(Mutex::new(base.to_string())),
            online: base.to_string(),
            password: Arc::new(Mutex::new(PASS.to_string())),
        }
    }

    pub fn offline(&self) {
        *self.base.lock().unwrap() = format!("http://127.0.0.1:{}{ROOT}", dead_port());
    }

    pub fn online(&self) {
        *self.base.lock().unwrap() = self.online.clone();
    }

    pub fn set_password(&self, p: &str) {
        *self.password.lock().unwrap() = p.to_string();
    }
}

impl Credentials for Switch {
    fn base(&self) -> Result<String, Error> {
        Ok(self.base.lock().unwrap().clone())
    }

    fn login(&self) -> Result<Login, Error> {
        Ok(Login {
            user: USER.to_string(),
            password: Zeroizing::new(self.password.lock().unwrap().clone()),
        })
    }
}

pub fn place(creds: &Switch) -> Box<WebDav> {
    Box::new(
        WebDav::new(
            "nextcloud",
            "ewe/safe/passwords.kdbx",
            Box::new(creds.clone()),
        )
        .insecure_loopback(true),
    )
}

/// A fresh scratch directory for one test.
pub fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("safe-store-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

pub fn cheap() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

pub fn key() -> DatabaseKey {
    safe_core::safe::key("correct horse battery", None).expect("key")
}

pub fn other_key() -> DatabaseKey {
    safe_core::safe::key("a new master password", None).expect("key")
}

pub fn new_safe() -> Safe {
    Safe::create("Sam's safe", cheap())
}

pub fn login(title: &str, username: &str) -> Draft {
    Draft {
        kind: Kind::Login,
        title: title.into(),
        username: username.into(),
        password: Zeroizing::new(format!("pw-{title}")),
        websites: vec![format!("https://{}.example", title.to_lowercase())],
        ..Draft::default()
    }
}

/// Titles of the items outside the recycle bin, sorted.
pub fn titles(s: &Safe) -> Vec<String> {
    let mut t: Vec<String> = s.items().into_iter().map(|i| i.title).collect();
    t.sort();
    t
}

pub fn id_of(s: &Safe, title: &str) -> String {
    s.items()
        .into_iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
        .id
}

pub fn username_of(s: &Safe, title: &str) -> String {
    s.items()
        .into_iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
        .username
}

/// Every username an item has had: now and in its history.
pub fn usernames_ever(s: &Safe, title: &str) -> Vec<String> {
    let db = s.database();
    let mut out = Vec::new();
    for e in db.iter_all_entries() {
        if e.get_title() != Some(title) {
            continue;
        }
        out.push(e.get_username().unwrap_or("").to_string());
        if let Some(h) = &e.history {
            for v in h.get_entries() {
                out.push(v.get_username().unwrap_or("").to_string());
            }
        }
    }
    out
}

/// A machine: its own state directory, credentials and syncer.
pub struct Machine {
    pub creds: Switch,
    pub sync: Syncer,
    pub dir: PathBuf,
}

pub fn machine(mock: &Mock, dir: PathBuf, name: &str) -> Machine {
    let creds = Switch::new(&mock.base());
    let sync = Syncer::new(place(&creds), &dir, name).expect("syncer");
    Machine { creds, sync, dir }
}

/// The error a load gives (a `Safe` has no `Debug`, on purpose).
pub fn load_err(sync: &mut Syncer, key: &DatabaseKey) -> Error {
    match sync.load(key) {
        Ok(_) => panic!("the load succeeded"),
        Err(e) => e,
    }
}
