//! One safe: a KDBX file opened, read, edited and written (PLAN.md §5).
//!
//! - [`Safe::open`] parses the file and, in parallel, runs the write guard
//!   on its XML (docs/SPIKE-0.md, C1); each derives the key once.
//! - Every edit is history-tracked, oldest version first as a KeePass file
//!   lists them. [`Safe::trash`] moves an item to the recycle bin; only
//!   [`Safe::purge`] and [`Safe::empty_bin`] delete, and they record each
//!   deletion in `DeletedObjects` so a merge never brings it back (C3).
//! - [`Safe::merge`] takes in another copy of the safe ([`crate::merge`]).
//! - [`Safe::to_bytes`] writes KDBX 4.1, reads the bytes back with the same
//!   key and compares their content with what is in memory before handing
//!   them out ([`crate::digest`]).

use std::path::Path;

use keepass::config::{
    CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig,
};
use keepass::db::{CustomDataItem, CustomDataValue, EntryId, GroupId, History, Times, fields};
use keepass::{Database, DatabaseKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::digest::{self, Digester};
use crate::guard::{self, Report};
use crate::import::{self, Batch, Imported};
use crate::item::{self, Draft, Field, Summary};
use crate::otp::Totp;
use crate::{atomic, kdf, merge, search};

// passkeys on items (set, add, remove, read): crate::passkey has the format
mod passkeys;

pub const GENERATOR: &str = "ewe-safe";
pub const RECYCLE_BIN: &str = "Recycle Bin";
/// KeePassXC's default when a file names none.
pub const HISTORY_MAX_ITEMS: usize = 10;
/// The recycle bin's icon in KeePass's built-in set.
const RECYCLE_BIN_ICON: usize = 43;
/// Meta custom data naming the machine that wrote a copy (ewe-sync's "last
/// saved by"); merge keeps the newer stamp.
pub const SAVED_BY_KEY: &str = "ewe.saved-by";

#[derive(Debug)]
pub enum Error {
    /// Wrong password or key file, or not a KeePass file.
    Open(String),
    /// Writing would lose content keepass-rs does not model (the guard's reasons).
    ReadOnly(Vec<String>),
    NotFound(String),
    Save(String),
    /// The written bytes did not read back as the same safe.
    Verify(String),
    Merge(String),
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Open(e) => write!(f, "cannot open the safe: {e}"),
            Error::ReadOnly(why) => write!(f, "read-only: Safe would lose {}", why.join("; ")),
            Error::NotFound(id) => write!(f, "no item {id}"),
            Error::Save(e) => write!(f, "cannot write the safe: {e}"),
            Error::Verify(e) => write!(f, "the written safe did not read back: {e}"),
            Error::Merge(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// The composite key: the master password, plus a key file's bytes if any.
pub fn key(password: &str, keyfile: Option<&[u8]>) -> std::io::Result<DatabaseKey> {
    let mut key = DatabaseKey::new().with_password(password);
    if let Some(mut bytes) = keyfile {
        key = key.with_keyfile(&mut bytes)?;
    }
    Ok(key)
}

fn version_label(v: &DatabaseVersion) -> String {
    match v {
        DatabaseVersion::KDB(_) => "KeePass 1 (kdb)".to_string(),
        DatabaseVersion::KDB2(m) => format!("KDBX 2.{m}"),
        DatabaseVersion::KDB3(m) => format!("KDBX 3.{m}"),
        DatabaseVersion::KDB4(m) => format!("KDBX 4.{m}"),
    }
}

fn entry_id(id: &str) -> Result<EntryId, Error> {
    Uuid::parse_str(id)
        .map(EntryId::from)
        .map_err(|_| Error::NotFound(id.to_string()))
}

/// Cloning copies the whole database, secrets included; the daemon clones
/// to talk to a place without holding up readers.
#[derive(Clone)]
pub struct Safe {
    db: Database,
    guard: Report,
    /// The version the file had when opened; None for a safe made here.
    opened_as: Option<DatabaseVersion>,
    /// The key derivation a KDBX 3 file gets when it is upgraded; None =
    /// calibrate at that moment.
    upgrade_kdf: Option<KdfConfig>,
}

impl Safe {
    /// A new, empty safe: KDBX 4.1, AES-256, ChaCha20 inner stream, gzip,
    /// and the given key derivation ([`kdf::argon2id`]).
    pub fn create(name: &str, kdf: KdfConfig) -> Safe {
        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB4(1);
        db.config.outer_cipher_config = OuterCipherConfig::AES256;
        db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        db.config.compression_config = CompressionConfig::GZip;
        db.config.kdf_config = kdf;
        db.meta.generator = Some(GENERATOR.to_string());
        db.meta.database_name = Some(name.to_string());
        db.meta.database_name_changed = Some(Times::now());
        db.meta.recyclebin_enabled = Some(true);
        db.meta.history_max_items = Some(HISTORY_MAX_ITEMS as isize);
        db.root_mut().name = name.to_string();
        Safe {
            db,
            guard: Report::default(),
            opened_as: None,
            upgrade_kdf: None,
        }
    }

    /// Open a KDBX file's bytes. A file keepass-rs cannot write back without
    /// loss still opens, read-only ([`Safe::writable`]).
    pub fn open(bytes: &[u8], key: &DatabaseKey) -> Result<Safe, Error> {
        let (parsed, scanned) = std::thread::scope(|s| {
            let scan = s.spawn(|| Database::get_xml(&mut &bytes[..], key.clone()));
            (Database::parse(bytes, key.clone()), scan.join())
        });
        let db = parsed.map_err(|e| Error::Open(e.to_string()))?;
        let guard = match scanned {
            Ok(Ok(xml)) => guard::scan(&xml),
            Ok(Err(e)) => Report {
                unsupported: vec![format!("content Safe cannot check ({e})")],
                ..Report::default()
            },
            Err(_) => Report {
                unsupported: vec!["content Safe cannot check (the check failed)".to_string()],
                ..Report::default()
            },
        };
        Ok(Safe {
            opened_as: Some(db.config.version.clone()),
            db,
            guard,
            upgrade_kdf: None,
        })
    }

    pub fn open_file(path: &Path, key: &DatabaseKey) -> Result<Safe, Error> {
        Safe::open(&std::fs::read(path)?, key)
    }

    /// Use this key derivation if a KDBX 3 file is upgraded on write,
    /// instead of calibrating then.
    pub fn set_upgrade_kdf(&mut self, kdf: KdfConfig) {
        self.upgrade_kdf = Some(kdf);
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    /// For the item kinds kept in their own modules (`ssh`).
    pub(crate) fn db_mut(&mut self) -> &mut Database {
        &mut self.db
    }

    /// `Meta/HistoryMaxItems`, KeePassXC's 10 when unset.
    pub(crate) fn history_max(&self) -> usize {
        self.db
            .meta
            .history_max_items
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(HISTORY_MAX_ITEMS)
    }

    pub(crate) fn in_bin(&self, group: GroupId) -> bool {
        self.in_recycle_bin(group)
    }

    pub fn guard(&self) -> &Report {
        &self.guard
    }

    /// The machine that last saved this copy, if one stamped it.
    pub fn saved_by(&self) -> Option<String> {
        self.db
            .meta
            .custom_data
            .get(SAVED_BY_KEY)
            .and_then(|i| i.value.as_ref())
            .map(item::custom_text)
    }

    /// Stamp this machine as the copy's writer, before a save.
    pub fn set_saved_by(&mut self, machine: &str) {
        self.db.meta.custom_data.insert(
            SAVED_BY_KEY.to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String(machine.to_string())),
                last_modification_time: Some(Times::now()),
            },
        );
    }

    /// The newest change this copy knows of: an item or folder changed or
    /// moved, or a deletion recorded. A copy whose newest change is older
    /// than one already seen is a rollback (PLAN.md §7).
    pub fn newest_change(&self) -> Option<chrono::NaiveDateTime> {
        let entries = self
            .db
            .iter_all_entries()
            .flat_map(|e| [e.times.last_modification, e.times.location_changed]);
        let groups = self
            .db
            .iter_all_groups()
            .flat_map(|g| [g.times.last_modification, g.times.location_changed]);
        let deletions = self.db.deleted_objects.values().copied();
        entries.chain(groups).chain(deletions).flatten().max()
    }

    pub fn writable(&self) -> Result<(), Error> {
        if self.guard.writable() {
            Ok(())
        } else {
            Err(Error::ReadOnly(self.guard.unsupported.clone()))
        }
    }

    /// The older format a write will upgrade to KDBX 4.1 ("KDBX 4.0"), if
    /// any — the user is told before the first write (SPIKE-0, C5).
    pub fn upgrade_from(&self) -> Option<String> {
        match &self.opened_as {
            Some(DatabaseVersion::KDB4(1)) | None => None,
            Some(v) => Some(version_label(v)),
        }
    }

    fn in_recycle_bin(&self, group: GroupId) -> bool {
        let Some(bin) = self.db.meta.recyclebin_uuid.map(GroupId::from_uuid) else {
            return false;
        };
        let mut g = self.db.group(group);
        while let Some(cur) = g {
            if cur.id() == bin {
                return true;
            }
            g = cur.parent().map(|p| p.id()).and_then(|p| self.db.group(p));
        }
        false
    }

    fn folder_of(&self, group: GroupId) -> String {
        let mut names = Vec::new();
        let mut g = self.db.group(group);
        while let Some(cur) = g {
            if cur.parent().is_none() {
                break;
            }
            names.push(cur.name.clone());
            g = cur.parent().map(|p| p.id()).and_then(|p| self.db.group(p));
        }
        names.reverse();
        names.join("/")
    }

    fn listed(&self, deleted: bool) -> Vec<Summary> {
        let mut out: Vec<Summary> = self
            .db
            .iter_all_entries()
            .filter(|e| self.in_recycle_bin(e.parent().id()) == deleted)
            .map(|e| {
                let mut s =
                    item::summary_of(e.id().to_string(), &e, self.folder_of(e.parent().id()));
                crate::ssh::refine(&e, &mut s);
                s
            })
            .collect();
        out.sort_by_key(|s| s.title.to_lowercase());
        out
    }

    /// Every item outside the recycle bin, by title.
    pub fn items(&self) -> Vec<Summary> {
        self.listed(false)
    }

    /// The recycle bin's items ("Recently deleted").
    pub fn deleted(&self) -> Vec<Summary> {
        self.listed(true)
    }

    pub fn summary(&self, id: &str) -> Result<Summary, Error> {
        let e = self
            .db
            .entry(entry_id(id)?)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        let mut s = item::summary_of(id.to_string(), &e, self.folder_of(e.parent().id()));
        crate::ssh::refine(&e, &mut s);
        Ok(s)
    }

    pub fn search(&self, query: &str) -> Vec<Summary> {
        search::rank(&self.items(), query)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn draft(&self, id: &str) -> Result<Draft, Error> {
        let e = self
            .db
            .entry(entry_id(id)?)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        Ok(item::draft_of(&e))
    }

    /// One value, for typing or copying. Never logged by the caller.
    pub fn reveal(&self, id: &str, field: &Field) -> Result<Zeroizing<String>, Error> {
        let e = self
            .db
            .entry(entry_id(id)?)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        let missing = || Error::NotFound(format!("{id}: no such field"));
        // a card's and an address's protocol names ("number",
        // "security_code", "line1") name their KDBX fields (crate::card)
        if let Field::Other(n) = field
            && e.get(n).is_none()
            && let Some(real) = crate::card::alias(item::kind_of(&e), n)
        {
            return e
                .get(real)
                .map(|v| Zeroizing::new(v.to_string()))
                .ok_or_else(missing);
        }
        // an SSH key's private key is an attachment, and a key another app
        // stored may have no public_key field (crate::ssh)
        if let Field::Other(n) = field
            && e.get(n).is_none()
        {
            if n == crate::ssh::PRIVATE_KEY {
                return self.ssh_private(id).map(|(key, _)| key);
            }
            if n == crate::ssh::PUBLIC_KEY
                && let Some(info) = self.summary(id)?.ssh.filter(|i| !i.public_key.is_empty())
            {
                return Ok(Zeroizing::new(info.public_key));
            }
        }
        let value = match field {
            Field::Username => e.get(fields::USERNAME),
            Field::Password => e.get(fields::PASSWORD),
            Field::Notes => e.get(fields::NOTES),
            Field::OtpCode => {
                let uri = e.get(item::OTP).ok_or_else(missing)?;
                let totp =
                    Totp::parse(uri).map_err(|err| Error::NotFound(format!("{id}: {err}")))?;
                return Ok(totp.now().0);
            }
            Field::Other(name) => e.get(name),
        };
        value
            .map(|v| Zeroizing::new(v.to_string()))
            .ok_or_else(missing)
    }

    /// Add an item at the top level; returns its id.
    pub fn add(&mut self, draft: &Draft) -> Result<String, Error> {
        self.add_in(draft, "")
    }

    /// Add an item in a folder ("Work/Mail"; "" is the top), making the
    /// folders that are missing; returns its id.
    pub fn add_in(&mut self, draft: &Draft, folder: &str) -> Result<String, Error> {
        self.writable()?;
        let at = self.folder(folder)?;
        let id = self
            .db
            .group_mut(at)
            .ok_or_else(|| Error::NotFound(folder.to_string()))?
            .add_entry()
            .edit(|e| {
                item::apply(e, draft);
                e.times.last_modification = Some(Times::now());
            })
            .id();
        Ok(id.to_string())
    }

    /// Bring in what an export holds ([`crate::import`]): every item the
    /// plan keeps, in its folder, with its custom fields, its password
    /// history (oldest first, dated as the export dates it), its
    /// attachments and its times. One edit in memory; the caller saves once.
    pub fn import(
        &mut self,
        batch: &Batch,
        opts: &import::Options,
    ) -> Result<import::Report, Error> {
        self.writable()?;
        let plan = import::plan(batch, &self.items(), opts);
        for (i, folder) in &plan.add {
            let it = &batch.items[*i];
            let id = self.add_imported(it, folder)?;
            if let Some(key) = &it.ssh {
                self.put_imported_key(&id, key)?;
            }
        }
        Ok(plan.report)
    }

    fn add_imported(&mut self, it: &Imported, folder: &str) -> Result<String, Error> {
        let at = self.folder(folder)?;
        let max = self
            .db
            .meta
            .history_max_items
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(HISTORY_MAX_ITEMS);
        let mut group = self
            .db
            .group_mut(at)
            .ok_or_else(|| Error::NotFound(folder.to_string()))?;
        let mut e = group.add_entry();
        item::apply(&mut e, &it.draft);
        for f in &it.fields {
            if f.protected {
                e.set_protected(f.name.clone(), f.value.as_str());
            } else {
                e.set_unprotected(f.name.clone(), f.value.as_str());
            }
        }
        let now = Times::now();
        let modified = it.modified.unwrap_or(now);
        e.times.creation = Some(it.created.unwrap_or(modified));
        e.times.last_modification = Some(modified);
        e.times.last_access = Some(modified);
        e.times.location_changed = Some(now);

        // each old password is the item as it is now with that password,
        // dated when it stopped being the password (or spread out after
        // the item's creation when the export doesn't say)
        if !it.history.is_empty() {
            let base: keepass::db::Entry = (*e).clone();
            let start = it.created.unwrap_or(modified);
            let mut versions: Vec<keepass::db::Entry> = it
                .history
                .iter()
                .enumerate()
                .map(|(n, old)| {
                    let mut v = base.clone();
                    v.history = None;
                    v.set_protected(fields::PASSWORD, old.value.as_str());
                    let when = old
                        .time
                        .unwrap_or_else(|| start + chrono::Duration::seconds(n as i64));
                    v.times.last_modification = Some(when.min(modified));
                    v
                })
                .collect();
            let surplus = versions.len().saturating_sub(max);
            versions.drain(..surplus);
            let mut h = History::default();
            // add_entry puts each one first, so add newest to oldest
            for v in versions.into_iter().rev() {
                h.add_entry(v);
            }
            e.history = Some(h);
        }

        let mut names: Vec<String> = Vec::new();
        for f in &it.files {
            let mut name = f.name.clone();
            let mut n = 2;
            while names.contains(&name) {
                name = format!("{} ({n})", f.name);
                n += 1;
            }
            names.push(name.clone());
            e.add_attachment(name, keepass::db::Value::protected(f.data.to_vec()));
        }
        Ok(e.id().to_string())
    }

    /// Move an item to a folder ("" is the top), making it if missing. A move
    /// is not an edit: no history version.
    pub fn move_to(&mut self, id: &str, folder: &str) -> Result<(), Error> {
        self.writable()?;
        let eid = entry_id(id)?;
        let parent = self
            .db
            .entry(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?
            .parent()
            .id();
        if self.in_recycle_bin(parent) {
            return Err(Error::NotFound(id.to_string()));
        }
        let at = self.folder(folder)?;
        if parent == at {
            return Ok(());
        }
        self.relocate(eid, at)
    }

    /// The folder at `path`, made if missing. Names compare without case, as
    /// KeePass apps do; the recycle bin is never a folder.
    fn folder(&mut self, path: &str) -> Result<GroupId, Error> {
        let bin = self.db.recycle_bin().map(|g| g.id());
        let mut at = self.db.root().id();
        for name in path.split('/').map(str::trim).filter(|n| !n.is_empty()) {
            let found = self.db.group(at).and_then(|g| {
                g.groups()
                    .find(|c| Some(c.id()) != bin && c.name.eq_ignore_ascii_case(name))
                    .map(|c| c.id())
            });
            at = match found {
                Some(id) => id,
                None => self
                    .db
                    .group_mut(at)
                    .ok_or_else(|| Error::NotFound(path.to_string()))?
                    .add_group()
                    .edit(|g| g.name = name.to_string())
                    .id(),
            };
        }
        Ok(at)
    }

    /// Replace an item's Safe fields; the previous version goes to history.
    pub fn update(&mut self, id: &str, draft: &Draft) -> Result<(), Error> {
        self.writable()?;
        let eid = entry_id(id)?;
        let max = self
            .db
            .meta
            .history_max_items
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(HISTORY_MAX_ITEMS);
        let mut e = self
            .db
            .entry_mut(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        e.edit_tracking(|t| {
            item::apply(t, draft);
            t.times.last_modification = Some(Times::now());
        });
        settle_history(&mut e, max);
        Ok(())
    }

    fn recycle_bin(&mut self) -> GroupId {
        if let Some(bin) = self.db.recycle_bin() {
            return bin.id();
        }
        let bin = self
            .db
            .root_mut()
            .add_group()
            .edit(|g| {
                g.name = RECYCLE_BIN.to_string();
                g.enable_autotype = Some(false);
                g.enable_searching = Some(false);
            })
            .id();
        if let Some(mut g) = self.db.group_mut(bin) {
            g.set_icon_builtin(RECYCLE_BIN_ICON);
        }
        self.db.meta.recyclebin_enabled = Some(true);
        self.db.meta.recyclebin_uuid = Some(bin.uuid());
        self.db.meta.recyclebin_changed = Some(Times::now());
        bin
    }

    /// Move an item to the recycle bin. A move is not an edit: no history
    /// version, only a new `LocationChanged`.
    pub fn trash(&mut self, id: &str) -> Result<(), Error> {
        self.writable()?;
        let eid = entry_id(id)?;
        if self.db.entry(eid).is_none() {
            return Err(Error::NotFound(id.to_string()));
        }
        let bin = self.recycle_bin();
        self.relocate(eid, bin)
    }

    fn relocate(&mut self, id: EntryId, to: GroupId) -> Result<(), Error> {
        let mut e = self
            .db
            .entry_mut(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        e.move_to(to).map_err(|err| Error::Save(err.to_string()))?;
        e.times.location_changed = Some(Times::now());
        Ok(())
    }

    /// Bring an item back from the recycle bin to the folder it left.
    pub fn restore(&mut self, id: &str) -> Result<(), Error> {
        self.writable()?;
        let eid = entry_id(id)?;
        let e = self
            .db
            .entry(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        let back = e
            .previous_parent()
            .map(|g| g.id())
            .filter(|g| !self.in_recycle_bin(*g))
            .unwrap_or_else(|| self.db.root().id());
        self.relocate(eid, back)
    }

    /// Delete for good. The deletion is recorded, so other copies of the
    /// safe drop the item on their next merge instead of bringing it back.
    pub fn purge(&mut self, id: &str) -> Result<(), Error> {
        self.writable()?;
        let eid = entry_id(id)?;
        let mut e = self
            .db
            .entry_mut(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        e.track_changes().remove();
        Ok(())
    }

    /// Delete everything in the recycle bin for good, each deletion
    /// recorded (C3). Returns how many items went.
    pub fn empty_bin(&mut self) -> Result<usize, Error> {
        self.writable()?;
        let Some(bin) = self.db.recycle_bin().map(|g| g.id()) else {
            return Ok(0);
        };
        let items: Vec<EntryId> = self
            .db
            .iter_all_entries()
            .filter(|e| self.in_recycle_bin(e.parent().id()))
            .map(|e| e.id())
            .collect();
        for id in &items {
            if let Some(mut e) = self.db.entry_mut(*id) {
                e.track_changes().remove();
            }
        }
        let folders: Vec<GroupId> = self
            .db
            .group(bin)
            .map(|g| g.group_ids().collect())
            .unwrap_or_default();
        for g in folders {
            if let Some(mut g) = self.db.group_mut(g) {
                g.track_changes()
                    .remove()
                    .map_err(|err| Error::Save(err.to_string()))?;
            }
        }
        Ok(items.len())
    }

    /// Take in another copy of this safe (PLAN.md §7): new items from either
    /// side stay, the newer version of an item wins and the other joins its
    /// history, recorded deletions apply. Both copies must be writable,
    /// since the merged safe is written by Safe.
    pub fn merge(&mut self, theirs: &Safe) -> Result<merge::Report, Error> {
        self.writable()?;
        if !theirs.guard.writable() {
            return Err(Error::ReadOnly(
                theirs
                    .guard
                    .unsupported
                    .iter()
                    .map(|why| format!("{why} (in the other copy)"))
                    .collect(),
            ));
        }
        let (db, report) =
            merge::merge(&self.db, &theirs.db).map_err(|e| Error::Merge(e.to_string()))?;
        self.db = db;
        Ok(report)
    }

    /// The safe as KDBX 4.1 bytes, verified by reading them back.
    pub fn to_bytes(&mut self, key: &DatabaseKey) -> Result<Vec<u8>, Error> {
        self.writable()?;
        match self.db.config.version {
            DatabaseVersion::KDB4(1) => {}
            DatabaseVersion::KDB4(_) => self.db.config.version = DatabaseVersion::KDB4(1),
            _ => {
                // KDBX 3 or older: the key derivation and inner stream move to
                // what a new safe uses; the outer cipher stays
                self.db.config.version = DatabaseVersion::KDB4(1);
                self.db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
                self.db.config.kdf_config = self
                    .upgrade_kdf
                    .clone()
                    .unwrap_or_else(|| kdf::argon2id(kdf::calibrate(kdf::TARGET)));
            }
        }
        self.db.meta.generator = Some(GENERATOR.to_string());

        let mut out = Vec::new();
        self.db
            .save(&mut out, key.clone())
            .map_err(|e| Error::Save(e.to_string()))?;
        let back = Database::parse(&out, key.clone()).map_err(|e| Error::Verify(e.to_string()))?;
        let d = Digester::new();
        let (mine, theirs) = (d.digest(&self.db), d.digest(&back));
        if mine != theirs {
            let diff = digest::differences(&mine, &theirs);
            return Err(Error::Verify(format!(
                "{} lines differ, first: {}",
                diff.len(),
                diff.first().map(String::as_str).unwrap_or("?")
            )));
        }
        // the file's own reading from now on, bookkeeping included
        self.db = back;
        self.opened_as = Some(self.db.config.version.clone());
        Ok(out)
    }

    /// [`Safe::to_bytes`], then an atomic replace of `path`.
    pub fn write_file(&mut self, path: &Path, key: &DatabaseKey) -> Result<(), Error> {
        let bytes = self.to_bytes(key)?;
        atomic::write(path, &bytes)?;
        Ok(())
    }
}

/// After a tracked edit: keepass-rs put the old version first, but a
/// KeePass file lists history oldest first, so it moves to the end; then
/// the newest `max` versions stay (keepass-rs never trims).
pub(crate) fn settle_history(entry: &mut keepass::db::Entry, max: usize) {
    let Some(h) = entry.history.as_ref() else {
        return;
    };
    let mut versions: Vec<keepass::db::Entry> = h.get_entries().to_vec();
    if versions.is_empty() {
        return;
    }
    let newest = versions.remove(0);
    versions.push(newest);
    let surplus = versions.len().saturating_sub(max);
    let mut settled = History::default();
    // add_entry puts each one first, so add newest to oldest
    for v in versions.into_iter().skip(surplus).rev() {
        settled.add_entry(v);
    }
    entry.history = Some(settled);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Kind;

    fn cheap() -> KdfConfig {
        KdfConfig::Argon2id {
            iterations: 1,
            memory: 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        }
    }

    fn pw() -> DatabaseKey {
        key("correct horse", None).expect("key")
    }

    fn login(title: &str, password: &str) -> Draft {
        Draft {
            kind: Kind::Login,
            title: title.into(),
            username: "sam".into(),
            password: Zeroizing::new(password.into()),
            websites: vec![format!("https://{}.example", title.to_lowercase())],
            ..Draft::default()
        }
    }

    #[test]
    fn the_saved_by_stamp_survives_a_write_even_when_it_looks_like_base64() {
        // "emoh" is valid base64: keepass-rs reads such custom data back as
        // bytes (SPIKE-0 F6)
        for name in ["emoh", "laptop"] {
            let mut s = Safe::create("Sam's safe", cheap());
            assert_eq!(s.saved_by(), None);
            s.set_saved_by(name);
            let back = Safe::open(&s.to_bytes(&pw()).expect("write"), &pw()).expect("open");
            assert_eq!(back.saved_by().as_deref(), Some(name));
        }
    }

    #[test]
    fn newest_change_counts_items_and_deletions() {
        let mut s = Safe::create("Sam's safe", cheap());
        let id = s.add(&login("Bank", "pw")).expect("add");
        let added = s.newest_change().expect("a time");
        s.trash(&id).expect("trash");
        s.purge(&id).expect("purge");
        let deleted_at = s
            .database()
            .deleted_objects
            .values()
            .flatten()
            .max()
            .copied();
        assert!(deleted_at.is_some(), "the purge was recorded");
        assert!(s.newest_change() >= deleted_at);
        assert!(s.newest_change() >= Some(added));
    }

    #[test]
    fn create_write_open_read() {
        let mut s = Safe::create("Sam's safe", cheap());
        let bank = s.add(&login("Bank", "hunter2")).expect("add");
        let note = s
            .add(&Draft {
                kind: Kind::Note,
                title: "Wi-Fi".into(),
                notes: Zeroizing::new("router in the hall".into()),
                ..Draft::default()
            })
            .expect("add note");
        let bytes = s.to_bytes(&pw()).expect("write");

        let back = Safe::open(&bytes, &pw()).expect("open");
        assert!(back.writable().is_ok());
        assert_eq!(back.upgrade_from(), None);
        let items = back.items();
        assert_eq!(
            items.iter().map(|i| i.title.as_str()).collect::<Vec<_>>(),
            ["Bank", "Wi-Fi"]
        );
        assert_eq!(
            back.reveal(&bank, &Field::Password)
                .expect("reveal")
                .as_str(),
            "hunter2"
        );
        assert_eq!(back.summary(&note).expect("note").kind, Kind::Note);
        assert_eq!(back.database().meta.generator.as_deref(), Some(GENERATOR));
    }

    #[test]
    fn the_wrong_password_does_not_open() {
        let mut s = Safe::create("x", cheap());
        let bytes = s.to_bytes(&pw()).expect("write");
        let wrong = key("wrong", None).expect("key");
        assert!(matches!(Safe::open(&bytes, &wrong), Err(Error::Open(_))));
    }

    #[test]
    fn an_update_keeps_history_and_moves_the_time() {
        let mut s = Safe::create("x", cheap());
        let id = s.add(&login("Bank", "one")).expect("add");
        let before = s.summary(&id).expect("summary").modified;
        s.db.entry_mut(entry_id(&id).expect("id"))
            .expect("entry")
            .times
            .last_modification = Some(chrono::NaiveDateTime::MIN);
        s.update(&id, &login("Bank", "two")).expect("update");
        assert_eq!(
            s.reveal(&id, &Field::Password).expect("reveal").as_str(),
            "two"
        );
        assert_ne!(
            s.summary(&id).expect("summary").modified,
            Some(chrono::NaiveDateTime::MIN)
        );
        assert!(before.is_some());
        let e = s.db.entry(entry_id(&id).expect("id")).expect("entry");
        let hist = e.history.as_ref().expect("history");
        assert_eq!(hist.get_entries()[0].get(fields::PASSWORD), Some("one"));
    }

    #[test]
    fn history_is_trimmed_to_the_safe_limit() {
        let mut s = Safe::create("x", cheap());
        s.db.meta.history_max_items = Some(3);
        let id = s.add(&login("Bank", "0")).expect("add");
        for n in 1..=6 {
            s.update(&id, &login("Bank", &n.to_string()))
                .expect("update");
        }
        let e = s.db.entry(entry_id(&id).expect("id")).expect("entry");
        let kept: Vec<_> = e
            .history
            .as_ref()
            .expect("history")
            .get_entries()
            .iter()
            .filter_map(|h| h.get(fields::PASSWORD))
            .collect();
        assert_eq!(kept, ["3", "4", "5"], "oldest first, newest kept");
    }

    #[test]
    fn folders() {
        let mut s = Safe::create("x", cheap());
        let a = s.add_in(&login("Mail", "x"), "Work/Mail").expect("add");
        let b = s.add_in(&login("Chat", "x"), "work").expect("add");
        assert_eq!(s.summary(&a).expect("a").folder, "Work/Mail");
        assert_eq!(
            s.summary(&b).expect("b").folder,
            "Work",
            "found without case"
        );
        s.move_to(&a, "").expect("move");
        assert_eq!(s.summary(&a).expect("a").folder, "");
        s.trash(&b).expect("trash");
        assert!(
            s.move_to(&b, "Work").is_err(),
            "an item in the bin doesn't move"
        );
    }

    #[test]
    fn trash_restore_purge() {
        let mut s = Safe::create("x", cheap());
        let id = s.add(&login("Bank", "x")).expect("add");
        s.trash(&id).expect("trash");
        assert!(s.items().is_empty());
        assert_eq!(s.deleted().len(), 1);
        assert!(s.search("bank").is_empty(), "the bin is not searched");
        s.restore(&id).expect("restore");
        assert_eq!(s.items().len(), 1);
        s.trash(&id).expect("trash again");
        s.purge(&id).expect("purge");
        assert!(s.deleted().is_empty());
        let uuid = entry_id(&id).expect("id").uuid();
        assert!(
            s.db.deleted_objects.contains_key(&uuid),
            "the deletion is recorded (C3)"
        );
        let bytes = s.to_bytes(&pw()).expect("write");
        let back = Safe::open(&bytes, &pw()).expect("open");
        assert!(back.database().deleted_objects.contains_key(&uuid));
    }

    #[test]
    fn a_read_only_safe_refuses_every_write() {
        let mut s = Safe::create("x", cheap());
        let id = s.add(&login("Bank", "x")).expect("add");
        s.guard.unsupported = vec!["element <Future> in <Meta>".into()];
        assert!(matches!(s.add(&login("B", "y")), Err(Error::ReadOnly(_))));
        assert!(matches!(
            s.update(&id, &login("B", "y")),
            Err(Error::ReadOnly(_))
        ));
        assert!(matches!(s.trash(&id), Err(Error::ReadOnly(_))));
        assert!(matches!(s.purge(&id), Err(Error::ReadOnly(_))));
        assert!(matches!(s.to_bytes(&pw()), Err(Error::ReadOnly(_))));
        // reading still works
        assert_eq!(
            s.reveal(&id, &Field::Password).expect("reveal").as_str(),
            "x"
        );
    }

    #[test]
    fn one_time_codes_reveal_digits() {
        let mut s = Safe::create("x", cheap());
        let mut d = login("Bank", "x");
        d.otp =
            Zeroizing::new("otpauth://totp/Bank:sam?secret=JBSWY3DPEHPK3PXP&issuer=Bank".into());
        let id = s.add(&d).expect("add");
        let code = s.reveal(&id, &Field::OtpCode).expect("code");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(s.reveal(&id, &Field::Other("missing".into())).is_err());
    }

    #[test]
    fn write_file_replaces_atomically() {
        let dir = std::env::temp_dir().join(format!("safe-core-safe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("passwords.kdbx");
        let mut s = Safe::create("x", cheap());
        s.add(&login("Bank", "x")).expect("add");
        s.write_file(&path, &pw()).expect("write");
        let back = Safe::open_file(&path, &pw()).expect("open");
        assert_eq!(back.items().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
