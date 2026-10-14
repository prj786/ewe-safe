//! The sync engine (PLAN.md §7, docs/PLACES.md). One [`Syncer`] per safe:
//! it keeps the encrypted cache, the backups and `sync.json` in a state
//! directory, and moves the safe between this machine and its place.
//!
//! - A **save** writes the cache first (with a backup of the old one), then
//!   stores it in the place only if the place still has the version this
//!   machine last saw. Stale → fetch theirs, merge, verify, try again (three
//!   times, then pending). Offline → pending.
//! - **Load** and **poll** merge the place's copy with this machine's: when
//!   this machine adds nothing, the place's bytes are taken as they are and
//!   nothing is uploaded, so two machines never trade uploads forever.
//! - A copy older than one already seen (a **rollback**) is never taken
//!   silently: it is merged with what this machine has, uploaded again, and
//!   the warning stays until [`Syncer::clear_warning`].
//! - Only bytes that were read back with the key (the verified write) are
//!   ever stored in the place.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use keepass::{Database, DatabaseKey};
use safe_core::Safe;
use safe_core::digest::Digester;
use safe_core::merge::Report;
use safe_core::safe::SAVED_BY_KEY;
use serde::{Deserialize, Serialize};

use crate::place::{Expect, Fetched, Place, PlaceInfo, Stored, Tag};
use crate::{Error, sha256_hex};

/// Encrypted copies of earlier saves this machine keeps.
pub const BACKUPS: usize = 20;
/// Store attempts in one save before the changes wait (pending).
const TRIES: usize = 3;
const CACHE: &str = "cache/passwords.kdbx";
const INCOMING: &str = "cache/incoming.kdbx";
const STATE: &str = "sync.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    /// The place's version the cache was last exchanged at.
    tag: Option<Tag>,
    synced_sha256: Option<String>,
    /// The newest change seen in any copy exchanged with the place.
    newest_seen: Option<NaiveDateTime>,
    /// The cache holds changes the place doesn't have yet.
    pending: bool,
    last_ok: Option<DateTime<Utc>>,
    last_error: Option<String>,
    /// PROTOCOL.md's code for the last failure (`offline`, `place-error`, …).
    last_error_code: Option<String>,
    by_machine: Option<String>,
    /// `rollback`, until cleared.
    warning: Option<String>,
    probe: Option<Probe>,
    /// The version of `cache/incoming.kdbx`, fetched while locked.
    incoming: Option<Tag>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub guarded: bool,
    pub checked_at: DateTime<Utc>,
}

/// PROTOCOL.md's sync object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncStatus {
    /// `in-sync` | `pending` | `offline` | `error` | `local`
    pub state: String,
    pub last: Option<String>,
    pub by_machine: Option<String>,
    pub pending: bool,
    /// `rollback` | `single-writer`
    pub warning: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Saved {
    /// In the place. `merged` = another copy was merged in on the way, so
    /// the safe in memory changed.
    Synced { merged: Option<Report> },
    /// Saved on this machine only; `reason` is PROTOCOL.md's code
    /// (`offline`, `place-error`, `key-changed`, `busy`).
    Pending { reason: String },
}

#[derive(Debug, Default)]
pub struct Loaded {
    /// What the place's copy brought in.
    pub merged: Option<Report>,
    /// The place couldn't be reached: this is the cache (or what was fetched
    /// while locked).
    pub offline: bool,
}

#[derive(Debug, Default)]
pub struct Polled {
    /// The safe in memory changed (another copy merged in).
    pub changed: bool,
    /// This machine's changes reached the place.
    pub uploaded: bool,
    pub merged: Option<Report>,
}

pub struct Syncer {
    place: Box<dyn Place>,
    dir: PathBuf,
    machine: String,
    state: State,
}

impl Syncer {
    /// `dir` is the state directory ([`default_dir`] in the daemon);
    /// `machine` names this machine in the file (`ewe.saved-by`).
    pub fn new(
        place: Box<dyn Place>,
        dir: impl Into<PathBuf>,
        machine: &str,
    ) -> Result<Syncer, Error> {
        let dir = dir.into();
        for d in [dir.clone(), dir.join("cache"), dir.join("backups")] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&d)?;
        }
        let state = match fs::read(dir.join(STATE)) {
            Ok(b) => match serde_json::from_slice::<State>(&b) {
                Ok(s) => s,
                Err(_) => {
                    // unreadable: keep it for a human, and assume the cache
                    // has changes so the next exchange merges, never replaces
                    let _ = fs::rename(dir.join(STATE), dir.join("sync.json.broken"));
                    State {
                        pending: dir.join(CACHE).exists(),
                        ..State::default()
                    }
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Syncer {
            place,
            dir,
            machine: machine.to_string(),
            state,
        })
    }

    pub fn place_info(&self) -> PlaceInfo {
        let mut info = self.place.info();
        if let Some(p) = &self.state.probe {
            info.guarded = p.guarded;
        }
        info
    }

    pub fn probe_result(&self) -> Option<&Probe> {
        self.state.probe.as_ref()
    }

    /// There is a cached copy of the safe on this machine.
    pub fn has_cache(&self) -> bool {
        self.dir.join(CACHE).exists()
    }

    pub fn status(&self) -> SyncStatus {
        let s = &self.state;
        let local = self.place.info().kind == "local";
        let state = match s.last_error_code.as_deref() {
            Some("offline") => "offline",
            Some(_) => "error",
            None if s.pending => "pending",
            None if local => "local",
            None => "in-sync",
        };
        let warning = s.warning.clone().or_else(|| {
            self.state
                .probe
                .as_ref()
                .filter(|p| !p.guarded)
                .map(|_| "single-writer".to_string())
        });
        SyncStatus {
            state: state.to_string(),
            last: s
                .last_ok
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            by_machine: s.by_machine.clone(),
            pending: s.pending,
            warning,
        }
    }

    /// The last failure's message, for a UI.
    pub fn last_error(&self) -> Option<&str> {
        self.state.last_error.as_deref()
    }

    /// The user has seen the rollback warning.
    pub fn clear_warning(&mut self) -> Result<(), Error> {
        self.state.warning = None;
        self.save_state()
    }

    /// Run the place's guard probe and remember the answer.
    pub fn probe(&mut self) -> Result<bool, Error> {
        let guarded = self.place.probe()?;
        self.state.probe = Some(Probe {
            guarded,
            checked_at: Utc::now(),
        });
        self.save_state()?;
        Ok(guarded)
    }

    /// Put a new safe in the place. A safe already there is not touched
    /// ([`Error::Exists`]); offline, it waits on this machine (pending).
    pub fn create(&mut self, safe: &mut Safe, key: &DatabaseKey) -> Result<Saved, Error> {
        if self.has_cache() {
            return Err(Error::Place(
                "this machine already has a safe for this place".into(),
            ));
        }
        self.state = State::default();
        safe.set_saved_by(&self.machine);
        let bytes = safe.to_bytes(key)?;
        self.write_cache(&bytes)?;
        self.state.pending = true;
        self.save_state()?;
        match self.place.store(&bytes, &Expect::Absent) {
            Ok(Stored::Ok(tag)) => {
                self.synced(tag, &bytes, safe, Some(self.machine.clone()))?;
                Ok(Saved::Synced { merged: None })
            }
            Ok(Stored::Stale) => {
                self.forget_all()?;
                Err(Error::Exists)
            }
            Err(e) => self.pending_after(e),
        }
    }

    /// Open the safe: the place's copy merged with this machine's. When the
    /// place can't be reached, the cache (merged in memory with what was
    /// fetched while locked); nothing is marked in sync then.
    pub fn load(&mut self, key: &DatabaseKey) -> Result<(Safe, Loaded), Error> {
        let cache = self.read(CACHE)?;
        let known = cache.as_ref().and(self.state.tag.clone());
        let fetched = self.place.fetch(known.as_ref());
        let ours = match &cache {
            Some(b) => match Safe::open(b, key) {
                Ok(s) => Some(s),
                Err(safe_core::Error::Open(_)) => None,
                Err(e) => return Err(e.into()),
            },
            None => None,
        };
        let wrong_key = || {
            Error::Safe(safe_core::Error::Open(
                "the password doesn't open this safe".into(),
            ))
        };
        let cache_key_old = cache.is_some() && ours.is_none();

        let (their_bytes, their_tag) = match fetched {
            Err(e @ (Error::Offline(_) | Error::Place(_))) => {
                self.note_error(&e)?;
                let incoming = match (self.read(INCOMING)?, &self.state.incoming) {
                    (Some(b), Some(_)) => Safe::open(&b, key).ok(),
                    _ => None,
                };
                let safe = match (ours, incoming) {
                    (Some(mut o), Some(i)) => {
                        if o.writable().is_ok() && i.writable().is_ok() {
                            o.merge(&i)?;
                        }
                        o
                    }
                    (Some(o), None) => o,
                    (None, Some(i)) => i,
                    (None, None) if cache_key_old => return Err(wrong_key()),
                    (None, None) => return Err(e),
                };
                return Ok((
                    safe,
                    Loaded {
                        merged: None,
                        offline: true,
                    },
                ));
            }
            Err(e) => return Err(e),
            Ok(Fetched::Unchanged | Fetched::Missing) if ours.is_none() => {
                self.drop_incoming()?;
                return Err(if cache_key_old {
                    wrong_key()
                } else {
                    Error::Missing
                });
            }
            Ok(Fetched::Unchanged) => {
                self.drop_incoming()?;
                let mut ours = ours.expect("checked above");
                let mut loaded = Loaded::default();
                if self.state.pending {
                    let bytes = cache.unwrap_or_default();
                    if let Saved::Synced { merged } = self.push(&mut ours, key, bytes)? {
                        loaded.merged = merged;
                    }
                } else {
                    self.ok_now(&ours)?;
                }
                return Ok((ours, loaded));
            }
            Ok(Fetched::Missing) => {
                // the place lost the file: put this machine's copy back
                self.drop_incoming()?;
                let mut ours = ours.expect("checked above");
                self.state.tag = None;
                self.state.pending = true;
                self.save_state()?;
                let mut loaded = Loaded::default();
                if let Saved::Synced { merged } =
                    self.push(&mut ours, key, cache.unwrap_or_default())?
                {
                    loaded.merged = merged;
                }
                return Ok((ours, loaded));
            }
            Ok(Fetched::Bytes { bytes, tag }) => {
                self.drop_incoming()?;
                (bytes, tag)
            }
        };

        let mut theirs = match Safe::open(&their_bytes, key) {
            Ok(s) => s,
            Err(safe_core::Error::Open(_)) if ours.is_some() => {
                self.note_error(&Error::KeyChanged)?;
                return Err(Error::KeyChanged);
            }
            Err(e) => return Err(e.into()),
        };
        if cache_key_old && self.state.pending {
            return Err(Error::CacheKey);
        }
        let by = theirs.saved_by();
        let rollback = self.is_rollback(&theirs);
        if rollback {
            self.state.warning = Some("rollback".to_string());
        }
        let Some(ours) = ours else {
            self.adopt(&their_bytes, their_tag, &theirs, by)?;
            return Ok((theirs, Loaded::default()));
        };
        if theirs.writable().is_err() || ours.writable().is_err() {
            // a copy Safe can't write back: nothing can be merged into it
            if self.state.pending {
                let e = Error::Safe(theirs.writable().and(ours.writable()).unwrap_err());
                self.note_error(&e)?;
                return Err(e);
            }
            self.adopt(&their_bytes, their_tag, &theirs, by)?;
            return Ok((theirs, Loaded::default()));
        }

        let before = content(theirs.database());
        let report = theirs.merge(&ours)?;
        let adds_nothing = content(theirs.database()) == before;
        let merged = (report != Report::default()).then_some(report);
        if adds_nothing && !rollback {
            self.adopt(&their_bytes, their_tag, &theirs, by)?;
            return Ok((
                theirs,
                Loaded {
                    merged,
                    offline: false,
                },
            ));
        }
        // this machine has something the place doesn't: upload the merge
        self.state.tag = Some(their_tag);
        theirs.set_saved_by(&self.machine);
        let bytes = theirs.to_bytes(key)?;
        self.write_cache(&bytes)?;
        self.state.pending = true;
        self.save_state()?;
        self.push(&mut theirs, key, bytes)?;
        Ok((
            theirs,
            Loaded {
                merged,
                offline: false,
            },
        ))
    }

    /// Save the safe: the cache now, the place if it can be reached.
    pub fn save(&mut self, safe: &mut Safe, key: &DatabaseKey) -> Result<Saved, Error> {
        safe.set_saved_by(&self.machine);
        let bytes = safe.to_bytes(key)?;
        self.write_cache(&bytes)?;
        self.state.pending = true;
        self.save_state()?;
        self.push(safe, key, bytes)
    }

    /// The periodic exchange (every few minutes, on network up, on unlock).
    /// Unlocked: pending changes go up, the place's changes merge in.
    /// Locked: pending bytes go up if nobody saved meanwhile; a newer copy is
    /// only downloaded (merging needs the key).
    pub fn poll(&mut self, unlocked: Option<(&mut Safe, &DatabaseKey)>) -> Result<Polled, Error> {
        match unlocked {
            Some((safe, key)) => self.poll_unlocked(safe, key),
            None => self.poll_locked(),
        }
    }

    fn poll_unlocked(&mut self, safe: &mut Safe, key: &DatabaseKey) -> Result<Polled, Error> {
        if self.state.pending {
            let bytes = match self.read(CACHE)? {
                Some(b) => b,
                None => safe.to_bytes(key)?,
            };
            return Ok(match self.push(safe, key, bytes)? {
                Saved::Synced { merged } => Polled {
                    changed: merged.is_some(),
                    uploaded: true,
                    merged,
                },
                Saved::Pending { .. } => Polled::default(),
            });
        }
        let fetched = match self.place.fetch(self.state.tag.as_ref()) {
            Ok(f) => f,
            Err(e @ (Error::Offline(_) | Error::Place(_))) => {
                self.note_error(&e)?;
                return Ok(Polled::default());
            }
            Err(e) => return Err(e),
        };
        match fetched {
            Fetched::Unchanged => {
                self.ok_now(safe)?;
                Ok(Polled::default())
            }
            Fetched::Missing => {
                self.state.tag = None;
                self.state.pending = true;
                self.save_state()?;
                self.poll_unlocked(safe, key)
            }
            Fetched::Bytes { bytes, tag } => {
                let mut theirs = match Safe::open(&bytes, key) {
                    Ok(s) => s,
                    Err(safe_core::Error::Open(_)) => {
                        self.note_error(&Error::KeyChanged)?;
                        return Err(Error::KeyChanged);
                    }
                    Err(e) => return Err(e.into()),
                };
                let by = theirs.saved_by();
                let rollback = self.is_rollback(&theirs);
                if rollback {
                    self.state.warning = Some("rollback".to_string());
                }
                if theirs.writable().is_err() || safe.writable().is_err() {
                    // nothing can be merged into a copy Safe can't write back;
                    // this machine has no changes (not pending), so take theirs
                    self.adopt(&bytes, tag, &theirs, by)?;
                    *safe = theirs;
                    return Ok(Polled {
                        changed: true,
                        uploaded: false,
                        merged: None,
                    });
                }
                let before = content(theirs.database());
                let mine = content(safe.database());
                let report = theirs.merge(safe)?;
                let after = content(theirs.database());
                let changed = after != mine;
                let merged = (report != Report::default()).then_some(report);
                if after == before && !rollback {
                    self.adopt(&bytes, tag, &theirs, by)?;
                    *safe = theirs;
                    return Ok(Polled {
                        changed,
                        uploaded: false,
                        merged,
                    });
                }
                self.state.tag = Some(tag);
                theirs.set_saved_by(&self.machine);
                let out = theirs.to_bytes(key)?;
                self.write_cache(&out)?;
                self.state.pending = true;
                self.save_state()?;
                *safe = theirs;
                let uploaded = matches!(self.push(safe, key, out)?, Saved::Synced { .. });
                Ok(Polled {
                    changed,
                    uploaded,
                    merged,
                })
            }
        }
    }

    fn poll_locked(&mut self) -> Result<Polled, Error> {
        if self.state.pending {
            let Some(bytes) = self.read(CACHE)? else {
                return Ok(Polled::default());
            };
            let expect = self.expect();
            return match self.place.store(&bytes, &expect) {
                Ok(Stored::Ok(tag)) => {
                    self.state.tag = Some(tag);
                    self.state.synced_sha256 = Some(sha256_hex(&bytes));
                    self.state.pending = false;
                    self.state.by_machine = Some(self.machine.clone());
                    self.mark_ok()?;
                    Ok(Polled {
                        changed: false,
                        uploaded: true,
                        merged: None,
                    })
                }
                // someone saved meanwhile: the merge waits for the key
                Ok(Stored::Stale) => Ok(Polled::default()),
                Err(e @ (Error::Offline(_) | Error::Place(_))) => {
                    self.note_error(&e)?;
                    Ok(Polled::default())
                }
                Err(e) => Err(e),
            };
        }
        match self.place.fetch(self.state.tag.as_ref()) {
            Ok(Fetched::Bytes { bytes, tag }) => {
                if self.state.incoming.as_ref() != Some(&tag) {
                    safe_core::atomic::write(&self.dir.join(INCOMING), &bytes)?;
                    self.state.incoming = Some(tag);
                }
                self.mark_ok()?;
            }
            Ok(Fetched::Unchanged) => {
                self.drop_incoming()?;
                self.mark_ok()?;
            }
            Ok(Fetched::Missing) => {}
            Err(e @ (Error::Offline(_) | Error::Place(_))) => self.note_error(&e)?,
            Err(e) => return Err(e),
        }
        Ok(Polled::default())
    }

    /// Store `bytes` (already verified, already in the cache) in the place;
    /// stale → merge theirs into `safe` and try again.
    fn push(
        &mut self,
        safe: &mut Safe,
        key: &DatabaseKey,
        mut bytes: Vec<u8>,
    ) -> Result<Saved, Error> {
        let mut merged: Option<Report> = None;
        for _ in 0..TRIES {
            let expect = self.expect();
            match self.place.store(&bytes, &expect) {
                Ok(Stored::Ok(tag)) => {
                    self.synced(tag, &bytes, safe, Some(self.machine.clone()))?;
                    return Ok(Saved::Synced { merged });
                }
                Ok(Stored::Stale) => {}
                Err(e) => return self.pending_after(e),
            }
            let (their_bytes, their_tag) = match self.place.fetch(None) {
                Ok(Fetched::Bytes { bytes, tag }) => (bytes, tag),
                Ok(Fetched::Missing) => {
                    self.state.tag = None;
                    continue;
                }
                Ok(Fetched::Unchanged) => continue,
                Err(e) => return self.pending_after(e),
            };
            let theirs = match Safe::open(&their_bytes, key) {
                Ok(s) => s,
                Err(safe_core::Error::Open(_)) => return self.pending_after(Error::KeyChanged),
                Err(e) => return Err(e.into()),
            };
            if self.is_rollback(&theirs) {
                self.state.warning = Some("rollback".to_string());
            }
            let report = safe.merge(&theirs)?;
            merged = Some(add(merged, report));
            safe.set_saved_by(&self.machine);
            bytes = safe.to_bytes(key)?;
            self.write_cache(&bytes)?;
            self.state.tag = Some(their_tag);
            self.save_state()?;
        }
        self.state.last_error = Some("other machines kept saving at the same time".into());
        self.state.last_error_code = Some("busy".into());
        self.save_state()?;
        Ok(Saved::Pending {
            reason: "busy".into(),
        })
    }

    fn expect(&self) -> Expect {
        match &self.state.tag {
            Some(t) => Expect::Tag(t.clone()),
            None => Expect::Absent,
        }
    }

    /// The exchange failed: the changes wait on this machine.
    fn pending_after(&mut self, e: Error) -> Result<Saved, Error> {
        match e {
            Error::Offline(_) | Error::Place(_) | Error::KeyChanged => {
                let reason = e.code().to_string();
                self.state.pending = true;
                self.note_error(&e)?;
                Ok(Saved::Pending { reason })
            }
            e => Err(e),
        }
    }

    fn note_error(&mut self, e: &Error) -> Result<(), Error> {
        self.state.last_error = Some(e.to_string());
        self.state.last_error_code = Some(e.code().to_string());
        self.save_state()
    }

    fn mark_ok(&mut self) -> Result<(), Error> {
        self.state.last_ok = Some(Utc::now());
        self.state.last_error = None;
        self.state.last_error_code = None;
        self.save_state()
    }

    /// The place answered "unchanged": this machine is in step with it.
    fn ok_now(&mut self, safe: &Safe) -> Result<(), Error> {
        self.state.newest_seen = newest(self.state.newest_seen, safe.newest_change());
        self.mark_ok()
    }

    /// The place's copy, taken as it is. `by` is who wrote it, read before
    /// any merge touched the copy in memory.
    fn adopt(
        &mut self,
        bytes: &[u8],
        tag: Tag,
        safe: &Safe,
        by: Option<String>,
    ) -> Result<(), Error> {
        self.write_cache(bytes)?;
        self.synced(tag, bytes, safe, by)
    }

    fn synced(
        &mut self,
        tag: Tag,
        bytes: &[u8],
        safe: &Safe,
        by: Option<String>,
    ) -> Result<(), Error> {
        self.state.tag = Some(tag);
        self.state.synced_sha256 = Some(sha256_hex(bytes));
        self.state.pending = false;
        self.state.newest_seen = newest(self.state.newest_seen, safe.newest_change());
        self.state.by_machine = by.or_else(|| Some(self.machine.clone()));
        self.drop_incoming()?;
        self.mark_ok()
    }

    fn is_rollback(&self, theirs: &Safe) -> bool {
        match (theirs.newest_change(), self.state.newest_seen) {
            (Some(n), Some(seen)) => n < seen,
            (None, Some(_)) => true,
            _ => false,
        }
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        match fs::read(self.dir.join(name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn drop_incoming(&mut self) -> Result<(), Error> {
        if self.state.incoming.take().is_some() {
            let _ = fs::remove_file(self.dir.join(INCOMING));
            self.save_state()?;
        }
        Ok(())
    }

    /// Replace the cache, keeping the old one among the backups.
    fn write_cache(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let cache = self.dir.join(CACHE);
        if let Some(old) = self.read(CACHE)?
            && old != bytes
        {
            self.backup(&old)?;
        }
        safe_core::atomic::write(&cache, bytes)?;
        Ok(())
    }

    fn backup(&self, bytes: &[u8]) -> Result<(), Error> {
        let dir = self.dir.join("backups");
        let stamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
        let mut path = dir.join(format!("passwords-{stamp}.kdbx"));
        let mut n = 1;
        while path.exists() {
            path = dir.join(format!("passwords-{stamp}-{n}.kdbx"));
            n += 1;
        }
        safe_core::atomic::write(&path, bytes)?;
        let mut all = backups(&dir)?;
        while all.len() > BACKUPS {
            let oldest = all.remove(0);
            fs::remove_file(oldest)?;
        }
        Ok(())
    }

    /// The backups, oldest first.
    pub fn backups(&self) -> Result<Vec<PathBuf>, Error> {
        backups(&self.dir.join("backups"))
    }

    fn forget_all(&mut self) -> Result<(), Error> {
        let _ = fs::remove_file(self.dir.join(CACHE));
        let _ = fs::remove_file(self.dir.join(INCOMING));
        self.state = State::default();
        self.save_state()
    }

    fn save_state(&self) -> Result<(), Error> {
        let bytes =
            serde_json::to_vec_pretty(&self.state).map_err(|e| Error::Io(io::Error::other(e)))?;
        let path = self.dir.join(STATE);
        safe_core::atomic::write(&path, &bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

/// `$XDG_STATE_HOME/ewe/safe`, else `~/.local/state/ewe/safe`.
pub fn default_dir() -> PathBuf {
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default();
            home.join(".local/state")
        });
    state.join("ewe/safe")
}

/// This machine's name, for `ewe.saved-by`.
pub fn machine_name() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this machine".to_string())
}

fn backups(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut all: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("passwords-") && n.ends_with(".kdbx"))
        })
        .collect();
    all.sort();
    Ok(all)
}

fn newest(a: Option<NaiveDateTime>, b: Option<NaiveDateTime>) -> Option<NaiveDateTime> {
    a.max(b)
}

fn add(a: Option<Report>, b: Report) -> Report {
    let a = a.unwrap_or_default();
    Report {
        added: a.added + b.added,
        updated: a.updated + b.updated,
        diverged: a.diverged + b.diverged,
        to_history: a.to_history + b.to_history,
        deleted: a.deleted + b.deleted,
        moved: a.moved + b.moved,
        groups_added: a.groups_added + b.groups_added,
        groups_deleted: a.groups_deleted + b.groups_deleted,
    }
}

/// What a copy holds, without what changes on every exchange and means
/// nothing: who saved it last and the last-selected-group hints.
fn content(db: &Database) -> Vec<String> {
    let mut db = db.clone();
    db.meta.custom_data.remove(SAVED_BY_KEY);
    db.meta.last_selected_group = None;
    db.meta.last_top_visible_group = None;
    DIGEST.with(|d| d.digest(&db))
}

thread_local! {
    // one key for every comparison in this thread
    static DIGEST: Digester = Digester::new();
}
