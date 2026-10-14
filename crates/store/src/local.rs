//! "This computer": the safe is a file on this machine. Its version is the
//! SHA-256 of its bytes, so a change made by something else (KeePassXC, a
//! restore, phase 3's sync tools) is seen and reported as stale instead of
//! being overwritten. Compare and write happen under one lock in this
//! process; another program writing in the same instant is not excluded.

use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use safe_core::atomic;

use crate::Error;
use crate::place::{Expect, Fetched, Place, PlaceInfo, Stored, Tag};

pub struct Local {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Local {
    pub fn new(path: impl Into<PathBuf>) -> Local {
        Local {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        match fs::read(&self.path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl Place for Local {
    fn info(&self) -> PlaceInfo {
        PlaceInfo {
            kind: "local".to_string(),
            location: self.path.display().to_string(),
            guarded: true,
        }
    }

    fn fetch(&self, known: Option<&Tag>) -> Result<Fetched, Error> {
        let _held = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        Ok(match self.read()? {
            None => Fetched::Missing,
            Some(bytes) => {
                let tag = Tag::content(&bytes);
                if known == Some(&tag) {
                    Fetched::Unchanged
                } else {
                    Fetched::Bytes { bytes, tag }
                }
            }
        })
    }

    fn store(&self, bytes: &[u8], expect: &Expect) -> Result<Stored, Error> {
        let _held = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.read()?.map(|b| Tag::content(&b));
        let fresh = match (expect, &current) {
            (Expect::Absent, None) => true,
            (Expect::Tag(want), Some(have)) => want == have,
            _ => false,
        };
        if !fresh {
            return Ok(Stored::Stale);
        }
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        atomic::write(&self.path, bytes)?;
        Ok(Stored::Ok(Tag::content(bytes)))
    }

    fn probe(&self) -> Result<bool, Error> {
        Ok(true)
    }
}
