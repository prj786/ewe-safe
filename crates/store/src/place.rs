//! What every place does. A place holds one file and refuses to overwrite
//! a copy the caller hasn't seen — that refusal is the conflict guard the
//! sync engine builds on (PLAN.md §6).

use serde::{Deserialize, Serialize};

use crate::Error;

/// A version of the file in its place. `etag:<v>` is a server's ETag;
/// `sha256:<hex>` is a content hash, for places with no version of their
/// own (a local file, a WebDAV server without ETags).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tag(pub String);

impl Tag {
    pub fn etag(v: &str) -> Tag {
        Tag(format!("etag:{v}"))
    }

    pub fn content(bytes: &[u8]) -> Tag {
        Tag(format!("sha256:{}", crate::sha256_hex(bytes)))
    }

    /// The server's ETag, if this tag is one.
    pub fn as_etag(&self) -> Option<&str> {
        self.0.strip_prefix("etag:")
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// PROTOCOL.md's place object — never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceInfo {
    /// `local` | `nextcloud` | `webdav` (later `folder`, `sftp`, `dropbox`, `gdrive`)
    pub kind: String,
    /// Where the file is: a path, or a path inside the account.
    pub location: String,
    /// The place refuses a stale save.
    pub guarded: bool,
}

#[derive(Debug)]
pub enum Fetched {
    /// The file is still the version the caller knows.
    Unchanged,
    /// There is no file.
    Missing,
    Bytes {
        bytes: Vec<u8>,
        tag: Tag,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Store only if there is no file yet.
    Absent,
    /// Store only if the file is still this version.
    Tag(Tag),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Stored {
    /// Stored; the file's new version.
    Ok(Tag),
    /// Refused: the file isn't the version expected (someone else saved).
    Stale,
}

pub trait Place: Send + Sync {
    fn info(&self) -> PlaceInfo;

    /// The file, unless it is still `known`.
    fn fetch(&self, known: Option<&Tag>) -> Result<Fetched, Error>;

    /// Write the file only if it is what `expect` says.
    fn store(&self, bytes: &[u8], expect: &Expect) -> Result<Stored, Error>;

    /// Check that the place really refuses a stale save (the guard probe).
    fn probe(&self) -> Result<bool, Error>;
}
