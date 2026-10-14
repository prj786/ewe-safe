//! safe-store — the places a safe can live, each one's conflict guard, and
//! the sync engine that moves the safe between this machine and its place
//! (PLAN.md §6, §7; docs/PLACES.md).
//!
//! - [`place`]: what every place does — fetch, store-if-unchanged, probe.
//! - [`local`]: "This computer": a file, guarded by its content hash.
//! - [`webdav`]: any WebDAV server, and the ewe account's Nextcloud through
//!   `ewe-cloud`; guarded by `If-Match`.
//! - [`sync`]: the [`Syncer`]: the encrypted cache, backups, `sync.json`,
//!   and save → stale → merge → retry.

pub mod local;
pub mod place;
pub mod sync;
pub mod webdav;

pub use local::Local;
pub use place::{Expect, Fetched, Place, PlaceInfo, Stored, Tag};
pub use sync::{Loaded, Polled, Probe, Saved, SyncStatus, Syncer, default_dir, machine_name};
pub use webdav::{Credentials, EweCloud, Fixed, Login, WebDav};

#[derive(Debug)]
pub enum Error {
    /// The place can't be reached: no network, DNS, refused, timed out.
    Offline(String),
    /// The place answered, but not with what Safe needs (a status, a sign-in
    /// problem, a refused plain-http URL).
    Place(String),
    /// The copy in the place doesn't open with this key: the master password
    /// was changed on another machine.
    KeyChanged,
    /// This machine's unsent changes are locked with a key that no longer
    /// opens anything else (the password changed elsewhere meanwhile).
    CacheKey,
    /// There is no safe here yet, neither in the place nor in the cache.
    Missing,
    /// `create` found a safe already in the place.
    Exists,
    Safe(safe_core::Error),
    Io(std::io::Error),
}

impl Error {
    /// The error code PROTOCOL.md names for this.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Offline(_) => "offline",
            Error::Place(_) | Error::Exists => "place-error",
            Error::KeyChanged | Error::CacheKey => "key-changed",
            Error::Missing => "not-set-up",
            Error::Safe(safe_core::Error::Open(_)) => "wrong-key",
            Error::Safe(safe_core::Error::ReadOnly(_)) => "read-only",
            Error::Safe(_) | Error::Io(_) => "internal",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Offline(e) => write!(f, "the place can't be reached: {e}"),
            Error::Place(e) => write!(f, "{e}"),
            Error::KeyChanged => write!(
                f,
                "the safe's password was changed on another machine: unlock with the new password"
            ),
            Error::CacheKey => write!(
                f,
                "this computer has changes saved under the old password: unlock with the old password once to bring them in"
            ),
            Error::Missing => write!(f, "there is no safe there yet"),
            Error::Exists => write!(f, "a safe is already there: open it instead"),
            Error::Safe(e) => write!(f, "{e}"),
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

impl From<safe_core::Error> for Error {
    fn from(e: safe_core::Error) -> Self {
        match e {
            safe_core::Error::Io(e) => Error::Io(e),
            e => Error::Safe(e),
        }
    }
}

/// SHA-256 of some bytes, as lowercase hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
