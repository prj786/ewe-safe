//! safe-core — the safe itself, with no network and no daemon.
//!
//! - [`safe`]: one KDBX file opened, read, edited and written (PLAN.md §5).
//! - [`item`]: Safe's two kinds of item and how they map onto KDBX fields.
//! - [`guard`]: what keepass-rs can write back, checked before any write
//!   (docs/SPIKE-0.md, C1).
//! - [`search`]: ranking items for what the user typed.
//! - [`generator`]: passwords and passphrases.
//! - [`kdf`]: the cost of a new safe's key derivation.
//! - [`otp`]: one-time codes (RFC 6238).
//! - [`atomic`]: writing a file so a crash leaves the old one or the new one.
//! - [`digest`]: what a safe holds, compared when a write is verified.
//! - [`merge`]: two copies of one safe made one (PLAN.md §7). keepass-rs's
//!   own merge loses data (SPIKE-0, M1/M2), so this one is Safe's.
//! - [`import`]: another password manager's export (1Password: 1PUX, CSV,
//!   `op`) turned into items (docs/IMPORT.md).
//! - [`passkey`]: passkeys in KeePassXC's fields, their keys, and what an
//!   authenticator answers (docs/FORMAT.md).

pub mod atomic;
pub mod digest;
pub mod generator;
pub mod guard;
pub mod import;
pub mod item;
pub mod kdf;
pub mod merge;
pub mod otp;
pub mod passkey;
pub mod safe;
pub mod search;

pub use item::{Draft, Field, Kind, Summary};
pub use safe::{Error, Safe};

/// The version every binary reports (`VERSION` at the repo root).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
