//! safe-secrets — Safe as the keyring (docs/SYSTEM.md §3, docs/KEYRING.md):
//! the freedesktop Secret Service API 0.2 (`org.freedesktop.secrets`) on
//! the session bus, the app secrets kept in `keyring.safe` under this
//! computer's key W (docs/SYSTEM.md §2), never synced.
//!
//! - [`service`]: the D-Bus objects — Service, Collection, Item, Session
//!   (`plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`), Prompt — and
//!   [`Keyring`], the daemon's handle on them.
//! - [`store`]: the keyring's files (`keyring.safe`, sealed; `keyring.index`,
//!   what a locked keyring may show: which items exist, attributes hashed).
//! - [`crypto`]: the transfer encryption.
//! - [`client`]: talking to the Secret Service that runs now through its
//!   own API (import, list).
//! - [`repair`]: `keyring repair`, the fix for the prompt at every start
//!   (the `default` alias naming a second keyring).
//! - [`carrier`]: W kept in the `login` keyring PAM already unlocks.
//!
//! W comes from a [`KeySource`] (the daemon's session; a stand-in in the
//! tests), so this crate builds and is tested without the daemon.

pub mod carrier;
pub mod client;
pub mod crypto;
pub mod repair;
pub mod service;
pub mod store;

pub use carrier::{carrier_delete, carrier_fetch, carrier_store};
pub use service::{Asking, ItemInfo, KeySource, Keyring, NAME, Secret};
pub use store::{Files, Incoming, Merged};
