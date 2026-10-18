//! Login unlock (docs/SYSTEM.md §2): the safe's master password is sealed on
//! this computer under **W**, and W under the login password. Typing the
//! login password (in Safe's unlock window) re-derives the KEK, opens
//! `login.key` → W, opens `master.wrap` → the master password, and runs the
//! normal unlock. Nothing here logs a secret.
//!
//! **How W reaches the daemon at login.** This release does *not* ship a PAM
//! module (that part of SYSTEM.md §2 is parked for the owner's review,
//! `.wt/parked-pam/`). Instead W rides in gnome-keyring's `login` collection,
//! which `pam_gnome_keyring` already unlocks silently at login. Stream K owns
//! that gnome-keyring client and sets [`ON_ENABLE`]/[`ON_DISABLE`] to carry W
//! in and out, and at start puts W into [`Daemon::session`] and calls
//! [`unlock_from_session`]. This module writes no D-Bus.
//!
//! **W lives for the login session** (base `session.rs`): locking the safe
//! keeps it; the daemon stopping (logout) drops it.
//!
//! **The master password, while the safe is unlocked**, is held here too
//! (base already keeps it inside the `DatabaseKey`; this is the same bytes,
//! zeroized), so `login-enable` and the re-seal on every master unlock can
//! seal `master.wrap` without asking again.

use std::sync::{Arc, OnceLock};

use safe_login::SessionKey;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::daemon::{Daemon, Fail, lk};
use crate::log;

type Args = Map<String, Value>;

/// 5 wrong login-password unlocks in a row lock login unlock until the master
/// password is used once (docs/SYSTEM.md §2).
const MAX_TRIES: u32 = 5;

/// Stream K wires these at daemon start, to carry W in gnome-keyring's
/// `login` collection (so the next login opens the safe with no password).
/// `login-enable` stores W; `login-disable` drops it. Left unset (K not in
/// the build), login unlock still works through Safe's own window.
pub static ON_ENABLE: OnceLock<fn(&Daemon, &SessionKey)> = OnceLock::new();
pub static ON_DISABLE: OnceLock<fn(&Daemon)> = OnceLock::new();

/// Login unlock's state beside W (that is base `session.rs`): the failed-try
/// count and the held master password.
#[derive(Default)]
pub struct Login {
    tries: std::sync::Mutex<u32>,
    /// The master password while the safe is unlocked (for sealing
    /// `master.wrap`); cleared on lock.
    master: std::sync::Mutex<Option<Zeroizing<String>>>,
}

impl Login {
    fn tries(&self) -> u32 {
        *lk(&self.tries)
    }

    fn reset_tries(&self) {
        *lk(&self.tries) = 0;
    }

    /// The master password while unlocked, if we hold it.
    pub fn master(&self) -> Option<Zeroizing<String>> {
        lk(&self.master).clone()
    }

    pub fn hold_master(&self, master: &Zeroizing<String>) {
        *lk(&self.master) = Some(master.clone());
    }

    /// The safe locked: the held master password never outlives it (W does).
    pub fn on_lock(&self) {
        *lk(&self.master) = None;
    }
}

/// Login unlock is on when `master.wrap` is present on this computer.
fn enabled(d: &Daemon) -> bool {
    d.paths.master_wrap().exists()
}

impl Daemon {
    /// After any successful master-password unlock (also `init`, `open`,
    /// `passwd`): hold the master password for re-sealing, clear the
    /// too-many-tries lock, and — while login unlock is on and W is in memory
    /// — re-seal `master.wrap` under W, so a master password changed on
    /// another machine is sealed again here (docs/SYSTEM.md §2).
    pub fn after_master_unlock(&self, master: &Zeroizing<String>) {
        self.login.hold_master(master);
        self.login.reset_tries();
        if enabled(self)
            && let Some(w) = self.session.key()
            && let Err(e) = safe_login::seal_master(&self.paths.master_wrap(), &w, master)
        {
            log(&format!("login: couldn't refresh master.wrap: {e}"));
        }
    }
}

/// `login-status`: `enabled`, `session_open` (W in memory).
pub fn status(d: &Daemon) -> Value {
    json!({
        "enabled": enabled(d),
        "session_open": d.session.is_open(),
    })
}

/// `login-enable {login_password, password?}`: make or open `login.key` → W,
/// seal `master.wrap` under it, and hand W to gnome-keyring (stream K's hook)
/// so the next login opens the safe with no password. The caller (the CLI,
/// the window) checked the login password with `unix_chkpwd` first; when the
/// safe is locked it also passes the master password.
pub fn enable(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    if !d.is_set_up() {
        return Err(Fail::not_set_up());
    }
    let login_password =
        take(a, "login_password").ok_or_else(|| Fail::bad("The login password is missing."))?;
    // the safe's master password: held while unlocked, else unlock with it now
    let master = match d.login.master() {
        Some(m) => m,
        None => {
            let master = take(a, "password").ok_or_else(Fail::locked)?;
            d.unlock(&master)?;
            d.login.master().unwrap_or(master)
        }
    };
    let w = crate::session::open_or_create(&d.paths.login_key(), login_password.as_bytes(), true)
        .map_err(login_fail)?;
    safe_login::seal_master(&d.paths.master_wrap(), &w, &master).map_err(login_fail)?;
    d.session.set(w.clone());
    d.login.reset_tries();
    if let Some(carry) = ON_ENABLE.get() {
        carry(d, &w);
    }
    log("login unlock enabled");
    Ok(json!({"enabled": true}))
}

/// `login-disable`: delete `master.wrap` and drop W from gnome-keyring
/// (stream K's hook). `login.key` stays while the keyring (stream K) still
/// uses it; otherwise it goes too.
pub fn disable(d: &Arc<Daemon>) -> Result<Value, Fail> {
    safe_login::remove(&d.paths.master_wrap()).map_err(Fail::from)?;
    if !d.paths.keyring_marker().exists() {
        safe_login::remove(&d.paths.login_key()).map_err(Fail::from)?;
    }
    if let Some(drop_w) = ON_DISABLE.get() {
        drop_w(d);
    }
    log("login unlock disabled");
    Ok(json!({"enabled": false}))
}

/// `unlock {login_password}`: the login password opens `login.key` → W →
/// `master.wrap` → the master password → the normal unlock.
pub fn unlock(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    if !d.is_set_up() {
        return Err(Fail::not_set_up());
    }
    if let Some(n) = d.unlocked_items() {
        return Ok(json!({"items": n}));
    }
    if !enabled(d) {
        return Err(not_enabled());
    }
    if d.login.tries() >= MAX_TRIES {
        return Err(too_many_tries());
    }
    let login_password =
        take(a, "login_password").ok_or_else(|| Fail::bad("The login password is missing."))?;
    let w = match safe_login::open_key(&d.paths.login_key(), login_password.as_bytes()) {
        Ok(w) => w,
        Err(safe_login::Error::Missing) => return Err(not_enabled()),
        Err(safe_login::Error::WrongKey) => {
            let mut t = lk(&d.login.tries);
            *t += 1;
            let over = *t >= MAX_TRIES;
            drop(t);
            return Err(if over {
                too_many_tries()
            } else {
                Fail::new("wrong-key", "That login password doesn't open Safe.")
            });
        }
        Err(e) => return Err(login_fail(e)),
    };
    let master = safe_login::open_master(&d.paths.master_wrap(), &w).map_err(|e| match e {
        safe_login::Error::WrongKey => Fail::new(
            "key-changed",
            "Safe's master password changed. Unlock with it once.",
        )
        .hint("ewe-safe unlock"),
        other => login_fail(other),
    })?;
    d.session.set(w);
    let master = Zeroizing::new(master.to_string());
    match d.unlock(&master) {
        Ok(n) => {
            d.login.reset_tries();
            Ok(json!({"items": n}))
        }
        // master.wrap opened, but its master no longer opens the safe (the
        // master password changed on another machine): drop master.wrap and
        // ask for the new one (docs/SYSTEM.md §2)
        Err(f) if f.code == "wrong-key" => {
            let _ = safe_login::remove(&d.paths.master_wrap());
            Err(Fail::new(
                "key-changed",
                "Safe's master password changed. Unlock with it once.",
            )
            .hint("ewe-safe unlock"))
        }
        Err(f) => Err(f),
    }
}

/// Open the safe with the W already in [`Daemon::session`] (stream K put it
/// there from gnome-keyring's `login` collection at login) and `master.wrap`,
/// with no password. The caller honours `[safe] unlock_at_login` and runs
/// this off the login path (it must not hold anything up for the network).
// stream K calls this at daemon start; the merge drops this allow
#[allow(dead_code)]
pub fn unlock_from_session(d: &Arc<Daemon>) -> Result<usize, Fail> {
    if !d.is_set_up() {
        return Err(Fail::not_set_up());
    }
    if let Some(n) = d.unlocked_items() {
        return Ok(n);
    }
    if !enabled(d) {
        return Err(not_enabled());
    }
    let w = d
        .session
        .key()
        .ok_or_else(|| Fail::new("not-enabled", "Safe's session key isn't open yet."))?;
    let master = safe_login::open_master(&d.paths.master_wrap(), &w).map_err(|e| match e {
        safe_login::Error::WrongKey => Fail::new(
            "key-changed",
            "Safe's master password changed. Unlock with it once.",
        ),
        other => login_fail(other),
    })?;
    let master = Zeroizing::new(master.to_string());
    d.unlock(&master)
}

/// `confirm {password | login_password}`: a fresh presence check for a
/// sensitive fill (a card, docs/SYSTEM.md §4). The safe must be unlocked;
/// either the master password or the login password is accepted.
pub fn confirm(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    if d.unlocked_items().is_none() {
        return Err(Fail::locked());
    }
    let ok = if let Some(login_password) = take(a, "login_password") {
        safe_login::open_key(&d.paths.login_key(), login_password.as_bytes()).is_ok()
    } else if let Some(password) = take(a, "password") {
        match d.login.master() {
            Some(master) => constant_time_eq(master.as_bytes(), password.as_bytes()),
            // the safe is unlocked but we never captured the master (unlocked
            // before this daemon ran): fall back to deriving the key
            None => safe_core::safe::key(&password, None)
                .ok()
                .is_some_and(|k| d.key_opens(&k)),
        }
    } else {
        return Err(Fail::bad("A password is needed to confirm."));
    };
    if !ok {
        return Err(Fail::new("wrong-key", "That password is wrong."));
    }
    d.session.confirm();
    d.mark_use();
    Ok(json!({"confirmed_for": d.session.confirmed_for()}))
}

/// `not-enabled`: login unlock isn't set up on this computer.
fn not_enabled() -> Fail {
    Fail::new("not-enabled", "Login unlock isn't set up on this computer.")
        .hint("Turn it on in Settings, or: ewe-safe login enable")
}

/// `too-many-tries`: too many wrong login passwords; the master password
/// clears it.
fn too_many_tries() -> Fail {
    Fail::new(
        "too-many-tries",
        "Too many wrong login passwords. Unlock with your master password once.",
    )
    .hint("ewe-safe unlock")
}

fn login_fail(e: safe_login::Error) -> Fail {
    match e {
        safe_login::Error::Missing => not_enabled(),
        safe_login::Error::WrongKey => {
            Fail::new("wrong-key", "That login password doesn't open Safe.")
        }
        other => Fail::new("internal", format!("Login unlock: {other}")),
    }
}

fn take(a: &mut Args, k: &str) -> Option<Zeroizing<String>> {
    match a.remove(k) {
        Some(Value::String(s)) => Some(Zeroizing::new(s)),
        _ => None,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
