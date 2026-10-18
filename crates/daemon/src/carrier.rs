//! The carrier glue (docs/KEYRING.md, docs/SYSTEM.md §2 as built): W rides in
//! gnome-keyring's `login` keyring, which the greeter already unlocks with the
//! login password, so Safe opens at login with no prompt and no PAM code of
//! its own. `login-enable` stores W there, `login-disable` drops it, and at
//! start the daemon takes it back: W into [`Daemon::session`], then — with
//! `[safe] unlock_at_login` — the safe opens in the background.
//!
//! Nothing here ever prompts or starts a keyring (`safe_secrets::carrier`): a
//! locked or missing `login` keyring just means "type your password later".

use std::sync::Arc;
use std::time::Duration;

use safe_login::SessionKey;

use crate::daemon::Daemon;
use crate::log;
use crate::login;

/// When to look for W after the daemon starts: at login the shell may wake
/// the daemon a moment before gnome-keyring has opened `login`.
const TRIES: [u64; 5] = [0, 2, 5, 10, 20];

fn machine() -> String {
    safe_store::machine_name()
}

/// Put W in `login`, unless it is there already (a login-password unlock
/// calls this every time; the keyring file is only written when it changes).
fn store(_d: &Daemon, w: &SessionKey) {
    if safe_secrets::carrier::carrier_fetch(&machine()).as_ref() == Some(w) {
        return;
    }
    match safe_secrets::carrier::carrier_store(w, &machine()) {
        Ok(()) => log("login unlock: the key is in the login keyring"),
        Err(e) => log(&format!(
            "login unlock: the login keyring can't keep the key ({e}); Safe asks for the login password instead"
        )),
    }
}

fn drop_it(_d: &Daemon) {
    if let Err(e) = safe_secrets::carrier::carrier_delete(&machine()) {
        log(&format!(
            "login unlock: the key stays in the login keyring ({e})"
        ));
    }
}

/// Wire the hooks, then (login unlock on) take W back from `login`.
pub fn spawn(d: Arc<Daemon>) {
    let _ = login::ON_ENABLE.set(store);
    let _ = login::ON_DISABLE.set(drop_it);
    if !d.paths.master_wrap().exists() {
        return;
    }
    std::thread::spawn(move || {
        let mut waited = 0;
        for at in TRIES {
            std::thread::sleep(Duration::from_secs(at - waited));
            waited = at;
            if d.session.is_open() {
                return;
            }
            let Some(w) = safe_secrets::carrier::carrier_fetch(&machine()) else {
                continue;
            };
            d.session.set(w);
            if !d.settings().unlock_at_login {
                log("login unlock: the key is back; the safe waits (unlock_at_login is off)");
                return;
            }
            match login::unlock_from_session(&d) {
                Ok(_) => log("unlocked at login"),
                Err(f) => log(&format!("not unlocked at login: {}", f.message)),
            }
            return;
        }
    });
}
