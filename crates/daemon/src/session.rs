//! W, this computer's session key (docs/SYSTEM.md §2), in memory for the
//! login session: set when a login password opens `login.key` (the
//! login keyring at login, the unlock window), kept while the safe locks and
//! unlocks, gone when the daemon stops (logout). The keyring (§3) reads it;
//! nothing writes it to disk.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use safe_login::SessionKey;

use crate::daemon::lk;

/// How long a confirm (docs/SYSTEM.md §4: filling a card) lasts.
pub const CONFIRM_FOR: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct Session {
    key: Mutex<Option<SessionKey>>,
    arrived: Condvar,
    /// The user typed a password to confirm (`confirm`); cleared on lock.
    confirmed_until: Mutex<Option<Instant>>,
}

/// W from `login.key` opened with `login_password`; with `create`, a new
/// W (and a new `login.key`) when there is none yet. Login unlock's
/// `enable` and the keyring's `adopt` come here.
pub fn open_or_create(
    path: &std::path::Path,
    login_password: &[u8],
    create: bool,
) -> Result<SessionKey, safe_login::Error> {
    match safe_login::open_key(path, login_password) {
        Err(safe_login::Error::Missing) if create => {
            safe_login::create_key(path, login_password, safe_login::Kdf::from_env())
        }
        other => other,
    }
}

impl Session {
    pub fn key(&self) -> Option<SessionKey> {
        lk(&self.key).clone()
    }

    pub fn is_open(&self) -> bool {
        lk(&self.key).is_some()
    }

    /// W is known: wake everyone waiting for it.
    pub fn set(&self, w: SessionKey) {
        *lk(&self.key) = Some(w);
        self.arrived.notify_all();
    }

    /// A password was typed just now to confirm a sensitive use.
    pub fn confirm(&self) {
        *lk(&self.confirmed_until) = Some(Instant::now() + CONFIRM_FOR);
    }

    /// Seconds left of the last confirm, 0 = none (or expired).
    pub fn confirmed_for(&self) -> u64 {
        lk(&self.confirmed_until)
            .map(|t| t.saturating_duration_since(Instant::now()).as_secs())
            .unwrap_or(0)
    }

    pub fn is_confirmed(&self) -> bool {
        lk(&self.confirmed_until).is_some_and(|t| Instant::now() < t)
    }

    /// The safe locked: a confirm never outlives it.
    pub fn clear_confirm(&self) {
        *lk(&self.confirmed_until) = None;
    }

    /// W, waiting up to `timeout` for it to arrive (the keyring's prompt
    /// gives the key from the login keyring a moment before it asks the user).
    pub fn wait(&self, timeout: Duration) -> Option<SessionKey> {
        let deadline = Instant::now() + timeout;
        let mut g = lk(&self.key);
        while g.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            g = match self.arrived.wait_timeout(g, left) {
                Ok((g, _)) => g,
                Err(p) => p.into_inner().0,
            };
        }
        g.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn wait_returns_when_w_arrives_and_times_out_without_it() {
        let s = Arc::new(Session::default());
        assert!(s.wait(Duration::from_millis(20)).is_none());
        let w = SessionKey::generate();
        let s2 = s.clone();
        let w2 = w.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            s2.set(w2);
        });
        assert_eq!(s.wait(Duration::from_secs(5)), Some(w));
        t.join().unwrap();
        assert!(s.is_open());
    }

    #[test]
    fn a_confirm_lasts_until_cleared() {
        let s = Session::default();
        assert!(!s.is_confirmed());
        s.confirm();
        assert!(s.is_confirmed() && s.confirmed_for() > 290);
        s.clear_confirm();
        assert!(!s.is_confirmed() && s.confirmed_for() == 0);
    }

    #[test]
    fn open_or_create_makes_one_key_and_then_opens_it() {
        let d = std::env::temp_dir().join(format!("ewe-safe-session-{}", std::process::id()));
        let p = d.join(safe_login::LOGIN_KEY);
        // SAFETY: the only test that reads this variable
        unsafe { std::env::set_var("EWE_SAFE_LOGIN_KDF", "64,1,1") };
        assert!(matches!(
            open_or_create(&p, b"pw", false),
            Err(safe_login::Error::Missing)
        ));
        let w = open_or_create(&p, b"pw", true).unwrap();
        assert_eq!(open_or_create(&p, b"pw", true).unwrap(), w);
        assert!(matches!(
            open_or_create(&p, b"other", true),
            Err(safe_login::Error::WrongKey)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }
}
