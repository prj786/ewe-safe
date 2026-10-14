//! The screen locks and the machine sleeps: logind's `LockedHint` on the
//! user's session (the shell's Lock.qml sets it) and `PrepareForSleep`.
//! Without a system bus there is no trigger; that is logged once.

use std::sync::Arc;

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

use crate::daemon::Daemon;
use crate::log;

const LOGIND: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";

pub fn spawn(d: Arc<Daemon>) {
    if std::env::var_os("EWE_SAFE_NO_LOGIND").is_some() {
        return;
    }
    std::thread::spawn(move || {
        // a test points this at a private bus with a stand-in logind
        let conn = match std::env::var("EWE_SAFE_LOGIND_BUS") {
            Ok(addr) => {
                zbus::blocking::connection::Builder::address(addr.as_str()).and_then(|b| b.build())
            }
            Err(_) => Connection::system(),
        };
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                log(&format!(
                    "no system bus ({e}): the safe won't lock with the screen or before sleep"
                ));
                return;
            }
        };
        let manager = match Proxy::new(&conn, LOGIND, MANAGER_PATH, MANAGER) {
            Ok(m) => m,
            Err(e) => {
                log(&format!(
                    "no logind ({e}): the safe won't lock with the screen or before sleep"
                ));
                return;
            }
        };
        let sleeper = d.clone();
        let m = manager.clone();
        std::thread::spawn(move || {
            let Ok(signals) = m.receive_signal("PrepareForSleep") else {
                log("can't follow PrepareForSleep");
                return;
            };
            for msg in signals {
                let going = msg.body().deserialize::<bool>().unwrap_or(false);
                if going && sleeper.settings().lock_on_sleep {
                    sleeper.lock("sleep");
                }
            }
        });
        let Some(path) = session(&conn, &manager) else {
            log("no logind session for this user: the safe won't lock with the screen");
            return;
        };
        let session = match Proxy::new(&conn, LOGIND, path, "org.freedesktop.login1.Session") {
            Ok(s) => s,
            Err(e) => {
                log(&format!("can't follow the session ({e})"));
                return;
            }
        };
        for change in session.receive_property_changed::<bool>("LockedHint") {
            if matches!(change.get(), Ok(true)) && d.settings().lock_on_screen_lock {
                d.lock("screen");
            }
        }
    });
}

/// The session to follow: `XDG_SESSION_ID` when the daemon runs inside it,
/// else the user's graphical session (logind's `Display`) — a user
/// service belongs to no session of its own.
fn session(conn: &Connection, manager: &Proxy<'_>) -> Option<OwnedObjectPath> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID")
        && let Ok(p) = manager.call::<_, _, OwnedObjectPath>("GetSession", &(id.as_str(),))
    {
        return Some(p);
    }
    // SAFETY: getuid has no failure mode
    let uid = unsafe { libc::getuid() };
    let user: OwnedObjectPath = manager.call("GetUser", &(uid,)).ok()?;
    let u = Proxy::new(conn, LOGIND, user, "org.freedesktop.login1.User").ok()?;
    let (id, path): (String, OwnedObjectPath) = u.get_property("Display").ok()?;
    (!id.is_empty()).then_some(path)
}
