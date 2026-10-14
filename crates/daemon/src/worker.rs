//! The worker: takes edits to the place, exchanges with it every few
//! minutes, re-reads the settings, and locks a safe left unused.

use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::daemon::{Daemon, Wake, rd};

const TICK: Duration = Duration::from_secs(5);
const SYNC_EVERY: Duration = Duration::from_secs(5 * 60);
const SETTINGS_EVERY: Duration = Duration::from_secs(60);

fn secs_env(var: &str) -> Option<Duration> {
    std::env::var(var)
        .ok()?
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

pub fn spawn(d: Arc<Daemon>) {
    let (tx, rx) = mpsc::channel();
    d.set_wake(tx);
    // test switches: a shorter exchange period and idle lock
    let sync_every = secs_env("EWE_SAFE_SYNC_SECONDS").unwrap_or(SYNC_EVERY);
    let idle_override = secs_env("EWE_SAFE_IDLE_SECONDS");
    std::thread::spawn(move || {
        let mut last_sync = Instant::now();
        let mut last_settings = Instant::now();
        loop {
            match rx.recv_timeout(TICK.min(sync_every)) {
                Ok(Wake::Push) => {
                    // a burst of edits is one exchange
                    while rx.try_recv().is_ok() {}
                    d.sync_once();
                    last_sync = Instant::now();
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if last_settings.elapsed() >= SETTINGS_EVERY {
                d.reload_settings();
                last_settings = Instant::now();
            }
            let idle = idle_override.or_else(|| match d.settings().lock_after_minutes {
                0 => None,
                m => Some(Duration::from_secs(m * 60)),
            });
            if let Some(limit) = idle
                && !rd(&d.snap).locked
                && d.idle_for() >= limit
            {
                d.lock("idle");
            }
            if d.is_set_up() && last_sync.elapsed() >= sync_every {
                d.sync_once();
                last_sync = Instant::now();
            }
        }
    });
}
