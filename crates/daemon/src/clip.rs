//! Copying a value: `wl-copy`, past the clipboard plugin's history gate
//! (the `ewe-clip-skip` marker its `clip-store.sh` honours — `wl-copy`
//! can't offer the `x-kde-passwordManagerHint` type next to the text), and
//! cleared later only if the clipboard still holds it. Only a hash of the
//! value is kept for that check.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::config;
use crate::daemon::{Daemon, Fail, lk};
use crate::log;

pub struct Job {
    hash: Vec<u8>,
    display: Option<String>,
    serial: u64,
}

static SERIAL: AtomicU64 = AtomicU64::new(0);

/// Put `value` on the clipboard for `clear_after` seconds (0 = keep).
pub fn copy(
    d: &Arc<Daemon>,
    value: &Zeroizing<String>,
    display: Option<String>,
    clear_after: u64,
) -> Result<(), Fail> {
    let display = display.or_else(|| std::env::var("WAYLAND_DISPLAY").ok());
    // one copy passes the history gate, then the marker is gone
    let _ = std::fs::write(d.paths.runtime.join("ewe-clip-skip"), "password");
    let mut cmd = Command::new("wl-copy");
    if let Some(v) = &display {
        cmd.env("WAYLAND_DISPLAY", v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Fail::new("internal", format!("wl-copy isn't available ({e})")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(value.as_bytes());
    }
    let ok = child.wait().map(|s| s.success()).unwrap_or(false);
    if !ok {
        return Err(Fail::new(
            "internal",
            "wl-copy failed: is there a Wayland display?",
        ));
    }
    let serial = SERIAL.fetch_add(1, Ordering::SeqCst) + 1;
    *lk(&d.clip) = Some(Job {
        hash: Sha256::digest(value.as_bytes()).to_vec(),
        display,
        serial,
    });
    if clear_after > 0 {
        let d = d.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(clear_after));
            let mine = lk(&d.clip).as_ref().is_some_and(|j| j.serial == serial);
            if mine {
                clear_if_ours(&d);
            }
        });
    }
    Ok(())
}

/// Clear the clipboard if it still holds what Safe put there (on a timer,
/// and when the safe locks). Something copied since is left alone.
pub fn clear_if_ours(d: &Daemon) {
    let Some(job) = lk(&d.clip).take() else {
        return;
    };
    let env: Vec<(String, String)> = job
        .display
        .iter()
        .map(|v| ("WAYLAND_DISPLAY".to_string(), v.clone()))
        .collect();
    let limit = Duration::from_secs(5);
    let Some(mut now) = config::run_env("wl-paste", &["--no-newline"], &env, limit) else {
        return;
    };
    let same = Sha256::digest(&now).to_vec() == job.hash;
    now.zeroize();
    if same && config::run_env("wl-copy", &["--clear"], &env, limit).is_none() {
        log("could not clear the clipboard");
    }
}
