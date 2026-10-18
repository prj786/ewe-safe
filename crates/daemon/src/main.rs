//! `ewe-safed`: holds the unlocked safe, locks it, syncs it (PLAN.md §4,
//! §8). Its contract is docs/PROTOCOL.md.
//!
//! - [`server`]: the socket (activated or bound), peers, NDJSON, events.
//! - [`verbs`]: the verbs.
//! - [`daemon`]: the state — the sync engine, the unlocked safe, the
//!   snapshot — and its three locks.
//! - [`worker`]: edits to the place, the periodic exchange, the idle lock.
//! - [`logind`]: lock with the screen and before sleep.
//! - [`clip`]: copy, past the clipboard history, cleared later.
//! - [`config`]: paths, ewe.conf `[safe]`, `machine.json`.
//! - [`hygiene`]: no core dumps, no ptrace, password buffers out of swap.
//! - [`import`]: another password manager's export, or 1Password through
//!   `op`, added in one edit.
//! - [`resolve`]: the value a `safe://` reference names.
//! - [`passkey`]: the passkey verbs (list, create, get) for the browser.
//! - [`session`]: W, this computer's session key, for the login session
//!   (docs/SYSTEM.md).
//! - [`login`]: login unlock — the verbs, the unlock at login, `confirm`
//!   (docs/SYSTEM.md §2).
//! - [`carrier`]: Safe's unlock key in the login keyring, so Safe opens at
//!   login (docs/KEYRING.md).
//! - [`agent`]: the SSH agent on its own socket; [`sshkeys`]: the `ssh-*`
//!   verbs.
//! - [`cards`]: cards and addresses — their objects in `add` and `edit`,
//!   the browser's `fields` behind the card gate, `convert`.
//! - [`keyring`]: Safe as the keyring (`org.freedesktop.secrets`, the
//!   `keyring-*` verbs; docs/KEYRING.md).

mod agent;
mod cards;
mod carrier;
mod clip;
mod config;
mod daemon;
mod hygiene;
mod import;
mod keyring;
mod login;
mod logind;
mod passkey;
mod resolve;
mod server;
mod session;
mod sshkeys;
mod verbs;
mod worker;

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;

/// One line to stderr (the journal under systemd). Never a value, a title or
/// a username.
pub fn log(msg: &str) {
    eprintln!("ewe-safed: {msg}");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("--version") => {
            println!(
                "{}",
                json!({"ok": true, "version": safe_core::VERSION, "protocol": 1})
            );
            return;
        }
        Some(_) => {
            eprintln!("usage: ewe-safed [--version] — talk to it with ewe-safe");
            std::process::exit(2);
        }
    }
    hygiene::harden();
    let paths = config::Paths::from_env();
    let (listener, bound) = match server::listen(&paths) {
        Ok(x) => x,
        Err(e) => {
            log(&e);
            std::process::exit(1);
        }
    };
    let d = Arc::new(daemon::Daemon::new(paths));
    d.start();
    worker::spawn(d.clone());
    logind::spawn(d.clone());
    agent::spawn(d.clone());
    keyring::spawn(d.clone());
    carrier::spawn(d.clone());
    on_signals(d.clone(), bound.clone());
    log(&format!(
        "ready, protocol 1 ({})",
        if bound.is_some() {
            "own socket"
        } else {
            "socket activation"
        }
    ));
    server::serve(listener, d);
}

/// SIGTERM (logout, `systemctl stop`), SIGINT, SIGHUP: lock and leave.
fn on_signals(d: Arc<daemon::Daemon>, bound: Option<PathBuf>) {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let mut signals = match signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP]) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("no signal handling ({e})"));
            return;
        }
    };
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            d.lock("logout");
            if let Some(p) = bound {
                let _ = std::fs::remove_file(p);
            }
            agent::cleanup();
            std::process::exit(0);
        }
    });
}
