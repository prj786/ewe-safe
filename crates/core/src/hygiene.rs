//! What a process holding secrets owes the machine (PLAN.md §8): no core
//! dumps, no same-uid ptrace, and secrets kept out of swap where it's cheap.
//! The daemon and the CLI share it.

use std::sync::OnceLock;

/// The core-size limit [`harden_soft`] found, for a program the CLI
/// becomes (`ewe-safe run`).
static FOUND: OnceLock<libc::rlimit> = OnceLock::new();

fn not_dumpable() {
    // SAFETY: a plain syscall on this process with constant arguments
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
}

/// The daemon's, before anything secret exists: not dumpable (no core file,
/// no ptrace by another process of this user) and no core size, soft and
/// hard.
pub fn harden() {
    not_dumpable();
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit on this process with a valid rlimit
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
}

/// The CLI's: the same, but only the soft limit drops (systemd-coredump
/// honours it), so [`restore_core`] can give a program `run` becomes its
/// own limit back. Not dumpable resets by itself at exec.
pub fn harden_soft() {
    not_dumpable();
    let mut now = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills a valid rlimit; setrlimit reads one
    unsafe {
        if libc::getrlimit(libc::RLIMIT_CORE, &mut now) != 0 {
            return;
        }
        let _ = FOUND.set(now);
        let soft = libc::rlimit {
            rlim_cur: 0,
            rlim_max: now.rlim_max,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &soft);
    }
}

/// Just before exec: the core limit [`harden_soft`] found, back.
pub fn restore_core() {
    if let Some(found) = FOUND.get() {
        // SAFETY: setrlimit on this process with a valid rlimit
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, found) };
    }
}

/// Best effort: keep a buffer out of swap while it holds a password. The
/// 64 MiB of key derivation and keepass-rs's own copies are not covered
/// (the default memlock limit is small).
pub struct Pinned<'a>(&'a [u8]);

impl<'a> Pinned<'a> {
    pub fn new(b: &'a [u8]) -> Pinned<'a> {
        if !b.is_empty() {
            // SAFETY: the range is a live borrow for the guard's lifetime
            unsafe { libc::mlock(b.as_ptr().cast(), b.len()) };
        }
        Pinned(b)
    }
}

impl Drop for Pinned<'_> {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            // SAFETY: the same range mlock was given
            unsafe { libc::munlock(self.0.as_ptr().cast(), self.0.len()) };
        }
    }
}
