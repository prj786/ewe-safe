//! What a process holding secrets owes the machine (PLAN.md §8): no core
//! dumps, no same-uid ptrace, and secrets kept out of swap where it's cheap.

/// Before anything secret exists: not dumpable (no core file, no ptrace by
/// another process of this user) and no core size.
pub fn harden() {
    // SAFETY: plain syscalls on this process with constant arguments
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
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
