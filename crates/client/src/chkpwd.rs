//! The login password, checked the way PAM's pam_unix does it:
//! `/usr/bin/unix_chkpwd <user> nullok` with the password on stdin (NUL
//! ended); exit 0 = right. The daemon can't run that setuid helper
//! (`NoNewPrivileges` in its unit), so the CLI and the window check first,
//! then send the password. `EWE_SAFE_CHKPWD` names another program (tests;
//! the same variable the login unlock uses).

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = "/usr/bin/unix_chkpwd";

/// This user's login name (from the password database, not `$USER`).
fn user() -> Option<String> {
    // SAFETY: getpwuid_r fills `pw` and `buf` and nothing else
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        let r = libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        );
        if r != 0 || out.is_null() || pw.pw_name.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr(pw.pw_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// `Ok(true)` = the login password; `Err` = it couldn't be checked.
pub fn check(password: &str) -> Result<bool, String> {
    let helper = std::env::var("EWE_SAFE_CHKPWD").unwrap_or_else(|_| HELPER.to_string());
    let user = user().ok_or("this user has no name")?;
    let mut child = Command::new(&helper)
        .args([user.as_str(), "nullok"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{helper}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let mut line = Vec::with_capacity(password.len() + 1);
        line.extend_from_slice(password.as_bytes());
        line.push(0);
        let sent = stdin.write_all(&line);
        zeroize::Zeroize::zeroize(&mut line);
        sent.map_err(|e| format!("{helper}: {e}"))?;
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Ok(st.success()),
            Ok(None) if start.elapsed() < Duration::from_secs(15) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{helper} didn't answer"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_user_has_a_name() {
        assert!(super::user().is_some_and(|u| !u.is_empty()));
    }
}
