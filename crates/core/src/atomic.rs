//! Write a file so that a crash leaves either the old bytes or the new ones:
//! a temp file in the same folder, fsync, rename over, fsync the folder.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Replace `path` with `bytes`. The file is created `0600`.
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));

    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written?;
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("safe-core-atomic-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[test]
    fn replaces_and_leaves_no_temp() {
        let d = scratch("replace");
        let p = d.join("passwords.kdbx");
        write(&p, b"one").expect("first write");
        write(&p, b"two").expect("second write");
        assert_eq!(fs::read(&p).expect("read"), b"two");
        let names: Vec<_> = fs::read_dir(&d)
            .expect("list")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names.len(), 1, "only the file itself: {names:?}");
        let mode = fs::metadata(&p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_failed_write_keeps_the_old_file() {
        let d = scratch("fail");
        let p = d.join("passwords.kdbx");
        write(&p, b"old").expect("first write");
        // a stale temp of the same name makes create_new fail
        fs::write(
            d.join(format!(".passwords.kdbx.tmp-{}", std::process::id())),
            b"x",
        )
        .expect("plant temp");
        assert!(write(&p, b"new").is_err());
        assert_eq!(fs::read(&p).expect("read"), b"old");
        let _ = fs::remove_dir_all(&d);
    }
}
