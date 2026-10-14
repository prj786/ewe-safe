//! The ewe account's Nextcloud: credentials from a fake `ewe-cloud` on
//! PATH. One test in its own binary, since it changes PATH.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::*;
use safe_store::{Place, Saved, Syncer, WebDav};

#[test]
fn nextcloud_signs_in_through_ewe_cloud() {
    let mock = Mock::start();
    let d = scratch("ewe-cloud");
    let bin = d.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let script = bin.join("ewe-cloud");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  webdav-url) echo '{}' ;;\n  token) echo '{{\"ok\": true, \"token\": \"{PASS}\", \"server\": \"x\", \"user\": \"{USER}\"}}' ;;\nesac\n",
            mock.base()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // SAFETY: this binary has one test, so nothing else reads the
    // environment while it changes
    unsafe { std::env::set_var("PATH", path) };

    let place = WebDav::nextcloud("ewe/safe/passwords.kdbx").insecure_loopback(true);
    assert_eq!(place.info().kind, "nextcloud");
    let mut sync = Syncer::new(Box::new(place), d.join("state"), "a").expect("syncer");
    let mut s = new_safe();
    s.add(&login("Nextcloud", "sam")).expect("add");
    assert!(matches!(
        sync.create(&mut s, &key()).expect("create"),
        Saved::Synced { .. }
    ));
    assert!(mock.file(FILE).is_some());

    // signed out: a sign-in error, never a hang
    std::fs::write(
        &script,
        "#!/bin/sh\necho '{\"ok\": false, \"error\": \"not-signed-in\"}'\nexit 1\n",
    )
    .expect("script");
    let place = WebDav::nextcloud("ewe/safe/passwords.kdbx").insecure_loopback(true);
    let e = place.fetch(None).expect_err("signed out");
    assert_eq!(e.code(), "place-error");
    assert!(e.to_string().contains("ewe-sync"));
}
