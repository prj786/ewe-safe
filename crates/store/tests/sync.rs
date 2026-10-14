//! The sync engine against a mock WebDAV server (PLAN.md §7).

mod common;

use std::time::Duration;

use common::*;
use safe_store::{Error, Saved};

fn synced(s: &Saved) -> bool {
    matches!(s, Saved::Synced { .. })
}

#[test]
fn create_load_save_round_trip() {
    let mock = Mock::start();
    let d = scratch("round-trip");
    let mut a = machine(&mock, d.join("a"), "laptop");
    let mut sa = new_safe();
    sa.add(&login("Discord", "sam")).expect("add");
    assert!(synced(&a.sync.create(&mut sa, &key()).expect("create")));
    assert!(mock.file(FILE).is_some(), "the safe is in the place");
    assert_eq!(a.sync.status().state, "in-sync");
    assert_eq!(a.sync.status().by_machine.as_deref(), Some("laptop"));

    // a second machine opens it
    let mut b = machine(&mock, d.join("b"), "desktop");
    let (mut sb, loaded) = b.sync.load(&key()).expect("load");
    assert!(!loaded.offline);
    assert_eq!(titles(&sb), ["Discord"]);
    sb.add(&login("Mail", "sam@example.org")).expect("add");
    assert!(synced(&b.sync.save(&mut sb, &key()).expect("save")));
    assert_eq!(b.sync.status().by_machine.as_deref(), Some("desktop"));

    // the first machine picks it up without uploading anything
    let puts = mock.count("PUT");
    let polled = a.sync.poll(Some((&mut sa, &key()))).expect("poll");
    assert!(polled.changed && !polled.uploaded);
    assert_eq!(titles(&sa), ["Discord", "Mail"]);
    assert_eq!(mock.count("PUT"), puts, "taking theirs uploads nothing");
    assert_eq!(a.sync.status().by_machine.as_deref(), Some("desktop"));

    // and polling again is a 304
    let polled = a.sync.poll(Some((&mut sa, &key()))).expect("poll");
    assert!(!polled.changed && !polled.uploaded);
}

#[test]
fn a_local_save_waits_for_the_next_poll() {
    let mock = Mock::start();
    let d = scratch("save-local");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    a.sync.create(&mut sa, &key()).expect("create");
    let puts = mock.count("PUT");
    sa.add(&login("Later", "x")).expect("add");
    a.sync.save_local(&mut sa, &key()).expect("save_local");
    assert_eq!(mock.count("PUT"), puts, "nothing went to the place yet");
    assert_eq!(a.sync.status().state, "pending");
    let polled = a.sync.poll(Some((&mut sa, &key()))).expect("poll");
    assert!(polled.uploaded);
    assert_eq!(a.sync.status().state, "in-sync");
    let mut b = machine(&mock, d.join("b"), "b");
    let (sb, _) = b.sync.load(&key()).expect("load");
    assert_eq!(titles(&sb), ["Later"]);
}

#[test]
fn a_stale_save_merges_and_keeps_both_edits() {
    let mock = Mock::start();
    let d = scratch("stale");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    sa.add(&login("Shared", "first")).expect("add");
    a.sync.create(&mut sa, &key()).expect("create");
    let mut b = machine(&mock, d.join("b"), "b");
    let (mut sb, _) = b.sync.load(&key()).expect("load");

    sa.add(&login("FromA", "a")).expect("add");
    assert!(synced(&a.sync.save(&mut sa, &key()).expect("save a")));

    // b still holds the old version: the server refuses, b merges, retries.
    // (Times have one-second steps: an edit in the creation's second could
    // lose the tie-break to the original, which then keeps it in history.)
    std::thread::sleep(Duration::from_millis(1100));
    sb.add(&login("FromB", "b")).expect("add");
    let id = id_of(&sb, "Shared");
    let mut d2 = sb.draft(&id).expect("draft");
    d2.username = "changed-on-b".into();
    sb.update(&id, &d2).expect("update");
    match b.sync.save(&mut sb, &key()).expect("save b") {
        Saved::Synced { merged } => assert!(merged.is_some(), "a's copy was merged in"),
        other => panic!("not synced: {other:?}"),
    }
    assert_eq!(titles(&sb), ["FromA", "FromB", "Shared"]);

    a.sync.poll(Some((&mut sa, &key()))).expect("poll");
    assert_eq!(titles(&sa), ["FromA", "FromB", "Shared"]);
    assert_eq!(username_of(&sa, "Shared"), "changed-on-b");
    assert!(usernames_ever(&sa, "Shared").contains(&"first".to_string()));
}

#[test]
fn two_machines_edit_offline_and_both_edits_survive() {
    let mock = Mock::start();
    let d = scratch("offline");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    a.sync.create(&mut sa, &key()).expect("create");
    let mut b = machine(&mock, d.join("b"), "b");
    let (mut sb, _) = b.sync.load(&key()).expect("load");

    a.creds.offline();
    b.creds.offline();
    sa.add(&login("OnTheTrain", "a")).expect("add");
    sb.add(&login("AtHome", "b")).expect("add");
    assert_eq!(
        a.sync.save(&mut sa, &key()).expect("save"),
        Saved::Pending {
            reason: "offline".into()
        }
    );
    b.sync.save(&mut sb, &key()).expect("save");
    assert_eq!(a.sync.status().state, "offline");
    assert!(a.sync.status().pending);

    // a reopened while offline: the cache, still with its change
    let (cached, loaded) = a.sync.load(&key()).expect("load offline");
    assert!(loaded.offline);
    assert_eq!(titles(&cached), ["OnTheTrain"]);

    a.creds.online();
    b.creds.online();
    assert!(a.sync.poll(Some((&mut sa, &key()))).expect("poll").uploaded);
    let polled = b.sync.poll(Some((&mut sb, &key()))).expect("poll");
    assert!(polled.uploaded && polled.changed);
    a.sync.poll(Some((&mut sa, &key()))).expect("poll");
    assert_eq!(titles(&sa), ["AtHome", "OnTheTrain"]);
    assert_eq!(titles(&sb), ["AtHome", "OnTheTrain"]);
    assert_eq!(a.sync.status().state, "in-sync");
    assert!(!b.sync.status().pending);
}

#[test]
fn a_new_master_key_elsewhere_is_reported_not_overwritten() {
    let mock = Mock::start();
    let d = scratch("key-changed");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    sa.add(&login("Bank", "sam")).expect("add");
    a.sync.create(&mut sa, &key()).expect("create");
    let mut b = machine(&mock, d.join("b"), "b");
    let (mut sb, _) = b.sync.load(&key()).expect("load");

    // a changes the master password
    assert!(synced(&a.sync.save(&mut sa, &other_key()).expect("passwd")));
    let new_bytes = mock.file(FILE).expect("file");

    // b saves under the old key: it stays on b, the place is untouched
    sb.add(&login("Edit", "b")).expect("add");
    assert_eq!(
        b.sync.save(&mut sb, &key()).expect("save"),
        Saved::Pending {
            reason: "key-changed".into()
        }
    );
    assert_eq!(b.sync.status().state, "error");
    assert_eq!(mock.file(FILE).expect("file"), new_bytes);

    // the old password: the place's copy no longer opens
    assert!(matches!(load_err(&mut b.sync, &key()), Error::KeyChanged));
    // the new password: b's unsent change is under the old one
    assert!(matches!(
        load_err(&mut b.sync, &other_key()),
        Error::CacheKey
    ));
    assert_eq!(Error::CacheKey.code(), "key-changed");
}

#[test]
fn a_rolled_back_copy_is_merged_reuploaded_and_flagged() {
    let mock = Mock::start();
    let d = scratch("rollback");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    sa.add(&login("Old", "sam")).expect("add");
    a.sync.create(&mut sa, &key()).expect("create");
    let old = mock.file(FILE).expect("file");

    std::thread::sleep(Duration::from_millis(1100));
    sa.add(&login("New", "sam")).expect("add");
    a.sync.save(&mut sa, &key()).expect("save");

    // the server hands out yesterday's file
    mock.replace(FILE, &old);
    let polled = a.sync.poll(Some((&mut sa, &key()))).expect("poll");
    assert!(polled.uploaded, "the newer data went back up");
    assert_eq!(titles(&sa), ["New", "Old"]);
    assert_eq!(a.sync.status().warning.as_deref(), Some("rollback"));

    // what the place has now opens with both
    let mut b = machine(&mock, d.join("b"), "b");
    let (sb, _) = b.sync.load(&key()).expect("load");
    assert_eq!(titles(&sb), ["New", "Old"]);

    a.sync.clear_warning().expect("clear");
    assert_eq!(a.sync.status().warning, None);
}

#[test]
fn the_probe_tells_a_guarded_server_from_a_single_writer() {
    let mock = Mock::start();
    let d = scratch("probe");
    let mut a = machine(&mock, d.join("a"), "a");
    assert!(a.sync.probe().expect("probe"));
    assert!(a.sync.place_info().guarded);
    assert!(
        mock.file(&FILE.replace("passwords.kdbx", ".ewe-safe-probe"))
            .is_none(),
        "cleaned up"
    );

    mock.set(|i| i.ignore_conditions = true);
    assert!(!a.sync.probe().expect("probe"));
    assert!(!a.sync.place_info().guarded);
    assert_eq!(a.sync.status().warning.as_deref(), Some("single-writer"));
}

#[test]
fn a_server_error_is_an_error_not_offline_and_heals() {
    let mock = Mock::start();
    let d = scratch("5xx");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    a.sync.create(&mut sa, &key()).expect("create");

    sa.add(&login("X", "x")).expect("add");
    mock.set(|i| i.fail_next = 1);
    assert_eq!(
        a.sync.save(&mut sa, &key()).expect("save"),
        Saved::Pending {
            reason: "place-error".into()
        }
    );
    assert_eq!(a.sync.status().state, "error");
    assert!(a.sync.last_error().is_some());

    assert!(a.sync.poll(Some((&mut sa, &key()))).expect("poll").uploaded);
    assert_eq!(a.sync.status().state, "in-sync");
}

#[test]
fn a_wrong_app_password_is_a_sign_in_error() {
    let mock = Mock::start();
    let d = scratch("401");
    let mut a = machine(&mock, d.join("a"), "a");
    a.creds.set_password("revoked");
    let mut sa = new_safe();
    match a.sync.create(&mut sa, &key()).expect("create") {
        Saved::Pending { reason } => assert_eq!(reason, "place-error"),
        other => panic!("{other:?}"),
    }
    assert!(a.sync.last_error().expect("error").contains("sign-in"));
}

#[test]
fn a_file_the_place_lost_is_put_back() {
    let mock = Mock::start();
    let d = scratch("missing");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    sa.add(&login("Keep", "me")).expect("add");
    a.sync.create(&mut sa, &key()).expect("create");

    mock.remove(FILE);
    let (s, _) = a.sync.load(&key()).expect("load");
    assert_eq!(titles(&s), ["Keep"]);
    assert!(mock.file(FILE).is_some(), "uploaded again");

    mock.remove(FILE);
    assert!(a.sync.poll(Some((&mut sa, &key()))).expect("poll").uploaded);
    assert!(mock.file(FILE).is_some());
}

#[test]
fn a_server_without_etags_still_merges() {
    let mock = Mock::start();
    mock.set(|i| i.no_etags = true);
    let d = scratch("no-etags");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    a.sync.create(&mut sa, &key()).expect("create");
    let mut b = machine(&mock, d.join("b"), "b");
    let (mut sb, _) = b.sync.load(&key()).expect("load");

    sa.add(&login("A", "a")).expect("add");
    a.sync.save(&mut sa, &key()).expect("save");
    sb.add(&login("B", "b")).expect("add");
    assert!(synced(&b.sync.save(&mut sb, &key()).expect("save")));
    a.sync.poll(Some((&mut sa, &key()))).expect("poll");
    assert_eq!(titles(&sa), ["A", "B"]);
}

#[test]
fn backups_keep_the_last_twenty() {
    let mock = Mock::start();
    let d = scratch("backups");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    a.sync.create(&mut sa, &key()).expect("create");
    for n in 0..25 {
        sa.add(&login(&format!("item{n}"), "u")).expect("add");
        a.sync.save(&mut sa, &key()).expect("save");
    }
    let backups = a.sync.backups().expect("backups");
    assert_eq!(backups.len(), safe_store::sync::BACKUPS);
    // each one is a safe that opens
    let newest = safe_core::Safe::open_file(backups.last().expect("one"), &key()).expect("open");
    assert_eq!(newest.items().len(), 24);
}

#[test]
fn locked_polls_upload_and_download_without_the_key() {
    let mock = Mock::start();
    let d = scratch("locked");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    a.sync.create(&mut sa, &key()).expect("create");
    let mut b = machine(&mock, d.join("b"), "b");
    let (mut sb, _) = b.sync.load(&key()).expect("load");

    // a saves offline, then locks; back online the bytes go up as they are
    a.creds.offline();
    sa.add(&login("Pending", "a")).expect("add");
    a.sync.save(&mut sa, &key()).expect("save");
    drop(sa);
    a.creds.online();
    assert!(a.sync.poll(None).expect("locked poll").uploaded);
    assert!(!a.sync.status().pending);

    // b, locked, downloads a's change; offline at unlock it still has it
    drop(sb);
    b.sync.poll(None).expect("locked poll");
    b.creds.offline();
    let (sb2, loaded) = b.sync.load(&key()).expect("load");
    assert!(loaded.offline);
    assert_eq!(titles(&sb2), ["Pending"]);
    sb = sb2;
    b.creds.online();
    b.sync.poll(Some((&mut sb, &key()))).expect("poll");
    assert_eq!(b.sync.status().state, "in-sync");
}

#[test]
fn creating_over_an_existing_safe_is_refused() {
    let mock = Mock::start();
    let d = scratch("exists");
    let mut a = machine(&mock, d.join("a"), "a");
    a.sync.create(&mut new_safe(), &key()).expect("create");
    let first = mock.file(FILE).expect("file");

    let mut b = machine(&mock, d.join("b"), "b");
    assert!(matches!(
        b.sync.create(&mut new_safe(), &other_key()),
        Err(Error::Exists)
    ));
    assert_eq!(mock.file(FILE).expect("file"), first, "untouched");
    assert!(!b.sync.has_cache(), "nothing half-made stays");
}

#[test]
fn no_safe_anywhere_is_not_set_up() {
    let mock = Mock::start();
    let d = scratch("nothing");
    let mut a = machine(&mock, d.join("a"), "a");
    let e = load_err(&mut a.sync, &key());
    assert_eq!(e.code(), "not-set-up");

    a.creds.offline();
    assert_eq!(load_err(&mut a.sync, &key()).code(), "offline");
}

#[test]
fn the_wrong_password_is_wrong_key() {
    let mock = Mock::start();
    let d = scratch("wrong");
    let mut a = machine(&mock, d.join("a"), "a");
    a.sync.create(&mut new_safe(), &key()).expect("create");
    let mut b = machine(&mock, d.join("b"), "b");
    assert_eq!(load_err(&mut b.sync, &other_key()).code(), "wrong-key");
    assert_eq!(load_err(&mut a.sync, &other_key()).code(), "wrong-key");
}

#[test]
fn state_survives_a_restart() {
    let mock = Mock::start();
    let d = scratch("restart");
    let mut a = machine(&mock, d.join("a"), "a");
    let mut sa = new_safe();
    a.sync.create(&mut sa, &key()).expect("create");
    a.creds.offline();
    sa.add(&login("Unsent", "u")).expect("add");
    a.sync.save(&mut sa, &key()).expect("save");
    drop(a);

    // the daemon restarts: the pending change is remembered and goes up
    let mut a = machine(&mock, d.join("a"), "a");
    assert!(a.sync.status().pending);
    let (s, _) = a.sync.load(&key()).expect("load");
    assert_eq!(titles(&s), ["Unsent"]);
    assert!(!a.sync.status().pending);
    let mut b = machine(&mock, d.join("b"), "b");
    assert_eq!(titles(&b.sync.load(&key()).expect("load").0), ["Unsent"]);
}
