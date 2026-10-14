//! "This computer": a file whose version is its content hash.

mod common;

use common::*;
use safe_store::{Expect, Fetched, Local, Place, Saved, Stored, Syncer, Tag};

#[test]
fn a_change_made_by_something_else_is_stale() {
    let d = scratch("local-stale");
    let p = Local::new(d.join("safe/passwords.kdbx"));
    let Stored::Ok(v1) = p.store(b"one", &Expect::Absent).expect("create") else {
        panic!("not stored");
    };
    assert_eq!(v1, Tag::content(b"one"));
    assert_eq!(
        p.store(b"again", &Expect::Absent).expect("store"),
        Stored::Stale
    );
    assert!(matches!(
        p.fetch(Some(&v1)).expect("fetch"),
        Fetched::Unchanged
    ));

    // KeePassXC (or a restore) writes the file
    std::fs::write(d.join("safe/passwords.kdbx"), b"theirs").expect("write");
    assert_eq!(
        p.store(b"two", &Expect::Tag(v1.clone())).expect("store"),
        Stored::Stale
    );
    match p.fetch(Some(&v1)).expect("fetch") {
        Fetched::Bytes { bytes, tag } => {
            assert_eq!(bytes, b"theirs");
            assert_eq!(
                p.store(b"two", &Expect::Tag(tag)).expect("store"),
                Stored::Ok(Tag::content(b"two"))
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(p.probe().expect("probe"));
    assert_eq!(p.info().kind, "local");
}

#[test]
fn two_syncers_on_one_file_merge_like_two_machines() {
    let d = scratch("local-two");
    let file = d.join("passwords.kdbx");
    let mut a = Syncer::new(Box::new(Local::new(&file)), d.join("a"), "a").expect("syncer");
    let mut b = Syncer::new(Box::new(Local::new(&file)), d.join("b"), "b").expect("syncer");
    let mut sa = new_safe();
    a.create(&mut sa, &key()).expect("create");
    assert_eq!(a.status().state, "local");
    let (mut sb, _) = b.load(&key()).expect("load");

    sa.add(&login("A", "a")).expect("add");
    a.save(&mut sa, &key()).expect("save");
    sb.add(&login("B", "b")).expect("add");
    assert!(matches!(
        b.save(&mut sb, &key()).expect("save"),
        Saved::Synced { merged: Some(_) }
    ));
    a.poll(Some((&mut sa, &key()))).expect("poll");
    assert_eq!(titles(&sa), ["A", "B"]);
    let on_disk = safe_core::Safe::open_file(&file, &key()).expect("open");
    assert_eq!(titles(&on_disk), ["A", "B"]);
}
