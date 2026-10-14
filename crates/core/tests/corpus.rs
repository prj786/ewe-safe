//! Every corpus file through `Safe` (docs/SPIKE-0.md): the write guard must
//! agree with the fidelity gate, and every writable file must take an edit
//! and survive the verified write. Skips when `tests/corpus/fetch.sh` has
//! not been run.

use std::path::PathBuf;

use keepass::config::KdfConfig;
use safe_core::safe::key;
use safe_core::{Error, Safe};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

#[test]
fn the_guard_agrees_with_the_fidelity_gate() {
    let dir = corpus_dir();
    let files = dir.join("files");
    if !files.is_dir() {
        eprintln!("corpus not fetched (tests/corpus/fetch.sh): skipped");
        return;
    }
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("corpus.json")).expect("corpus.json"),
    )
    .expect("json");
    let mut checked = 0;
    for f in manifest["files"].as_array().expect("files") {
        let source = f["source"].as_str().expect("source");
        let name = f["file"].as_str().expect("file");
        let path = files.join(source).join(name);
        let keyfile = f["keyfile"]
            .as_str()
            .map(|k| std::fs::read(files.join(source).join(k)).expect("keyfile"));
        let k = key(
            f["password"].as_str().expect("password"),
            keyfile.as_deref(),
        )
        .expect("key");
        let expect = &f["expect"];

        let opened = Safe::open_file(&path, &k);
        if expect["open_fails"].is_string() {
            assert!(
                matches!(opened, Err(Error::Open(_))),
                "{name}: should not open"
            );
            checked += 1;
            continue;
        }
        let mut safe = opened.unwrap_or_else(|e| panic!("{name}: {e}"));
        let unknown_content = expect["lost"].as_array().is_some_and(|l| {
            l.iter()
                .any(|p| p.as_str().is_some_and(|p| p.contains("Future")))
        });
        if unknown_content {
            assert!(
                safe.writable().is_err(),
                "{name}: must be read-only, guard said {:?}",
                safe.guard()
            );
            checked += 1;
            continue;
        }
        assert!(
            safe.writable().is_ok(),
            "{name}: guard said {:?}",
            safe.guard()
        );
        if name.contains("synth_rich") {
            assert_eq!(
                safe.guard().cosmetic.len(),
                1,
                "{name}: the fallback icon (F3)"
            );
        }

        safe.set_upgrade_kdf(KdfConfig::Argon2id {
            iterations: 1,
            memory: 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        });
        if let Some(first) = safe.items().into_iter().next() {
            let mut d = safe.draft(&first.id).expect("draft");
            d.title.push_str(" (ewe)");
            safe.update(&first.id, &d)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let bytes = safe.to_bytes(&k).unwrap_or_else(|e| panic!("{name}: {e}"));
        let back = Safe::open(&bytes, &k).unwrap_or_else(|e| panic!("{name}: reopen: {e}"));
        assert!(
            back.writable().is_ok(),
            "{name}: our own output must be writable"
        );
        assert_eq!(back.upgrade_from(), None, "{name}: written as KDBX 4.1");
        assert_eq!(back.items().len(), safe.items().len(), "{name}: same items");
        checked += 1;
    }
    assert!(checked >= 37, "only {checked} corpus files checked");
}

fn cheap() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

/// Every writable corpus file merged with an edited copy of itself, both
/// ways, through the verified write; merging the same copy again changes
/// nothing. A read-only file is refused as the other copy (docs/FORMAT.md,
/// "Merge").
#[test]
fn every_writable_file_merges_with_an_edited_copy() {
    let dir = corpus_dir();
    let files = dir.join("files");
    if !files.is_dir() {
        eprintln!("corpus not fetched (tests/corpus/fetch.sh): skipped");
        return;
    }
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("corpus.json")).expect("corpus.json"),
    )
    .expect("json");
    let (mut merged, mut refused) = (0, 0);
    for f in manifest["files"].as_array().expect("files") {
        if f["expect"]["open_fails"].is_string() {
            continue;
        }
        let source = f["source"].as_str().expect("source");
        let name = f["file"].as_str().expect("file");
        let path = files.join(source).join(name);
        let keyfile = f["keyfile"]
            .as_str()
            .map(|k| std::fs::read(files.join(source).join(k)).expect("keyfile"));
        let k = key(
            f["password"].as_str().expect("password"),
            keyfile.as_deref(),
        )
        .expect("key");
        let open = || {
            let mut s = Safe::open_file(&path, &k).unwrap_or_else(|e| panic!("{name}: {e}"));
            s.set_upgrade_kdf(cheap());
            s
        };

        let theirs = open();
        if theirs.writable().is_err() {
            let mut fresh = Safe::create("x", cheap());
            assert!(
                matches!(fresh.merge(&theirs), Err(Error::ReadOnly(_))),
                "{name}: a read-only copy must be refused"
            );
            refused += 1;
            continue;
        }

        // the other machine: one item edited, one added
        let mut other = open();
        let first = other.items().into_iter().next();
        if let Some(first) = &first {
            let mut d = other.draft(&first.id).expect("draft");
            d.title.push_str(" (other machine)");
            other
                .update(&first.id, &d)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let added = other
            .add(&safe_core::Draft {
                title: "added there".into(),
                ..safe_core::Draft::default()
            })
            .expect("add");

        let mut here = open();
        let r = here.merge(&other).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(r.added, 1, "{name}: {r:?}");
        assert_eq!(r.updated, usize::from(first.is_some()), "{name}: {r:?}");
        let bytes = here
            .to_bytes(&k)
            .unwrap_or_else(|e| panic!("{name}: write: {e}"));
        let back = Safe::open(&bytes, &k).unwrap_or_else(|e| panic!("{name}: reopen: {e}"));
        assert_eq!(
            back.items().len(),
            other.items().len(),
            "{name}: same items"
        );
        assert!(back.summary(&added).is_ok(), "{name}: the added item");
        if let Some(first) = &first {
            assert!(
                back.summary(&first.id)
                    .expect("item")
                    .title
                    .ends_with(" (other machine)"),
                "{name}: the newer title"
            );
        }
        let again = here.merge(&other).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(again, safe_core::merge::Report::default(), "{name}: twice");

        // and the other way: the edited copy takes in the untouched file
        let r = other
            .merge(&open())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((r.added, r.updated, r.deleted), (0, 0, 0), "{name}: {r:?}");
        other
            .to_bytes(&k)
            .unwrap_or_else(|e| panic!("{name}: write: {e}"));
        merged += 1;
    }
    eprintln!("{merged} corpus files merged, {refused} read-only refused");
    assert!(merged >= 25, "only {merged} corpus files merged");
    assert!(refused >= 4, "only {refused} read-only files refused");
}

/// F11 (vendor/keepass/PATCHED.md): KeePass stores a file once when two
/// entries carry it. Deleting one entry must not take the other's file.
#[test]
fn deleting_an_item_keeps_a_file_another_item_shares() {
    let path = corpus_dir().join("files/synthetic/synth_rich.kdbx");
    if !path.is_file() {
        eprintln!("corpus not fetched (tests/corpus/fetch.sh): skipped");
        return;
    }
    let k = key("demopass", None).expect("key");
    let mut safe = Safe::open_file(&path, &k).expect("open");
    let db = safe.database();
    let mut users: std::collections::HashMap<usize, Vec<(String, String, Vec<u8>)>> =
        std::collections::HashMap::new();
    for e in db.iter_all_entries() {
        for (name, a) in e.attachments_named() {
            users.entry(a.id().id()).or_default().push((
                e.id().to_string(),
                name.to_string(),
                a.data.get().clone(),
            ));
        }
    }
    let shared = users
        .into_values()
        .find(|u| u.len() >= 2)
        .expect("synth_rich has a file two entries share");
    let (gone, _, _) = &shared[0];
    let (kept, kept_name, data) = &shared[1];
    safe.trash(gone).expect("trash");
    safe.purge(gone).expect("purge");
    let bytes = safe.to_bytes(&k).expect("write");
    let back = Safe::open(&bytes, &k).expect("reopen");
    let id = keepass::db::EntryId::from_uuid(uuid::Uuid::parse_str(kept).expect("uuid"));
    let e = back.database().entry(id).expect("the other entry");
    let file = e
        .attachment_by_name(kept_name)
        .expect("the other entry keeps its file");
    assert_eq!(file.data.get(), data, "with the same content");
}
