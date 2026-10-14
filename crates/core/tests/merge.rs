//! Merge (PLAN.md §7, docs/FORMAT.md "Merge"): the spike's 14 cases
//! (docs/SPIKE-0.md §2), then properties over seeded random edits of two
//! copies, then deletions through `Safe` (C3). Every merged result must
//! survive a write and a read back unchanged.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{NaiveDate, NaiveDateTime};
use keepass::config::{DatabaseVersion, KdfConfig};
use keepass::db::{EntryId, EntryRef, GroupId, Value, fields};
use keepass::{Database, DatabaseKey};
use safe_core::digest::Digester;
use safe_core::merge::{Report, merge};
use safe_core::safe::key;
use safe_core::{Draft, Kind, Safe};
use zeroize::Zeroizing;

fn t(hour: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 1, 1)
        .and_then(|d| d.and_hms_opt(hour % 24, 0, 0))
        .expect("valid time")
        + chrono::Duration::days(i64::from(hour / 24))
}

fn cheap() -> KdfConfig {
    KdfConfig::Aes { rounds: 1 }
}

fn pw() -> DatabaseKey {
    DatabaseKey::new().with_password("merge test")
}

/// Write and read back: a merged safe must come back exactly as it was.
fn roundtrips(db: &Database) {
    let mut db = db.clone();
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.kdf_config = cheap();
    let mut bytes = Vec::new();
    db.save(&mut bytes, pw()).expect("save");
    let back = Database::parse(&bytes, pw()).expect("parse");
    let d = Digester::new();
    let (a, b) = (d.digest(&db), d.digest(&back));
    assert_eq!(
        a,
        b,
        "changed on the way back: {:?}",
        safe_core::digest::differences(&a, &b)
    );
}

fn merged(ours: &Database, theirs: &Database) -> (Database, Report) {
    let (m, r) = merge(ours, theirs).expect("merge");
    roundtrips(&m);
    (m, r)
}

struct Base {
    db: Database,
    entry: EntryId,
    group: GroupId,
}

/// One group "Work" with one login "mail", everything stamped at hour 0.
fn base() -> Base {
    let mut db = Database::new();
    db.config.kdf_config = cheap();
    let group = db
        .root_mut()
        .add_group()
        .edit(|g| g.name = "Work".into())
        .id();
    let entry = db
        .group_mut(group)
        .expect("group")
        .add_entry()
        .edit(|e| {
            e.set_unprotected(fields::TITLE, "mail");
            e.set_unprotected(fields::USERNAME, "sam");
            e.set_protected(fields::PASSWORD, "one");
        })
        .id();
    stamp(&mut db, 0);
    Base { db, entry, group }
}

fn stamp(db: &mut Database, hour: u32) {
    db.foreach_entry_mut(|mut e| {
        e.times.creation = Some(t(hour));
        e.times.last_modification = Some(t(hour));
        e.times.location_changed = Some(t(hour));
        e.times.last_access = Some(t(hour));
    });
    db.foreach_group_mut(|mut g| {
        g.times.creation = Some(t(hour));
        g.times.last_modification = Some(t(hour));
        g.times.location_changed = Some(t(hour));
        g.times.last_access = Some(t(hour));
    });
}

/// A history-tracked change, the way Safe edits, stamped at `hour`.
fn set_password(db: &mut Database, id: EntryId, value: &str, hour: u32) {
    let mut e = db.entry_mut(id).expect("entry");
    e.edit_tracking(|e| e.set_protected(fields::PASSWORD, value));
    e.times.last_modification = Some(t(hour));
    settle(db, id);
}

/// keepass-rs puts the old version first; a KeePass file (and Safe) lists
/// history oldest first.
fn settle(db: &mut Database, id: EntryId) {
    let mut e = db.entry_mut(id).expect("entry");
    let Some(h) = e.history.take() else {
        return;
    };
    let mut versions = h.get_entries().clone();
    if !versions.is_empty() {
        let newest = versions.remove(0);
        versions.push(newest);
    }
    let mut settled = keepass::db::History::default();
    for v in versions.into_iter().rev() {
        settled.add_entry(v);
    }
    e.history = Some(settled);
}

/// A recorded deletion, stamped at `hour`.
fn delete(db: &mut Database, id: EntryId, hour: u32) {
    db.entry_mut(id).expect("entry").track_changes().remove();
    db.deleted_objects.insert(id.uuid(), Some(t(hour)));
}

fn password(db: &Database, id: EntryId) -> Option<String> {
    db.entry(id)
        .and_then(|e| e.get(fields::PASSWORD).map(str::to_string))
}

fn history_passwords(db: &Database, id: EntryId) -> Vec<String> {
    db.entry(id)
        .and_then(|e| e.history.clone())
        .map(|h| {
            h.get_entries()
                .iter()
                .filter_map(|e| e.get(fields::PASSWORD).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn files(db: &Database, id: EntryId) -> Vec<String> {
    let mut f: Vec<String> = db
        .entry(id)
        .map(|e| {
            e.attachments_named()
                .map(|(n, a)| format!("{n}={}", String::from_utf8_lossy(a.data.get())))
                .collect()
        })
        .unwrap_or_default();
    f.sort();
    f
}

// ── the spike's 14 cases (docs/SPIKE-0.md §2) ───────────────────────────────

#[test]
fn case_01_new_on_either_side_is_kept() {
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    let new_theirs = theirs
        .group_mut(b.group)
        .expect("group")
        .add_entry()
        .edit(|e| e.set_unprotected(fields::TITLE, "theirs"))
        .id();
    let new_mine = mine
        .root_mut()
        .add_entry()
        .edit(|e| e.set_unprotected(fields::TITLE, "mine"))
        .id();
    for (m, r) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        assert!(m.entry(new_theirs).is_some() && m.entry(new_mine).is_some());
        assert_eq!(r.added, 1);
    }
    let (m, _) = merged(&mine, &theirs);
    assert_eq!(
        m.entry(new_theirs).map(|e| e.parent().id()),
        Some(b.group),
        "a new entry lands in its own folder"
    );
}

#[test]
fn case_02_new_entry_brings_its_attachment() {
    let b = base();
    let mine = b.db.clone();
    let mut theirs = b.db.clone();
    let id = theirs
        .root_mut()
        .add_entry()
        .edit(|e| e.set_unprotected(fields::TITLE, "with file"))
        .id();
    theirs
        .entry_mut(id)
        .expect("entry")
        .add_attachment("a.txt", Value::unprotected(b"hello".to_vec()));
    let (m, _) = merged(&mine, &theirs);
    assert_eq!(files(&m, id), ["a.txt=hello"]);
}

fn both_edited(mine_hour: u32, theirs_hour: u32) {
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    set_password(&mut mine, b.entry, "mine", mine_hour);
    set_password(&mut theirs, b.entry, "theirs", theirs_hour);
    let (win, lose) = if theirs_hour > mine_hour {
        ("theirs", "mine")
    } else {
        ("mine", "theirs")
    };
    let (m1, r1) = merged(&mine, &theirs);
    let (m2, _) = merged(&theirs, &mine);
    for m in [&m1, &m2] {
        assert_eq!(password(m, b.entry).as_deref(), Some(win));
        assert_eq!(
            history_passwords(m, b.entry),
            ["one", lose],
            "the base once, then the loser; oldest first"
        );
    }
    assert_eq!(r1.diverged, 1);
    assert_eq!(r1.to_history, 1);
    assert_eq!(r1.updated, usize::from(win == "theirs"));
}

#[test]
fn case_03_both_edited_theirs_newer() {
    both_edited(1, 2);
}

#[test]
fn case_04_both_edited_mine_newer_keeps_theirs_in_history() {
    // M1: keepass-rs threw theirs away
    both_edited(2, 1);
}

#[test]
fn case_05_attachment_added_to_an_existing_entry_there() {
    // M2: keepass-rs did not merge it
    let b = base();
    let mine = b.db.clone();
    let mut theirs = b.db.clone();
    {
        let mut e = theirs.entry_mut(b.entry).expect("entry");
        e.edit_tracking(|e| {
            e.add_attachment("scan.pdf", Value::unprotected(b"%PDF".to_vec()));
        });
        e.times.last_modification = Some(t(2));
    }
    for (m, _) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        assert_eq!(files(&m, b.entry), ["scan.pdf=%PDF"]);
    }
}

#[test]
fn case_06_different_edits_in_the_same_second() {
    // M4: keepass-rs refused
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    set_password(&mut mine, b.entry, "mine", 1);
    set_password(&mut theirs, b.entry, "theirs", 1);
    let (m1, _) = merged(&mine, &theirs);
    let (m2, _) = merged(&theirs, &mine);
    let win = password(&m1, b.entry).expect("password");
    assert_eq!(password(&m2, b.entry).as_deref(), Some(win.as_str()));
    let lose = if win == "mine" { "theirs" } else { "mine" };
    assert!(history_passwords(&m1, b.entry).contains(&lose.to_string()));
    assert_eq!(
        history_passwords(&m1, b.entry),
        history_passwords(&m2, b.entry)
    );
}

#[test]
fn case_07_deleted_there_then_edited_here_the_edit_wins() {
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    delete(&mut theirs, b.entry, 1);
    set_password(&mut mine, b.entry, "edited later", 2);
    for (m, _) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        assert_eq!(password(&m, b.entry).as_deref(), Some("edited later"));
    }
}

#[test]
fn case_08_edited_here_then_deleted_there_the_deletion_wins() {
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    set_password(&mut mine, b.entry, "edited earlier", 1);
    delete(&mut theirs, b.entry, 2);
    let (m1, r1) = merged(&mine, &theirs);
    let (m2, _) = merged(&theirs, &mine);
    for m in [&m1, &m2] {
        assert!(m.entry(b.entry).is_none());
        assert_eq!(m.deleted_objects.get(&b.entry.uuid()), Some(&Some(t(2))));
    }
    assert_eq!(r1.deleted, 1);
}

#[test]
fn case_09_an_unrecorded_removal_comes_back() {
    let b = base();
    let mine = b.db.clone();
    let mut theirs = b.db.clone();
    theirs.entry_mut(b.entry).expect("entry").remove();
    let (m, _) = merged(&theirs, &mine);
    assert!(m.entry(b.entry).is_some());
}

fn renamed(mine_hour: u32, theirs_hour: u32) {
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    for (db, name, hour) in [
        (&mut mine, "Mine", mine_hour),
        (&mut theirs, "Theirs", theirs_hour),
    ] {
        let mut g = db.group_mut(b.group).expect("group");
        g.name = name.into();
        g.times.last_modification = Some(t(hour));
    }
    let want = if theirs_hour > mine_hour {
        "Theirs"
    } else {
        "Mine"
    };
    for (m, _) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        assert_eq!(
            m.group(b.group).map(|g| g.name.clone()).as_deref(),
            Some(want)
        );
    }
}

#[test]
fn case_10_group_renamed_both_theirs_newer() {
    renamed(1, 2);
}

#[test]
fn case_11_group_renamed_both_mine_newer() {
    renamed(2, 1);
}

#[test]
fn case_12_a_newer_move_there_is_followed() {
    let mut b = base();
    let home =
        b.db.root_mut()
            .add_group()
            .edit(|g| g.name = "Home".into())
            .id();
    stamp(&mut b.db, 0);
    let mine = b.db.clone();
    let mut theirs = b.db.clone();
    {
        let mut e = theirs.entry_mut(b.entry).expect("entry");
        e.move_to(home).expect("move");
        e.times.location_changed = Some(t(2));
    }
    for (m, _) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        let e = m.entry(b.entry).expect("entry");
        assert_eq!(e.parent().id(), home);
        assert_eq!(e.previous_parent().map(|g| g.id()), Some(b.group));
        assert_eq!(e.times.location_changed, Some(t(2)));
    }
}

#[test]
fn case_13_metadata_newer_wins() {
    // M3: keepass-rs left Meta alone
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    mine.meta.database_name = Some("Mine".into());
    mine.meta.database_name_changed = Some(t(1));
    theirs.meta.database_name = Some("Theirs".into());
    theirs.meta.database_name_changed = Some(t(2));
    for (m, _) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        assert_eq!(m.meta.database_name.as_deref(), Some("Theirs"));
        assert_eq!(m.meta.database_name_changed, Some(t(2)));
    }
}

#[test]
fn case_14_merging_an_identical_copy_changes_nothing() {
    let b = base();
    let mut x = b.db.clone();
    set_password(&mut x, b.entry, "two", 1);
    let (m, r) = merged(&x, &x.clone());
    assert_eq!(r, Report::default());
    let d = Digester::new();
    assert_eq!(d.digest(&m), d.digest(&x));
}

// ── what the cases leave out ────────────────────────────────────────────────

#[test]
fn the_loser_keeps_its_attachment_in_history() {
    // F10: dropping an attachment from the current state also dropped it
    // for history; the winner here has none, the loser's version must keep
    // its file
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    {
        let mut e = mine.entry_mut(b.entry).expect("entry");
        e.edit_tracking(|e| {
            e.add_attachment("key.txt", Value::protected(b"s3cret".to_vec()));
        });
        e.times.last_modification = Some(t(1));
    }
    set_password(&mut theirs, b.entry, "theirs", 2);
    for (m, _) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        assert!(files(&m, b.entry).is_empty(), "the winner has no file");
        let e = m.entry(b.entry).expect("entry");
        let h = e.history.as_ref().expect("history");
        let with_file = (0..h.get_entries().len())
            .filter_map(|i| e.historical(i))
            .find(|v| v.attachments().next().is_some())
            .expect("the loser's version is in history");
        let (name, a) = with_file.attachments_named().next().expect("file");
        assert_eq!(name, "key.txt");
        assert_eq!(a.data.get(), b"s3cret");
        assert!(a.data.is_protected());
    }
}

#[test]
fn two_recycle_bins_become_one() {
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    let other =
        b.db.root()
            .group_by_name("Work")
            .map(|g| g.id())
            .expect("work");
    let extra = theirs
        .group_mut(other)
        .expect("group")
        .add_entry()
        .edit(|e| e.set_unprotected(fields::TITLE, "old"))
        .id();
    stamp(&mut theirs, 0);
    let mut bins = Vec::new();
    for (db, id, hour) in [(&mut mine, b.entry, 1), (&mut theirs, extra, 2)] {
        let bin = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Recycle Bin".into())
            .id();
        db.meta.recyclebin_enabled = Some(true);
        db.meta.recyclebin_uuid = Some(bin.uuid());
        db.meta.recyclebin_changed = Some(t(hour));
        let mut e = db.entry_mut(id).expect("entry");
        e.move_to(bin).expect("move");
        e.times.location_changed = Some(t(hour));
        bins.push(bin);
    }
    for (m, r) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        let bin = m.recycle_bin().map(|g| g.id()).expect("bin");
        assert_eq!(bin, bins[1], "the newer bin");
        assert!(m.group(bins[0]).is_none(), "the other one is gone");
        assert!(m.deleted_objects.contains_key(&bins[0].uuid()));
        for id in [b.entry, extra] {
            let e = m.entry(id).expect("entry");
            assert_eq!(e.parent().id(), bin);
            assert_eq!(
                e.previous_parent().map(|g| g.id()),
                Some(b.group),
                "restore still knows the way back"
            );
        }
        assert_eq!(r.groups_deleted, 1);
    }
}

#[test]
fn a_deleted_group_goes_unless_something_new_is_in_it() {
    let b = base();
    let mut mine = b.db.clone();
    let mut theirs = b.db.clone();
    // theirs deletes Work with its entry at 2
    theirs
        .group_mut(b.group)
        .expect("group")
        .track_changes()
        .remove()
        .expect("remove");
    theirs.deleted_objects.insert(b.group.uuid(), Some(t(2)));
    theirs.deleted_objects.insert(b.entry.uuid(), Some(t(2)));
    let (m, _) = merged(&mine, &theirs);
    assert!(m.group(b.group).is_none() && m.entry(b.entry).is_none());

    // but mine added an entry to Work at 3: Work stays, the old one goes
    let new = mine
        .group_mut(b.group)
        .expect("group")
        .add_entry()
        .edit(|e| e.set_unprotected(fields::TITLE, "new"))
        .id();
    if let Some(mut e) = mine.entry_mut(new) {
        e.times.last_modification = Some(t(3));
        e.times.location_changed = Some(t(3));
    }
    for (m, _) in [merged(&mine, &theirs), merged(&theirs, &mine)] {
        assert!(m.group(b.group).is_some());
        assert!(m.entry(new).is_some());
        assert!(m.entry(b.entry).is_none());
    }
}

#[test]
fn custom_icons_match_by_picture() {
    let b = base();
    let mine = b.db.clone();
    let mut theirs = b.db.clone();
    theirs.entry_mut(b.entry).expect("entry").edit(|e| {
        e.set_icon_custom_new(vec![1, 2, 3]);
        e.times.last_modification = Some(t(1));
    });
    let (m, _) = merged(&mine, &theirs);
    let icon = m
        .entry(b.entry)
        .and_then(|e| e.custom_icon().map(|i| i.data.clone()));
    assert_eq!(icon, Some(vec![1, 2, 3]));
    // merging again finds the same picture and adds no second icon
    let (again, r) = merged(&m, &theirs);
    assert_eq!(again.num_custom_icons(), 1);
    assert_eq!(r, Report::default());
}

#[test]
fn history_grows_to_the_cap_and_no_further() {
    let b = base();
    let mut mine = b.db.clone();
    mine.meta.history_max_items = Some(3);
    let mut theirs = mine.clone();
    for h in 1..=3 {
        set_password(&mut mine, b.entry, &format!("m{h}"), h);
        set_password(&mut theirs, b.entry, &format!("t{h}"), h + 10);
    }
    let (m, _) = merged(&mine, &theirs);
    // each side had 3 (one, and its first two); with mine's current version
    // that makes 6 older than t3; the merge keeps the newest 3, oldest first
    assert_eq!(history_passwords(&m, b.entry), ["m3", "t1", "t2"]);
    assert_eq!(password(&m, b.entry).as_deref(), Some("t3"));
}

// ── properties over seeded random edits ─────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// UUIDs from the seed too, so a failing seed fails every run.
    fn uuid(&mut self) -> uuid::Uuid {
        uuid::Uuid::from_u64_pair(self.next(), self.next())
    }
}

fn ids(db: &Database) -> Vec<EntryId> {
    let mut v: Vec<EntryId> = db.iter_all_entries().map(|e| e.id()).collect();
    v.sort_by_key(|i| i.uuid());
    v
}

fn group_ids(db: &Database) -> Vec<GroupId> {
    let bin = db.meta.recyclebin_uuid;
    let mut v: Vec<GroupId> = db
        .iter_all_groups()
        .map(|g| g.id())
        .filter(|g| Some(g.uuid()) != bin)
        .collect();
    v.sort_by_key(|g| g.uuid());
    v
}

/// One random change, the way a KeePass app makes it, stamped at `hour`.
fn random_edit(db: &mut Database, rng: &mut Rng, hour: u32, n: u32) {
    let entries = ids(db);
    let groups = group_ids(db);
    let pick_entry = |rng: &mut Rng| entries.get(rng.below(entries.len().max(1))).copied();
    match rng.below(8) {
        0 | 1 => {
            if let Some(id) = pick_entry(rng) {
                set_password(db, id, &format!("p{hour}-{n}"), hour);
            }
        }
        2 => {
            if let Some(id) = pick_entry(rng) {
                let mut e = db.entry_mut(id).expect("entry");
                e.edit_tracking(|e| {
                    e.add_attachment(
                        format!("f{hour}-{n}.txt"),
                        Value::unprotected(format!("data {hour} {n}").into_bytes()),
                    );
                });
                e.times.last_modification = Some(t(hour));
                settle(db, id);
            }
        }
        3 => {
            let g = groups[rng.below(groups.len())];
            let new = EntryId::from_uuid(rng.uuid());
            let id = db
                .group_mut(g)
                .expect("group")
                .add_entry_with_id(new)
                .expect("fresh id")
                .edit(|e| {
                    e.set_unprotected(fields::TITLE, format!("new {hour}-{n}"));
                    e.set_protected(fields::PASSWORD, format!("np{hour}-{n}"));
                })
                .id();
            let mut e = db.entry_mut(id).expect("entry");
            e.times.creation = Some(t(hour));
            e.times.last_modification = Some(t(hour));
            e.times.location_changed = Some(t(hour));
            e.times.last_access = Some(t(hour));
        }
        4 => {
            if let Some(id) = pick_entry(rng) {
                delete(db, id, hour);
            }
        }
        5 => {
            if let Some(id) = pick_entry(rng) {
                let g = groups[rng.below(groups.len())];
                let here = db.entry(id).map(|e| e.parent().id());
                let mut e = db.entry_mut(id).expect("entry");
                if here != Some(g) {
                    e.move_to(g).expect("move");
                    e.times.location_changed = Some(t(hour));
                }
            }
        }
        6 => {
            if let Some(id) = pick_entry(rng) {
                let bin = match db.recycle_bin().map(|g| g.id()) {
                    Some(b) => b,
                    None => {
                        let b = db
                            .root_mut()
                            .add_group_with_id(GroupId::from_uuid(rng.uuid()))
                            .expect("fresh id")
                            .edit(|g| g.name = "Recycle Bin".into())
                            .id();
                        if let Some(mut g) = db.group_mut(b) {
                            g.times.creation = Some(t(hour));
                            g.times.last_modification = Some(t(hour));
                            g.times.location_changed = Some(t(hour));
                        }
                        db.meta.recyclebin_enabled = Some(true);
                        db.meta.recyclebin_uuid = Some(b.uuid());
                        db.meta.recyclebin_changed = Some(t(hour));
                        b
                    }
                };
                let here = db.entry(id).map(|e| e.parent().id());
                let mut e = db.entry_mut(id).expect("entry");
                if here != Some(bin) {
                    e.move_to(bin).expect("move");
                    e.times.location_changed = Some(t(hour));
                }
            }
        }
        _ => {
            let g = groups[rng.below(groups.len())];
            if g != db.root().id() {
                let mut g = db.group_mut(g).expect("group");
                g.name = format!("folder {hour}-{n}");
                g.times.last_modification = Some(t(hour));
            }
        }
    }
}

fn scenario(seed: u64) -> (Database, Database) {
    // SAFE_MERGE_SALT=n gives every seed a different scenario
    let salt: u64 = std::env::var("SAFE_MERGE_SALT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut rng = Rng((seed ^ salt.rotate_left(32)).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut db = Database::new_with_root_id(GroupId::from_uuid(rng.uuid()));
    db.config.kdf_config = cheap();
    // no cap here: "nothing is thrown away" is checked version by version
    db.meta.history_max_items = Some(-1);
    let work = db
        .root_mut()
        .add_group_with_id(GroupId::from_uuid(rng.uuid()))
        .expect("fresh id")
        .edit(|g| g.name = "Work".into())
        .id();
    let home = db
        .root_mut()
        .add_group_with_id(GroupId::from_uuid(rng.uuid()))
        .expect("fresh id")
        .edit(|g| g.name = "Home".into())
        .id();
    for i in 0..6 {
        let g = [db.root().id(), work, home][i % 3];
        let new = EntryId::from_uuid(rng.uuid());
        let id = db
            .group_mut(g)
            .expect("group")
            .add_entry_with_id(new)
            .expect("fresh id")
            .edit(|e| {
                e.set_unprotected(fields::TITLE, format!("item {i}"));
                e.set_protected(fields::PASSWORD, format!("base {i}"));
            })
            .id();
        if i % 2 == 0 {
            db.entry_mut(id).expect("entry").add_attachment(
                "base.txt",
                Value::unprotected(format!("base {i}").into_bytes()),
            );
        }
    }
    stamp(&mut db, 0);
    let mut a = db.clone();
    let mut b = db;
    // each copy's clock only moves forward; the two interleave at random
    let (mut ha, mut hb) = (0, 0);
    for n in 0..6 {
        ha += 1 + rng.below(4) as u32;
        hb += 1 + rng.below(4) as u32;
        random_edit(&mut a, &mut rng, ha, n);
        random_edit(&mut b, &mut rng, hb, n + 100);
    }
    (a, b)
}

/// An entry version's visible content, in plain text (tests only).
fn version(e: &EntryRef<'_>) -> String {
    let mut f: Vec<String> = e
        .fields
        .iter()
        .map(|(k, v)| format!("{k}={}{}", v.get(), if v.is_protected() { "*" } else { "" }))
        .collect();
    f.sort();
    let mut a: Vec<String> = e
        .attachments_named()
        .map(|(n, a)| format!("{n}={:?}", a.data.get()))
        .collect();
    a.sort();
    format!(
        "{} tags={:?} mod={:?} created={:?} files=[{}]",
        f.join(","),
        e.tags,
        e.times.last_modification,
        e.times.creation,
        a.join(",")
    )
}

/// What two merges must agree on: every entry with its place and history,
/// every group, the metadata and the deletions. Not the previous parent
/// (a move remembers where it came from in this copy) and not the
/// program that wrote the file.
fn content(db: &Database) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for e in db.iter_all_entries() {
        let mut s = format!(
            "parent={} moved={:?} access={:?} uses={:?} {}",
            e.parent().id(),
            e.times.location_changed,
            e.times.last_access,
            e.times.usage_count,
            version(&e)
        );
        let n = e.history.as_ref().map_or(0, |h| h.get_entries().len());
        for i in 0..n {
            s += &format!(" | {}", version(&e.historical(i).expect("history")));
        }
        out.insert(format!("entry {}", e.id()), s);
    }
    for g in db.iter_all_groups() {
        out.insert(
            format!("group {}", g.id()),
            format!(
                "parent={:?} name={} times={:?}",
                g.parent().map(|p| p.id()),
                g.name,
                g.times
            ),
        );
    }
    let mut meta = db.meta.clone();
    meta.generator = None;
    out.insert("meta".into(), format!("{meta:?}"));
    let mut deleted: Vec<String> = db
        .deleted_objects
        .iter()
        .map(|(k, v)| format!("{k} {v:?}"))
        .collect();
    deleted.sort();
    out.insert("deleted".into(), deleted.join(","));
    out
}

/// Every version an entry has anywhere (current and history), as content.
fn versions_of(db: &Database, id: EntryId) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(e) = db.entry(id) {
        out.insert(version(&e));
        let n = e.history.as_ref().map_or(0, |h| h.get_entries().len());
        for i in 0..n {
            out.insert(version(&e.historical(i).expect("history")));
        }
    }
    out
}

fn same(a: &Database, b: &Database, what: &str) {
    let (x, y) = (content(a), content(b));
    if x != y {
        let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
        for k in keys {
            if x.get(k) != y.get(k) {
                panic!(
                    "{what}: {k}\n  left:  {:?}\n  right: {:?}",
                    x.get(k),
                    y.get(k)
                );
            }
        }
    }
}

#[test]
fn random_edits_merge_the_same_both_ways_and_lose_nothing() {
    // SAFE_MERGE_SEEDS=5000 cargo test … for a longer hunt
    let seeds: u64 = std::env::var("SAFE_MERGE_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut seen = Report::default();
    for seed in 1..=seeds {
        let (a, b) = scenario(seed);
        let (ab, r) = merged(&a, &b);
        seen.added += r.added;
        seen.updated += r.updated;
        seen.diverged += r.diverged;
        seen.to_history += r.to_history;
        seen.deleted += r.deleted;
        seen.moved += r.moved;
        seen.groups_added += r.groups_added;
        seen.groups_deleted += r.groups_deleted;
        let (ba, _) = merged(&b, &a);
        same(&ab, &ba, &format!("seed {seed}: merge(a,b) vs merge(b,a)"));

        for x in [&a, &b, &ab] {
            let (xx, r) = merged(x, x);
            same(&xx, x, &format!("seed {seed}: merging a copy with itself"));
            assert_eq!(r, Report::default(), "seed {seed}");
        }
        let (again, _) = merged(&ab, &a);
        same(&again, &ab, &format!("seed {seed}: merging a again"));
        let (again, _) = merged(&ab, &b);
        same(&again, &ab, &format!("seed {seed}: merging b again"));

        let mut all: Vec<EntryId> = ids(&a).into_iter().chain(ids(&b)).collect();
        all.sort_by_key(|i| i.uuid());
        all.dedup();
        for id in all {
            if ab.entry(id).is_none() {
                assert!(
                    ab.deleted_objects.contains_key(&id.uuid()),
                    "seed {seed}: {id} vanished with no deletion recorded"
                );
                continue;
            }
            let kept = versions_of(&ab, id);
            for side in [&a, &b] {
                for v in versions_of(side, id) {
                    assert!(
                        kept.contains(&v),
                        "seed {seed}: {id} lost a version: {v}\n  kept: {kept:?}"
                    );
                }
            }
        }
    }
    eprintln!("{seeds} seeds: {seen:?}");
    // the scenarios must reach every rule, or the properties prove little
    assert!(seen.added > 0 && seen.updated > 0 && seen.diverged > 0);
    assert!(seen.to_history > 0 && seen.deleted > 0 && seen.moved > 0);
    assert!(seen.groups_deleted > 0, "two recycle bins never met");
}

// ── deletions through Safe (C3) ─────────────────────────────────────────────

fn login(title: &str, password: &str) -> Draft {
    Draft {
        kind: Kind::Login,
        title: title.into(),
        username: "sam".into(),
        password: Zeroizing::new(password.into()),
        ..Draft::default()
    }
}

fn safe_cheap() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

#[test]
fn a_deletion_survives_a_merge_with_a_copy_that_still_has_the_item() {
    let k = key("correct horse", None).expect("key");
    let mut a = Safe::create("x", safe_cheap());
    let keep = a.add(&login("Keep", "1")).expect("add");
    let gone = a.add(&login("Gone", "2")).expect("add");
    let bytes = a.to_bytes(&k).expect("write");
    let b = Safe::open(&bytes, &k).expect("open");

    a.trash(&gone).expect("trash");
    a.purge(&gone).expect("purge");

    let mut a2 = Safe::open(&a.to_bytes(&k).expect("write"), &k).expect("open");
    let r = a2.merge(&b).expect("merge");
    assert_eq!(r.added, 0, "the old copy does not bring it back");
    assert!(a2.summary(&gone).is_err());
    a2.to_bytes(&k).expect("verified write");

    let mut b2 = Safe::open(&bytes, &k).expect("open");
    let r = b2.merge(&a).expect("merge");
    assert_eq!(r.deleted, 1, "the deletion reaches the other copy");
    assert!(b2.summary(&gone).is_err());
    assert!(b2.summary(&keep).is_ok());
    b2.to_bytes(&k).expect("verified write");
}

#[test]
fn emptying_the_bin_records_every_deletion() {
    let k = key("correct horse", None).expect("key");
    let mut a = Safe::create("x", safe_cheap());
    let ids: Vec<String> = (0..3)
        .map(|i| a.add(&login(&format!("i{i}"), "x")).expect("add"))
        .collect();
    let bytes = a.to_bytes(&k).expect("write");
    for id in &ids {
        a.trash(id).expect("trash");
    }
    assert_eq!(a.empty_bin().expect("empty"), 3);
    assert!(a.deleted().is_empty() && a.items().is_empty());
    let mut b = Safe::open(&bytes, &k).expect("open");
    let r = b.merge(&a).expect("merge");
    assert_eq!(r.deleted, 3);
    assert!(b.items().is_empty());
}

#[test]
fn trash_and_restore_add_no_history() {
    let mut a = Safe::create("x", safe_cheap());
    let id = a.add(&login("Bank", "x")).expect("add");
    a.trash(&id).expect("trash");
    a.restore(&id).expect("restore");
    let eid = EntryId::from_uuid(uuid::Uuid::parse_str(&id).expect("uuid"));
    let e = a.database().entry(eid).expect("entry");
    assert_eq!(e.history.as_ref().map_or(0, |h| h.get_entries().len()), 0);
}
