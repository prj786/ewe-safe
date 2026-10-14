//! Merge spike (PLAN.md phase 0): keepass-rs `Database::merge` (feature
//! `_merge`) against the five rules of PLAN.md §7, one case per rule, with
//! fixed times so every run is the same. Prints one row per case and a
//! JSON summary; never fails, the table is the result.
//!
//!   cargo run -p safe-core --example merge-spike

use chrono::{NaiveDate, NaiveDateTime};
use keepass::Database;
use keepass::db::{EntryId, GroupId, fields};

fn t(hour: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 1, 1)
        .and_then(|d| d.and_hms_opt(hour, 0, 0))
        .expect("valid time")
}

struct Base {
    db: Database,
    entry: EntryId,
    group: GroupId,
}

/// One group "Work" with one login "mail", everything stamped at hour 0.
fn base() -> Base {
    let mut db = Database::new();
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
    db.foreach_entry_mut(|mut e| {
        e.times.creation = Some(t(0));
        e.times.last_modification = Some(t(0));
        e.times.location_changed = Some(t(0));
    });
    db.foreach_group_mut(|mut g| {
        g.times.creation = Some(t(0));
        g.times.last_modification = Some(t(0));
        g.times.location_changed = Some(t(0));
    });
    Base { db, entry, group }
}

/// Change the password the way Safe will (history-tracked), stamped at `hour`.
fn set_password(db: &mut Database, id: EntryId, value: &str, hour: u32) {
    let mut e = db.entry_mut(id).expect("entry");
    e.edit_tracking(|e| e.set_protected(fields::PASSWORD, value));
    e.times.last_modification = Some(t(hour));
}

/// Delete through the tracked path (records DeletedObjects), stamped at `hour`.
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

struct Case {
    rule: &'static str,
    name: &'static str,
    pass: bool,
    detail: String,
}

fn merged(dest: &Database, source: &Database) -> (Database, Vec<String>, String) {
    let mut d = dest.clone();
    match d.merge(source) {
        Ok(log) => (d, log.warnings, String::new()),
        Err(e) => (dest.clone(), vec![], format!("merge error: {e}")),
    }
}

fn main() {
    let mut cases = Vec::new();

    // 1 — new on either side is kept
    {
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
        let (m, w, err) = merged(&mine, &theirs);
        let pass = err.is_empty() && m.entry(new_theirs).is_some() && m.entry(new_mine).is_some();
        cases.push(Case {
            rule: "1",
            name: "an entry new on either side is kept",
            pass,
            detail: format!("{err} warnings={w:?}"),
        });
    }

    // 2 — both edited: newer wins, the older version lands in history (both directions)
    for (label, mine_hour, theirs_hour) in [("theirs newer", 1, 2), ("mine newer", 2, 1)] {
        let b = base();
        let mut mine = b.db.clone();
        let mut theirs = b.db.clone();
        set_password(&mut mine, b.entry, "mine", mine_hour);
        set_password(&mut theirs, b.entry, "theirs", theirs_hour);
        let want = if theirs_hour > mine_hour {
            "theirs"
        } else {
            "mine"
        };
        let lose = if want == "theirs" { "mine" } else { "theirs" };
        let (m, w, err) = merged(&mine, &theirs);
        let (m2, _, err2) = merged(&theirs, &mine);
        let got = password(&m, b.entry);
        let got2 = password(&m2, b.entry);
        let hist = history_passwords(&m, b.entry);
        let pass = err.is_empty()
            && err2.is_empty()
            && got.as_deref() == Some(want)
            && got2.as_deref() == Some(want)
            && hist.iter().any(|p| p == lose)
            && hist.iter().any(|p| p == "one");
        cases.push(Case {
            rule: "2",
            name: if label == "theirs newer" {
                "both edited, theirs newer: theirs wins, mine kept in history; same result merged the other way"
            } else {
                "both edited, mine newer: mine wins, theirs kept in history; same result merged the other way"
            },
            pass,
            detail: format!("{err}{err2} result={got:?} other-way={got2:?} history={hist:?} warnings={w:?}"),
        });
    }

    // 3 — deleted on one side, edited on the other AFTER the deletion: the edit wins
    {
        let b = base();
        let mut mine = b.db.clone();
        let mut theirs = b.db.clone();
        delete(&mut theirs, b.entry, 1);
        set_password(&mut mine, b.entry, "edited later", 2);
        let (m, w, err) = merged(&mine, &theirs);
        let (m2, _, err2) = merged(&theirs, &mine);
        let pass = err.is_empty()
            && err2.is_empty()
            && password(&m, b.entry).as_deref() == Some("edited later")
            && password(&m2, b.entry).as_deref() == Some("edited later");
        cases.push(Case {
            rule: "3",
            name: "deleted there at 1, edited here at 2: the edit wins (both directions)",
            pass,
            detail: format!(
                "{err}{err2} here={:?} there={:?} warnings={w:?}",
                password(&m, b.entry),
                password(&m2, b.entry)
            ),
        });
    }

    // 4 — deleted AFTER the other side's edit: the deletion wins
    {
        let b = base();
        let mut mine = b.db.clone();
        let mut theirs = b.db.clone();
        set_password(&mut mine, b.entry, "edited earlier", 1);
        delete(&mut theirs, b.entry, 2);
        let (m, w, err) = merged(&mine, &theirs);
        let (m2, _, err2) = merged(&theirs, &mine);
        let pass = err.is_empty()
            && err2.is_empty()
            && m.entry(b.entry).is_none()
            && m2.entry(b.entry).is_none()
            && m.deleted_objects.contains_key(&b.entry.uuid());
        cases.push(Case {
            rule: "3",
            name: "edited here at 1, deleted there at 2: the deletion wins (both directions) and is recorded",
            pass,
            detail: format!(
                "{err}{err2} here={:?} there={:?} warnings={w:?}",
                password(&m, b.entry),
                password(&m2, b.entry)
            ),
        });
    }

    // 5 — a plain, untracked removal is not a deletion: merge brings it back
    {
        let b = base();
        let mine = b.db.clone();
        let mut theirs = b.db.clone();
        theirs.entry_mut(b.entry).expect("entry").remove();
        let (m, _, err) = merged(&theirs, &mine);
        cases.push(Case {
            rule: "3",
            name: "merge deletes only what DeletedObjects names (an untracked removal comes back)",
            pass: err.is_empty() && m.entry(b.entry).is_some(),
            detail: err,
        });
    }

    // 6 — groups: newer rename wins
    for (label, mine_hour, theirs_hour) in [("theirs newer", 1, 2), ("mine newer", 2, 1)] {
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
        let (m, w, err) = merged(&mine, &theirs);
        let got = m.group(b.group).map(|g| g.name.clone());
        cases.push(Case {
            rule: "4",
            name: if label == "theirs newer" {
                "group renamed both sides, theirs newer: theirs wins"
            } else {
                "group renamed both sides, mine newer: mine wins"
            },
            pass: err.is_empty() && got.as_deref() == Some(want),
            detail: format!("{err} got={got:?} warnings={w:?}"),
        });
    }

    // 7 — a move on the other side, newer: followed
    {
        let mut b = base();
        let other =
            b.db.root_mut()
                .add_group()
                .edit(|g| g.name = "Home".into())
                .id();
        b.db.foreach_group_mut(|mut g| {
            g.times.last_modification = Some(t(0));
            g.times.location_changed = Some(t(0));
        });
        let mine = b.db.clone();
        let mut theirs = b.db.clone();
        {
            let mut e = theirs.entry_mut(b.entry).expect("entry");
            e.move_to(other).expect("move");
            e.times.location_changed = Some(t(2));
        }
        let (m, w, err) = merged(&mine, &theirs);
        let parent = m.entry(b.entry).map(|e| e.parent().id());
        cases.push(Case {
            rule: "4",
            name: "entry moved to another group there (newer): followed here",
            pass: err.is_empty() && parent == Some(other),
            detail: format!("{err} warnings={w:?}"),
        });
    }

    // 8 — metadata: newer database name wins
    {
        let b = base();
        let mut mine = b.db.clone();
        let mut theirs = b.db.clone();
        mine.meta.database_name = Some("Mine".into());
        mine.meta.database_name_changed = Some(t(1));
        theirs.meta.database_name = Some("Theirs".into());
        theirs.meta.database_name_changed = Some(t(2));
        let (m, w, err) = merged(&mine, &theirs);
        cases.push(Case {
            rule: "4",
            name: "metadata (database name) changed both sides: newer wins",
            pass: err.is_empty() && m.meta.database_name.as_deref() == Some("Theirs"),
            detail: format!("{err} got={:?} warnings={w:?}", m.meta.database_name),
        });
    }

    // 9 — idempotence: merging a copy of yourself changes nothing
    {
        let b = base();
        let mut x = b.db.clone();
        set_password(&mut x, b.entry, "two", 1);
        let (m, _, err) = merged(&x, &x.clone());
        cases.push(Case {
            rule: "-",
            name: "merging an identical copy changes nothing",
            pass: err.is_empty() && m == x,
            detail: err,
        });
    }

    // 10 — attachments come across with a new entry
    {
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
            .add_attachment("a.txt", keepass::db::Value::unprotected(b"hello".to_vec()));
        let (m, w, err) = merged(&mine, &theirs);
        let n = m.entry(id).map(|e| e.attachments().count()).unwrap_or(0);
        cases.push(Case {
            rule: "1",
            name: "a new entry's attachment comes across",
            pass: err.is_empty() && n == 1,
            detail: format!("{err} attachments={n} warnings={w:?}"),
        });
    }

    // 11 — an attachment added to an EXISTING entry there (newer) comes across
    {
        let b = base();
        let mine = b.db.clone();
        let mut theirs = b.db.clone();
        {
            let mut e = theirs.entry_mut(b.entry).expect("entry");
            e.edit_tracking(|e| {
                e.add_attachment(
                    "scan.pdf",
                    keepass::db::Value::unprotected(b"%PDF".to_vec()),
                );
            });
            e.times.last_modification = Some(t(2));
        }
        let (m, w, err) = merged(&mine, &theirs);
        let n = m
            .entry(b.entry)
            .map(|e| e.attachments().count())
            .unwrap_or(0);
        cases.push(Case {
            rule: "2",
            name: "attachment added to an existing entry there (newer): it comes across",
            pass: err.is_empty() && n == 1,
            detail: format!("{err} attachments={n} warnings={w:?}"),
        });
    }

    // 12 — two different edits stamped in the same second (Times::now is whole seconds)
    {
        let b = base();
        let mut mine = b.db.clone();
        let mut theirs = b.db.clone();
        set_password(&mut mine, b.entry, "mine", 1);
        set_password(&mut theirs, b.entry, "theirs", 1);
        let (m, _, err) = merged(&mine, &theirs);
        let hist = history_passwords(&m, b.entry);
        cases.push(Case {
            rule: "2",
            name: "different edits in the same second: one wins, the other is kept in history",
            pass: err.is_empty() && hist.iter().any(|p| p == "theirs" || p == "mine"),
            detail: format!("{err} result={:?} history={hist:?}", password(&m, b.entry)),
        });
    }

    let passed = cases.iter().filter(|c| c.pass).count();
    for c in &cases {
        println!(
            "{}  rule {}  {}{}",
            if c.pass { "PASS" } else { "FAIL" },
            c.rule,
            c.name,
            if c.detail.trim().is_empty() || c.pass {
                String::new()
            } else {
                format!("\n      {}", c.detail.trim())
            }
        );
    }
    println!("{passed} of {} cases pass", cases.len());
}
