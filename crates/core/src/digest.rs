//! What a safe holds, as sorted lines, for the verify step of a write.
//!
//! keepass-rs's own `PartialEq` also compares bookkeeping that a write
//! legitimately rebuilds (an attachment's list of the entries that use it
//! misses the history copy a tracked edit made). So the write compares
//! content instead: every field, time, tag, attachment and icon, with each
//! value as a keyed hash: no plaintext stays in the lines.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};

use keepass::Database;
use keepass::db::{CustomDataItem, EntryRef, GroupRef};

use crate::item::custom_text;

pub struct Digester {
    keys: RandomState,
}

impl Digester {
    pub fn new() -> Digester {
        Digester {
            keys: RandomState::new(),
        }
    }

    fn h(&self, v: impl Hash) -> u64 {
        self.keys.hash_one(v)
    }

    fn custom(&self, out: &mut Vec<String>, at: &str, data: &HashMap<String, CustomDataItem>) {
        for (k, item) in data {
            let text = item.value.as_ref().map(custom_text);
            out.push(format!(
                "{at} custom {k}={:x} t={:?}",
                self.h(text),
                item.last_modification_time
            ));
        }
    }

    fn entry(&self, out: &mut Vec<String>, at: &str, e: &EntryRef<'_>) {
        out.push(format!(
            "{at} parent={} previous={:?} tags={:?} times={:?} icon={:?} fg={:?} bg={:?} url={:?} quality={} autotype={:?}",
            e.parent().id(),
            e.previous_parent().map(|g| g.id()),
            e.tags,
            e.times,
            e.icon(),
            e.foreground_color,
            e.background_color,
            e.override_url,
            e.quality_check,
            e.autotype,
        ));
        for (k, v) in &e.fields {
            out.push(format!(
                "{at} field {k} protected={} {:x}",
                v.is_protected(),
                self.h(v.get())
            ));
        }
        self.custom(out, at, &e.custom_data);
        for (name, a) in e.attachments_named() {
            out.push(format!(
                "{at} attachment {name} protected={} {:x}",
                a.data.is_protected(),
                self.h(a.data.get())
            ));
        }
        let versions = e.history.as_ref().map_or(0, |h| h.get_entries().len());
        for i in 0..versions {
            if let Some(old) = e.historical(i) {
                self.entry(out, &format!("{at} history[{i}]"), &old);
            }
        }
    }

    fn group(&self, out: &mut Vec<String>, g: &GroupRef<'_>) {
        let at = format!("group {}", g.id());
        out.push(format!(
            "{at} parent={:?} previous={:?} name={:?} notes={:x} tags={:?} times={:?} icon={:?} expanded={} sequence={:?} autotype={:?} searching={:?}",
            g.parent().map(|p| p.id()),
            g.previous_parent().map(|p| p.id()),
            g.name,
            self.h(&g.notes),
            g.tags,
            g.times,
            g.icon(),
            g.is_expanded,
            g.default_autotype_sequence,
            g.enable_autotype,
            g.enable_searching,
        ));
        self.custom(out, &at, &g.custom_data);
    }

    pub fn digest(&self, db: &Database) -> Vec<String> {
        let mut out = Vec::new();
        let c = &db.config;
        out.push(format!(
            "config {:?} {:?} {:?} {:?} {:?}",
            c.version,
            c.outer_cipher_config,
            c.compression_config,
            c.inner_cipher_config,
            c.kdf_config
        ));
        if let Some(public) = &c.public_custom_data {
            for (k, v) in public.iter() {
                out.push(format!("config public {k} {:x}", self.h(format!("{v:?}"))));
            }
        }
        let mut meta = db.meta.clone();
        let meta_custom = std::mem::take(&mut meta.custom_data);
        out.push(format!("meta {:x}", self.h(format!("{meta:?}"))));
        self.custom(&mut out, "meta", &meta_custom);
        for icon in db.iter_all_custom_icons() {
            out.push(format!(
                "icon {:?} name={:?} t={:?} {:x}",
                icon.id(),
                icon.name,
                icon.last_modification_time,
                self.h(&icon.data)
            ));
        }
        for g in db.iter_all_groups() {
            self.group(&mut out, &g);
        }
        for e in db.iter_all_entries() {
            self.entry(&mut out, &format!("entry {}", e.id()), &e);
        }
        for (uuid, when) in &db.deleted_objects {
            out.push(format!("deleted {uuid} {when:?}"));
        }
        out.sort();
        out
    }
}

/// Lines in one digest and not the other, for the verify error.
pub fn differences(a: &[String], b: &[String]) -> Vec<String> {
    let mut d: Vec<String> = a
        .iter()
        .filter(|l| !b.contains(l))
        .map(|l| format!("- {l}"))
        .collect();
    d.extend(
        b.iter()
            .filter(|l| !a.contains(l))
            .map(|l| format!("+ {l}")),
    );
    d
}

impl Default for Digester {
    fn default() -> Self {
        Digester::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::fields;

    fn db() -> Database {
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Bank");
            e.set_protected(fields::PASSWORD, "hunter2-secret");
        });
        db
    }

    #[test]
    fn the_same_content_digests_the_same_and_shows_no_secret() {
        let d = Digester::new();
        let a = db();
        let lines = d.digest(&a);
        assert_eq!(lines, d.digest(&a.clone()));
        assert!(lines.iter().all(|l| !l.contains("hunter2-secret")));
    }

    #[test]
    fn a_changed_password_is_seen() {
        let d = Digester::new();
        let a = db();
        let mut b = a.clone();
        b.foreach_entry_mut(|mut e| e.set_protected(fields::PASSWORD, "other"));
        let (x, y) = (d.digest(&a), d.digest(&b));
        assert_ne!(x, y);
        let diff = differences(&x, &y);
        assert_eq!(diff.len(), 2);
        assert!(diff[0].contains("field Password"));
    }
}
