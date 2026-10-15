//! Merging two copies of one safe (PLAN.md §7; the rules as built are in
//! docs/FORMAT.md, "Merge").
//!
//! keepass-rs's own merge loses data (docs/SPIKE-0.md §2, M1–M4), so Safe
//! merges itself, on keepass-rs's model and through its public API only:
//!
//! - Entries and groups are matched by UUID; one that is new on either side
//!   is kept.
//! - When both copies changed an entry, the newer `LastModificationTime`
//!   wins and the other version joins the entry's history. Equal times are
//!   settled by a hash of the content, so both machines pick the same one.
//! - One exception inside an entry: its passkey ([`carry_passkey`]). When
//!   only the losing side changed the passkey since the newest version both
//!   copies share, its passkey goes onto the winner, and the winner's own
//!   version joins the history too.
//! - Deletions come only from `DeletedObjects` (the union of both copies). A
//!   deletion wins over a copy last changed at or before it and loses to a
//!   later change.
//! - Groups and metadata: the newer change wins. Entries and groups follow
//!   the newer `LocationChanged`.
//! - Two recycle bins (both machines trashed something before they synced)
//!   become one.
//!
//! A history version is made the one way keepass-rs allows: the entry is
//! given that version's content and a copy of it goes into the history.
//! That relies on the vendored keepass-rs keeping an attachment while any
//! history version still uses it (vendor/keepass/PATCHED.md; FORMAT.md,
//! F10/F11). At the end the database is written and read back in memory
//! ([`normalize`]), then the attachments nothing uses any more are dropped.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use chrono::NaiveDateTime;
use keepass::config::{
    CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig,
};
use keepass::db::{
    CustomDataItem, CustomIconId, CustomIconRef, Entry, EntryId, EntryRef, GroupId, GroupRef,
    History, Icon, Meta, Times, Value,
};
use keepass::{Database, DatabaseKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::item::custom_text;
use crate::passkey;
use crate::safe::HISTORY_MAX_ITEMS;

type Time = Option<NaiveDateTime>;
type Hash = [u8; 32];

/// What a merge did to this copy, as counts: never a title or a value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Items that were only in the other copy.
    pub added: usize,
    /// Items whose current version changed here: the other copy's was
    /// newer, or its passkey came over.
    pub updated: usize,
    /// Items both copies changed: one version won, the other is in history.
    pub diverged: usize,
    /// Versions that joined an item's history here.
    pub to_history: usize,
    /// Items the other copy's deletion removed here.
    pub deleted: usize,
    /// Items that took their folder from the other copy.
    pub moved: usize,
    pub groups_added: usize,
    pub groups_deleted: usize,
}

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "merge failed: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Merge `theirs` into `ours`. The result keeps `ours`' file settings
/// (cipher, key derivation); the caller writes it with its own key.
pub fn merge(ours: &Database, theirs: &Database) -> Result<(Database, Report), Error> {
    let mut out = ours.clone();
    let mut report = Report::default();
    let root = ours.root().id();
    let their_root = theirs.root().id();
    // two copies of one safe share the root; for two unrelated files the
    // other root is read as this one
    let map = move |g: GroupId| if g == their_root { root } else { g };

    let mut deleted = ours.deleted_objects.clone();
    for (uuid, when) in &theirs.deleted_objects {
        let mine = deleted.entry(*uuid).or_insert(*when);
        if *when > *mine {
            *mine = *when;
        }
    }
    out.deleted_objects = deleted.clone();
    out.meta = merge_meta(&ours.meta, &theirs.meta);
    let cap = history_cap(&out.meta);

    merge_groups(&mut out, ours, theirs, &map, &mut report)?;
    merge_entries(&mut out, ours, theirs, &map, &deleted, cap, &mut report)?;
    unify_bins(&mut out, ours, theirs, &mut report);
    prune_groups(&mut out, ours, theirs, &deleted, &mut report);

    let mut out = normalize(&out)?;
    collect_garbage(&mut out, ours);
    Ok((out, report))
}

/// The database written and read back in memory with a throwaway key. The
/// read renumbers the attachments, rebuilds which entries use each custom
/// icon and drops every back-reference to a history position, so removing
/// an unused attachment or icon afterwards follows no stale one. The
/// result keeps `db`'s file settings.
pub(crate) fn normalize(db: &Database) -> Result<Database, Error> {
    let mut tmp = db.clone();
    tmp.config.version = DatabaseVersion::KDB4(1);
    tmp.config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    tmp.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    tmp.config.compression_config = CompressionConfig::None;
    tmp.config.kdf_config = KdfConfig::Aes { rounds: 1 };
    let key = DatabaseKey::new().with_password("ewe-safe merge, in memory only");
    let mut bytes = Zeroizing::new(Vec::new());
    tmp.save(&mut *bytes, key.clone())
        .map_err(|e| Error(format!("write in memory: {e}")))?;
    let mut back =
        Database::parse(&bytes, key).map_err(|e| Error(format!("read in memory: {e}")))?;
    back.config = db.config.clone();
    Ok(back)
}

struct Hasher(Sha256);

impl Hasher {
    fn new() -> Hasher {
        Hasher(Sha256::new())
    }

    fn bytes(&mut self, b: &[u8]) {
        self.0.update((b.len() as u64).to_le_bytes());
        self.0.update(b);
    }

    fn text(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    fn debug(&mut self, v: &impl Debug) {
        self.text(&format!("{v:?}"));
    }

    fn custom(&mut self, data: &HashMap<String, CustomDataItem>) {
        let mut keys: Vec<&String> = data.keys().collect();
        keys.sort();
        for k in keys {
            let item = &data[k];
            self.text(k);
            self.debug(&item.value.as_ref().map(custom_text));
            self.debug(&item.last_modification_time);
        }
    }

    /// A custom icon by its picture, not its id: copies of one icon made on
    /// two machines have different ids.
    fn icon(&mut self, icon: Option<&Icon>, custom: Option<CustomIconRef<'_>>) {
        match (icon, custom) {
            (Some(Icon::Custom(_)), Some(c)) => {
                self.text("custom");
                self.bytes(&c.data);
            }
            (Some(Icon::BuiltIn(n)), _) => {
                self.text("builtin");
                self.debug(n);
            }
            _ => self.text("none"),
        }
    }

    fn done(self) -> Hash {
        self.0.finalize().into()
    }
}

fn debug_hash(v: &impl Debug) -> Hash {
    let mut h = Hasher::new();
    h.debug(v);
    h.done()
}

/// An entry version's content: everything but its place, its history and
/// the read-only counters (last access, usage count).
fn entry_hash(e: &EntryRef<'_>) -> Hash {
    content_hash(e, &e.fields, &e.tags)
}

/// [`entry_hash`] of `e` with these fields and tags instead of its own.
fn content_hash(
    e: &EntryRef<'_>,
    fields: &HashMap<String, Value<String>>,
    tags: &[String],
) -> Hash {
    let mut h = Hasher::new();
    let mut keys: Vec<&String> = fields.keys().collect();
    keys.sort();
    for k in keys {
        let v = &fields[k];
        h.text(k);
        h.bytes(&[u8::from(v.is_protected())]);
        h.text(v.get());
    }
    h.debug(&tags);
    let t = &e.times;
    h.debug(&(t.creation, t.last_modification, t.expiry, t.expires));
    h.custom(&e.custom_data);
    h.icon(e.icon(), e.custom_icon());
    h.debug(&(
        &e.foreground_color,
        &e.background_color,
        &e.override_url,
        e.quality_check,
        &e.autotype,
    ));
    let mut files: Vec<_> = e.attachments_named().collect();
    files.sort_by(|a, b| a.0.cmp(b.0));
    for (name, a) in files {
        h.text(name);
        h.bytes(&[u8::from(a.data.is_protected())]);
        h.bytes(a.data.get());
    }
    h.done()
}

fn group_hash(g: &GroupRef<'_>) -> Hash {
    let mut h = Hasher::new();
    h.text(&g.name);
    h.debug(&g.notes);
    h.debug(&g.tags);
    let t = &g.times;
    h.debug(&(t.creation, t.last_modification, t.expiry, t.expires));
    h.custom(&g.custom_data);
    h.icon(g.icon(), g.custom_icon());
    h.debug(&(
        g.is_expanded,
        &g.default_autotype_sequence,
        g.enable_autotype,
        g.enable_searching,
    ));
    h.done()
}

/// The newer of two values with their change times; equal times go to the
/// larger hash, so both machines pick the same one.
fn newer<T: Debug>(ours: T, ours_at: Time, theirs: T, theirs_at: Time) -> (T, Time) {
    if (theirs_at, debug_hash(&theirs)) > (ours_at, debug_hash(&ours)) {
        (theirs, theirs_at)
    } else {
        (ours, ours_at)
    }
}

fn merge_meta(o: &Meta, t: &Meta) -> Meta {
    let mut m = o.clone();
    (m.database_name, m.database_name_changed) = newer(
        o.database_name.clone(),
        o.database_name_changed,
        t.database_name.clone(),
        t.database_name_changed,
    );
    (m.database_description, m.database_description_changed) = newer(
        o.database_description.clone(),
        o.database_description_changed,
        t.database_description.clone(),
        t.database_description_changed,
    );
    (m.default_username, m.default_username_changed) = newer(
        o.default_username.clone(),
        o.default_username_changed,
        t.default_username.clone(),
        t.default_username_changed,
    );
    (
        (m.recyclebin_enabled, m.recyclebin_uuid),
        m.recyclebin_changed,
    ) = newer(
        (o.recyclebin_enabled, o.recyclebin_uuid),
        o.recyclebin_changed,
        (t.recyclebin_enabled, t.recyclebin_uuid),
        t.recyclebin_changed,
    );
    (m.entry_templates_group, m.entry_templates_group_changed) = newer(
        o.entry_templates_group,
        o.entry_templates_group_changed,
        t.entry_templates_group,
        t.entry_templates_group_changed,
    );
    let settings = |x: &Meta| {
        (
            x.maintenance_history_days,
            x.color.clone(),
            x.master_key_change_rec,
            x.master_key_change_force,
            x.memory_protection.clone(),
            x.history_max_items,
            x.history_max_size,
        )
    };
    let (s, at) = newer(
        settings(o),
        o.settings_changed,
        settings(t),
        t.settings_changed,
    );
    (
        m.maintenance_history_days,
        m.color,
        m.master_key_change_rec,
        m.master_key_change_force,
        m.memory_protection,
        m.history_max_items,
        m.history_max_size,
    ) = s;
    m.settings_changed = at;
    m.master_key_changed = o.master_key_changed.max(t.master_key_changed);
    m.custom_data = merge_custom(&o.custom_data, &t.custom_data);
    m
}

/// Metadata custom data, key by key; a key removed on one side cannot be
/// told from one never added, so keys only accumulate.
fn merge_custom(
    o: &HashMap<String, CustomDataItem>,
    t: &HashMap<String, CustomDataItem>,
) -> HashMap<String, CustomDataItem> {
    let key = |i: &CustomDataItem| {
        (
            i.last_modification_time,
            debug_hash(&i.value.as_ref().map(custom_text)),
        )
    };
    let mut out = o.clone();
    for (k, ti) in t {
        if o.get(k).is_none_or(|oi| key(ti) > key(oi)) {
            out.insert(k.clone(), ti.clone());
        }
    }
    out
}

/// How many history versions an entry keeps; None = no limit.
fn history_cap(meta: &Meta) -> Option<usize> {
    match meta.history_max_items {
        Some(n) => usize::try_from(n).ok(),
        None => Some(HISTORY_MAX_ITEMS),
    }
}

/// Where an object sits, for comparing two copies: a copy's recycle bin is
/// "the bin" whatever its id, since two bins become one (and a same-second
/// trash wins over a move).
fn place(db: &Database, g: GroupId) -> Uuid {
    if db.meta.recyclebin_uuid == Some(g.uuid()) {
        Uuid::from_u128(u128::MAX)
    } else {
        g.uuid()
    }
}

fn changed_at(t: &Times) -> Time {
    t.last_modification.max(t.location_changed)
}

/// A deletion wins over an object last changed at or before it. One with
/// no time is honoured nowhere: keeping an item is the safe mistake.
fn deletion_wins(deleted: &HashMap<Uuid, Time>, uuid: Uuid, times: &Times) -> bool {
    matches!(deleted.get(&uuid), Some(Some(d)) if changed_at(times) <= Some(*d))
}

enum IconPlan {
    None,
    BuiltIn(usize),
    Existing(CustomIconId),
    New {
        data: Vec<u8>,
        name: Option<String>,
        time: Time,
    },
}

/// The icon to give an object in `out` so it shows `icon`: a custom icon is
/// reused when `out` has the same picture, otherwise copied.
fn icon_plan(out: &Database, icon: Option<&Icon>, custom: Option<CustomIconRef<'_>>) -> IconPlan {
    match (icon, custom) {
        (Some(Icon::BuiltIn(n)), _) => IconPlan::BuiltIn(*n),
        (Some(Icon::Custom(_)), Some(c)) => {
            if let Some(same) = out.custom_icon(c.id()).filter(|i| i.data == c.data) {
                return IconPlan::Existing(same.id());
            }
            match out
                .iter_all_custom_icons()
                .filter(|i| i.data == c.data)
                .min_by_key(|i| i.id().uuid())
            {
                Some(i) => IconPlan::Existing(i.id()),
                None => IconPlan::New {
                    data: c.data.clone(),
                    name: c.name.clone(),
                    time: c.last_modification_time,
                },
            }
        }
        _ => IconPlan::None,
    }
}

/// Theirs' groups, each after its parent.
fn groups_in_order(db: &Database) -> Vec<GroupId> {
    let mut order = Vec::new();
    let mut stack = vec![db.root().id()];
    while let Some(id) = stack.pop() {
        order.push(id);
        if let Some(g) = db.group(id) {
            let mut children: Vec<GroupId> = g.group_ids().collect();
            children.reverse();
            stack.extend(children);
        }
    }
    order
}

fn set_group(out: &mut Database, id: GroupId, src: &GroupRef<'_>) {
    let plan = icon_plan(out, src.icon(), src.custom_icon());
    let Some(mut g) = out.group_mut(id) else {
        return;
    };
    g.name = src.name.clone();
    g.notes = src.notes.clone();
    g.tags = src.tags.clone();
    g.times = src.times.clone();
    g.custom_data = src.custom_data.clone();
    g.is_expanded = src.is_expanded;
    g.default_autotype_sequence = src.default_autotype_sequence.clone();
    g.enable_autotype = src.enable_autotype;
    g.enable_searching = src.enable_searching;
    match plan {
        IconPlan::None => g.set_icon_none(),
        IconPlan::BuiltIn(n) => g.set_icon_builtin(n),
        IconPlan::Existing(c) => {
            let _ = g.set_icon_custom(c);
        }
        IconPlan::New { data, name, time } => {
            g.set_icon_custom_new(data).edit(|i| {
                i.name = name;
                i.last_modification_time = time;
            });
        }
    }
}

fn is_inside(db: &Database, group: GroupId, ancestor: GroupId) -> bool {
    let mut g = Some(group);
    while let Some(id) = g {
        if id == ancestor {
            return true;
        }
        g = db.group(id).and_then(|x| x.parent().map(|p| p.id()));
    }
    false
}

/// Move a group under `to`, by way of `previous` so that it is remembered
/// as the group's previous parent. A move that would put a group inside
/// itself (each copy moved one into the other) is not made.
fn move_group(out: &mut Database, id: GroupId, to: GroupId, previous: Option<GroupId>) -> bool {
    let Some(cur) = out.group(id).and_then(|g| g.parent().map(|p| p.id())) else {
        return false;
    };
    if cur == to || out.group(to).is_none() || is_inside(out, to, id) {
        return false;
    }
    if let Some(p) = previous
        .filter(|p| *p != to && *p != cur && out.group(*p).is_some() && !is_inside(out, *p, id))
        && let Some(mut g) = out.group_mut(id)
    {
        let _ = g.move_to(p);
    }
    out.group_mut(id).is_some_and(|mut g| g.move_to(to).is_ok())
}

fn merge_groups(
    out: &mut Database,
    ours: &Database,
    theirs: &Database,
    map: &dyn Fn(GroupId) -> GroupId,
    report: &mut Report,
) -> Result<(), Error> {
    let their_root = theirs.root().id();
    for tid in groups_in_order(theirs) {
        let Some(t) = theirs.group(tid) else {
            continue;
        };
        let id = map(tid);
        match ours.group(id) {
            Some(o) => {
                if (t.times.last_modification, group_hash(&t))
                    > (o.times.last_modification, group_hash(&o))
                {
                    set_group(out, id, &t);
                }
                let (Some(op), Some(tp)) = (o.parent().map(|p| p.id()), t.parent().map(|p| p.id()))
                else {
                    continue;
                };
                let (po, pt) = (place(ours, op), place(theirs, tp));
                let tp = if tp == their_root { map(tp) } else { tp };
                let located = if po == pt || op == tp {
                    o.times.location_changed.max(t.times.location_changed)
                } else if (t.times.location_changed, pt) > (o.times.location_changed, po)
                    && move_group(out, id, tp, t.previous_parent().map(|p| map(p.id())))
                {
                    t.times.location_changed
                } else {
                    o.times.location_changed
                };
                if let Some(mut g) = out.group_mut(id) {
                    g.times.location_changed = located;
                }
            }
            None => {
                let parent = t.parent().map(|p| map(p.id())).unwrap_or(out.root().id());
                let previous = t
                    .previous_parent()
                    .map(|p| map(p.id()))
                    .filter(|p| *p != parent && out.group(*p).is_some());
                out.group_mut(previous.unwrap_or(parent))
                    .ok_or_else(|| Error(format!("no parent group for group {id}")))?
                    .add_group_with_id(id)
                    .map_err(|e| Error(e.to_string()))?;
                if previous.is_some()
                    && let Some(mut g) = out.group_mut(id)
                {
                    let _ = g.move_to(parent);
                }
                set_group(out, id, &t);
                report.groups_added += 1;
            }
        }
    }
    Ok(())
}

/// A passkey field: KeePassXC's `KPEX_PASSKEY_*` and Strongbox's username.
fn is_passkey_field(name: &str) -> bool {
    name.starts_with(passkey::PREFIX) || name == passkey::KPXC_USERNAME
}

fn has_passkey(e: &Entry) -> bool {
    e.fields.keys().any(|k| is_passkey_field(k)) || e.tags.iter().any(|t| t == passkey::TAG)
}

/// A version's passkey (its fields with their protection, and the tag), as
/// a hash: compared, never kept.
fn passkey_hash(e: &Entry) -> Hash {
    let mut h = Hasher::new();
    let mut keys: Vec<&String> = e.fields.keys().filter(|k| is_passkey_field(k)).collect();
    keys.sort();
    for k in keys {
        let v = &e.fields[k];
        h.text(k);
        h.bytes(&[u8::from(v.is_protected())]);
        h.text(v.get());
    }
    h.debug(&e.tags.iter().any(|t| t == passkey::TAG));
    h.done()
}

/// The passkey of the newest version both copies have (current or in
/// history): what the entry's passkey was before the two diverged. None
/// when they share no version (a history turned off or trimmed).
fn shared_passkey(
    o: &EntryRef<'_>,
    t: &EntryRef<'_>,
    ours_history: &[EntryRef<'_>],
    theirs_history: &[EntryRef<'_>],
) -> Option<Hash> {
    let ours: HashSet<Hash> = ours_history.iter().chain([o]).map(entry_hash).collect();
    theirs_history
        .iter()
        .chain([t])
        .filter_map(|v| {
            let h = entry_hash(v);
            ours.contains(&h)
                .then(|| (v.times.last_modification, h, passkey_hash(v)))
        })
        .max()
        .map(|(_, _, pk)| pk)
}

/// Whether the losing version's passkey goes onto the winner: only the
/// loser changed it (added, replaced or removed) since the shared version.
/// When both changed it, the winner, the newer version, keeps its own. With
/// no shared version, a passkey only the loser has is kept: losing a
/// passkey breaks a sign-in, keeping one breaks nothing.
fn carry_passkey(winner: &EntryRef<'_>, loser: &EntryRef<'_>, shared: Option<Hash>) -> bool {
    let (w, l) = (passkey_hash(winner), passkey_hash(loser));
    w != l
        && match shared {
            Some(base) => w == base,
            None => !has_passkey(winner) && has_passkey(loser),
        }
}

/// The tie-break between two versions with the same time: their content
/// without the passkey first, so a winner that took the loser's passkey
/// still wins against both inputs the next time (merging again changes
/// nothing). Without a passkey this is [`entry_hash`]: the rule for every
/// other item is as it was.
fn rank_hash(e: &EntryRef<'_>) -> Hash {
    if !has_passkey(e) {
        return entry_hash(e);
    }
    let fields: HashMap<String, Value<String>> = e
        .fields
        .iter()
        .filter(|(k, _)| !is_passkey_field(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let tags: Vec<String> = e
        .tags
        .iter()
        .filter(|t| *t != passkey::TAG)
        .cloned()
        .collect();
    content_hash(e, &fields, &tags)
}

/// The winner's fields and tags with the loser's passkey in them.
fn with_passkey_of(
    winner: &EntryRef<'_>,
    loser: &EntryRef<'_>,
) -> (HashMap<String, Value<String>>, Vec<String>) {
    let mut fields: HashMap<String, Value<String>> = winner
        .fields
        .iter()
        .filter(|(k, _)| !is_passkey_field(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, v) in loser.fields.iter().filter(|(k, _)| is_passkey_field(k)) {
        fields.insert(k.clone(), v.clone());
    }
    let mut tags = winner.tags.clone();
    if loser.tags.iter().any(|t| t == passkey::TAG) {
        if !tags.iter().any(|t| t == passkey::TAG) {
            tags.push(passkey::TAG.to_string());
        }
    } else {
        tags.retain(|t| t != passkey::TAG);
    }
    (fields, tags)
}

/// An entry's history versions as stored (a KeePass file lists them oldest
/// first).
fn history_of<'a>(e: &'a EntryRef<'_>) -> Vec<EntryRef<'a>> {
    let n = e.history.as_ref().map_or(0, |h| h.get_entries().len());
    (0..n).filter_map(|i| e.historical(i)).collect()
}

/// Make `out`'s entry `id` look like `v` in everything but its place and
/// its history.
fn set_entry(out: &mut Database, id: EntryId, v: &EntryRef<'_>) {
    let plan = icon_plan(out, v.icon(), v.custom_icon());
    let want: Vec<(String, Value<Vec<u8>>)> = v
        .attachments_named()
        .map(|(n, a)| (n.to_string(), a.data.clone()))
        .collect();
    let Some(mut e) = out.entry_mut(id) else {
        return;
    };
    e.fields = v.fields.clone();
    e.tags = v.tags.clone();
    e.times = v.times.clone();
    e.custom_data = v.custom_data.clone();
    e.foreground_color = v.foreground_color.clone();
    e.background_color = v.background_color.clone();
    e.override_url = v.override_url.clone();
    e.quality_check = v.quality_check;
    e.autotype = v.autotype.clone();
    match plan {
        IconPlan::None => e.set_icon_none(),
        IconPlan::BuiltIn(n) => e.set_icon_builtin(n),
        IconPlan::Existing(c) => {
            let _ = e.set_icon_custom(c);
        }
        IconPlan::New { data, name, time } => {
            e.set_icon_custom_new(data).edit(|i| {
                i.name = name;
                i.last_modification_time = time;
            });
        }
    }
    let have: Vec<(String, Value<Vec<u8>>)> = e
        .as_ref()
        .attachments_named()
        .map(|(n, a)| (n.to_string(), a.data.clone()))
        .collect();
    for (name, _) in &have {
        if !want.iter().any(|(n, _)| n == name) {
            e.remove_attachment_by_name(name);
        }
    }
    for (name, data) in want {
        if !have.iter().any(|(n, d)| *n == name && *d == data) {
            e.add_attachment(name, data);
        }
    }
}

/// Give `out`'s entry `id` the history `versions` (oldest first) and the
/// current state `current`: each version in turn becomes the entry's
/// content and a copy goes into the history.
fn rebuild(
    out: &mut Database,
    id: EntryId,
    versions: &[EntryRef<'_>],
    current: &EntryRef<'_>,
) -> Result<(), Error> {
    let gone = || Error(format!("entry {id} vanished during the merge"));
    out.entry_mut(id).ok_or_else(gone)?.history = Some(History::default());
    for v in versions {
        set_entry(out, id, v);
        let mut version: Entry = (*out.entry(id).ok_or_else(gone)?).clone();
        version.history = None;
        out.entry_mut(id)
            .ok_or_else(gone)?
            .history
            .get_or_insert_default()
            .add_entry(version);
    }
    set_entry(out, id, current);
    // add_entry put each version first: turn the list round, oldest first
    // as a KeePass file has it
    let mut e = out.entry_mut(id).ok_or_else(gone)?;
    if let Some(h) = e.history.take() {
        let mut ordered = History::default();
        for v in h.get_entries().iter().cloned() {
            ordered.add_entry(v);
        }
        e.history = Some(ordered);
    }
    Ok(())
}

/// Move an entry under `to`, by way of `previous` so that it is remembered
/// as the entry's previous parent ("restore" brings it back there).
fn move_entry(out: &mut Database, id: EntryId, to: GroupId, previous: Option<GroupId>) {
    let Some(cur) = out.entry(id).map(|e| e.parent().id()) else {
        return;
    };
    if cur == to || out.group(to).is_none() {
        return;
    }
    if let Some(p) = previous.filter(|p| *p != to && *p != cur && out.group(*p).is_some())
        && let Some(mut e) = out.entry_mut(id)
    {
        let _ = e.move_to(p);
    }
    if let Some(mut e) = out.entry_mut(id) {
        let _ = e.move_to(to);
    }
}

/// An entry only theirs has: copied with its history as it is.
fn add_entry(
    out: &mut Database,
    t: &EntryRef<'_>,
    map: &dyn Fn(GroupId) -> GroupId,
) -> Result<(), Error> {
    let id = t.id();
    let parent = map(t.parent().id());
    let previous = t.previous_parent().map(|p| map(p.id()));
    let first = previous
        .filter(|p| *p != parent && out.group(*p).is_some())
        .unwrap_or(parent);
    out.group_mut(first)
        .ok_or_else(|| Error(format!("no group for entry {id}")))?
        .add_entry_with_id(id)
        .map_err(|e| Error(e.to_string()))?;
    move_entry(out, id, parent, None);
    rebuild(out, id, &history_of(t), t)
}

#[allow(clippy::too_many_arguments)]
fn merge_entry(
    out: &mut Database,
    ours: &Database,
    theirs: &Database,
    o: &EntryRef<'_>,
    t: &EntryRef<'_>,
    map: &dyn Fn(GroupId) -> GroupId,
    cap: Option<usize>,
    report: &mut Report,
) -> Result<(), Error> {
    let id = o.id();
    let (ho, ht) = (entry_hash(o), entry_hash(t));
    let diverged = ho != ht;
    let theirs_wins = diverged
        && (t.times.last_modification, rank_hash(t), ht)
            > (o.times.last_modification, rank_hash(o), ho);
    let (winner, loser) = if theirs_wins { (t, o) } else { (o, t) };

    let ours_history = history_of(o);
    let theirs_history = history_of(t);
    let ours_hashes: Vec<Hash> = ours_history.iter().map(entry_hash).collect();
    let longest = ours_history.len().max(theirs_history.len());

    // the passkey the loser changed alone goes onto the winner; the
    // winner's own version then joins the history too, so nothing is lost
    let carry = diverged
        && carry_passkey(
            winner,
            loser,
            shared_passkey(o, t, &ours_history, &theirs_history),
        );
    let current = carry.then(|| with_passkey_of(winner, loser));
    let hc = match &current {
        Some((fields, tags)) => content_hash(winner, fields, tags),
        None => entry_hash(winner),
    };
    let side = |theirs_side: bool| {
        if theirs_side {
            theirs.entry(id)
        } else {
            ours.entry(id)
        }
    };
    let mut lost: Vec<EntryRef<'_>> = Vec::new();
    if diverged {
        lost.extend(side(!theirs_wins));
        if carry {
            lost.extend(side(theirs_wins));
        }
    }
    lost.retain(|v| entry_hash(v) != hc);

    let mut seen = HashSet::new();
    let mut versions: Vec<(Time, Hash, EntryRef<'_>)> = Vec::new();
    for v in ours_history.into_iter().chain(theirs_history).chain(lost) {
        let h = entry_hash(&v);
        if seen.insert(h) {
            versions.push((v.times.last_modification, h, v));
        }
    }
    versions.sort_by_key(|v| (v.0, v.1));
    // the cap stops growth; it never trims a history either copy already had
    if let Some(cap) = cap.map(|c| c.max(longest)) {
        let surplus = versions.len().saturating_sub(cap);
        versions.drain(..surplus);
    }
    let hashes: Vec<Hash> = versions.iter().map(|v| v.1).collect();
    report.to_history += hashes.iter().filter(|h| !ours_hashes.contains(h)).count();
    if diverged {
        report.diverged += 1;
    }
    if hc != ho {
        report.updated += 1;
    }
    if hc != ho || hashes != ours_hashes {
        let versions: Vec<EntryRef<'_>> = versions.into_iter().map(|v| v.2).collect();
        rebuild(out, id, &versions, winner)?;
        if let Some((fields, tags)) = current
            && let Some(mut e) = out.entry_mut(id)
        {
            e.fields = fields;
            e.tags = tags;
        }
    }

    let op = o.parent().id();
    let (po, pt) = (place(ours, op), place(theirs, t.parent().id()));
    let tp = map(t.parent().id());
    let located = if po == pt || op == tp {
        o.times.location_changed.max(t.times.location_changed)
    } else if (t.times.location_changed, pt) > (o.times.location_changed, po) {
        move_entry(out, id, tp, t.previous_parent().map(|p| map(p.id())));
        report.moved += 1;
        t.times.location_changed
    } else {
        o.times.location_changed
    };
    if let Some(mut e) = out.entry_mut(id) {
        e.times.location_changed = located;
        e.times.last_access = o.times.last_access.max(t.times.last_access);
        e.times.usage_count = o.times.usage_count.max(t.times.usage_count);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn merge_entries(
    out: &mut Database,
    ours: &Database,
    theirs: &Database,
    map: &dyn Fn(GroupId) -> GroupId,
    deleted: &HashMap<Uuid, Time>,
    cap: Option<usize>,
    report: &mut Report,
) -> Result<(), Error> {
    let gone: Vec<EntryId> = ours
        .iter_all_entries()
        .filter(|o| {
            theirs.entry(o.id()).is_none() && deletion_wins(deleted, o.id().uuid(), &o.times)
        })
        .map(|o| o.id())
        .collect();
    let mut ids: Vec<EntryId> = theirs.iter_all_entries().map(|e| e.id()).collect();
    ids.sort_by_key(|id| id.uuid());
    for id in ids {
        let Some(t) = theirs.entry(id) else {
            continue;
        };
        match ours.entry(id) {
            None => {
                if deletion_wins(deleted, id.uuid(), &t.times) {
                    continue;
                }
                add_entry(out, &t, map)?;
                report.added += 1;
            }
            Some(o) => merge_entry(out, ours, theirs, &o, &t, map, cap, report)?,
        }
    }
    // a plain remove: the deletion that wins is already in DeletedObjects
    for id in gone {
        if let Some(e) = out.entry_mut(id) {
            e.remove();
            report.deleted += 1;
        }
    }
    Ok(())
}

/// Two copies that each made a recycle bin end with the one the metadata
/// names; the other's contents move into it and its deletion is recorded.
fn unify_bins(out: &mut Database, ours: &Database, theirs: &Database, report: &mut Report) {
    let root = out.root().id();
    let mut bins: Vec<Uuid> = [ours.meta.recyclebin_uuid, theirs.meta.recyclebin_uuid]
        .into_iter()
        .flatten()
        .filter(|u| {
            let g = GroupId::from_uuid(*u);
            g != root && out.group(g).is_some()
        })
        .collect();
    bins.sort();
    bins.dedup();
    let named = out
        .meta
        .recyclebin_uuid
        .filter(|u| out.group(GroupId::from_uuid(*u)).is_some());
    let Some(bin) = named.or_else(|| bins.first().copied()) else {
        return;
    };
    out.meta.recyclebin_uuid = Some(bin);
    let bin_id = GroupId::from_uuid(bin);
    for other in bins.into_iter().filter(|u| *u != bin) {
        let other_id = GroupId::from_uuid(other);
        if is_inside(out, bin_id, other_id) || is_inside(out, other_id, bin_id) {
            continue;
        }
        let Some(g) = out.group(other_id) else {
            continue;
        };
        let when = [
            changed_at(&g.times),
            ours.meta.recyclebin_changed,
            theirs.meta.recyclebin_changed,
        ]
        .into_iter()
        .max()
        .flatten()
        .unwrap_or_else(Times::epoch);
        let entries: Vec<EntryId> = g.entry_ids().collect();
        let groups: Vec<GroupId> = g.group_ids().collect();
        for e in entries {
            let previous = out
                .entry(e)
                .and_then(|x| x.previous_parent().map(|p| p.id()));
            move_entry(out, e, bin_id, previous);
        }
        for c in groups {
            move_group(out, c, bin_id, None);
        }
        let empty = out
            .group(other_id)
            .is_some_and(|g| g.entry_ids().next().is_none() && g.group_ids().next().is_none());
        if empty && let Some(g) = out.group_mut(other_id) {
            g.remove();
            out.deleted_objects.insert(other, Some(when));
            report.groups_deleted += 1;
        }
    }
}

/// Remove the groups a deletion names that only one copy still has, once
/// nothing that survived the merge is left in them.
fn prune_groups(
    out: &mut Database,
    ours: &Database,
    theirs: &Database,
    deleted: &HashMap<Uuid, Time>,
    report: &mut Report,
) {
    let root = out.root().id();
    loop {
        let doomed: Vec<GroupId> = out
            .iter_all_groups()
            .filter(|g| {
                let id = g.id();
                id != root
                    && g.entry_ids().next().is_none()
                    && g.group_ids().next().is_none()
                    && (ours.group(id).is_none() || theirs.group(id).is_none())
                    && deletion_wins(deleted, id.uuid(), &g.times)
            })
            .map(|g| g.id())
            .collect();
        if doomed.is_empty() {
            break;
        }
        for id in doomed {
            if let Some(g) = out.group_mut(id) {
                g.remove();
                report.groups_deleted += 1;
            }
        }
    }
}

/// Drop the attachments nothing uses any more (a version the history cap
/// let go) and the custom icons the merge made that nothing uses. Runs on a
/// freshly read database ([`normalize`]): no stale back-reference to follow.
fn collect_garbage(out: &mut Database, ours: &Database) {
    let mut files = HashSet::new();
    let mut icons = HashSet::new();
    for e in out.iter_all_entries() {
        files.extend(e.attachments().map(|a| a.id().id()));
        if let Some(Icon::Custom(c)) = e.icon() {
            icons.insert(c.uuid());
        }
        for v in history_of(&e) {
            files.extend(v.attachments().map(|a| a.id().id()));
            if let Some(Icon::Custom(c)) = v.icon() {
                icons.insert(c.uuid());
            }
        }
    }
    for g in out.iter_all_groups() {
        if let Some(Icon::Custom(c)) = g.icon() {
            icons.insert(c.uuid());
        }
    }
    let unused_files: Vec<_> = out
        .iter_all_attachments()
        .map(|a| a.id())
        .filter(|a| !files.contains(&a.id()))
        .collect();
    for a in unused_files {
        if let Some(a) = out.attachment_mut(a) {
            a.remove();
        }
    }
    let unused_icons: Vec<_> = out
        .iter_all_custom_icons()
        .map(|i| i.id())
        .filter(|i| !icons.contains(&i.uuid()) && ours.custom_icon(*i).is_none())
        .collect();
    for i in unused_icons {
        if let Some(i) = out.custom_icon_mut(i) {
            i.remove();
        }
    }
}
