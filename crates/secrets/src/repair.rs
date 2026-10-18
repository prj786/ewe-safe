//! `keyring repair` (docs/SYSTEM.md §0, docs/KEYRING.md): the keyring
//! prompt at every start, fixed in the keyring that runs (gnome-keyring).
//!
//! PAM unlocks the `login` collection with the login password, but on a
//! machine hit by ewe's 2026-09-03 bug the `default` alias names a second
//! keyring with its own password, where apps write: it is locked at every
//! start. The repair copies every item of every other collection into
//! `login` and points `default` at `login`:
//!
//! - an item `login` already has (the same attributes and the same secret)
//!   is a duplicate and isn't copied again, so running it twice is safe;
//! - the same attributes with another secret is a conflict: the newer by
//!   `Modified` stays (the other keyring's copy replaces `login`'s only when
//!   it is newer);
//! - nothing in the other collections is changed or deleted, and no
//!   collection is deleted: the old keyring stays as a backup;
//! - unlocking a locked collection shows the keyring's own window (for the
//!   second keyring, the last time it asks); one that stays locked leaves
//!   `default` as it was, so nothing is stranded behind a prompt.
//!
//! Nothing here logs a label or a secret.

use std::collections::BTreeMap;
use std::time::Duration;

use zbus::blocking::Connection;
use zeroize::Zeroizing;

use crate::client::{LOGIN_PATH, Remote, name_of, read_collection, tail};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The collection `default` named before (`Default_keyring`), if any.
    pub default_was: Option<String>,
    /// `default` already named `login`: nothing to do.
    pub already: bool,
    /// The other collections read.
    pub sources: Vec<String>,
    pub moved: usize,
    pub duplicates: usize,
    pub conflicts: usize,
    /// Conflicts where the other keyring's newer copy replaced `login`'s.
    pub replaced: usize,
    /// Items not copied: in a collection that stayed locked, or with no
    /// secret given.
    pub skipped: usize,
    /// Collections that stayed locked (their window was closed). Then
    /// `default` is left as it was, so running the repair again finishes it.
    pub locked: Vec<String>,
    /// `default` names `login` now.
    pub fixed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// No keyring runs on this bus.
    NoKeyring,
    /// The keyring has no `login` collection.
    NoLogin,
    /// `login` stayed locked.
    LoginLocked,
    Bus(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoKeyring => write!(f, "no keyring runs now"),
            Error::NoLogin => write!(f, "the keyring has no login collection"),
            Error::LoginLocked => write!(f, "the login keyring stayed locked"),
            Error::Bus(e) => write!(f, "{e}"),
        }
    }
}

/// What `login` holds, as far as the repair compares.
struct Have {
    label: String,
    attributes: BTreeMap<String, String>,
    secret: Zeroizing<Vec<u8>>,
    modified: u64,
}

enum Step {
    Duplicate,
    Copy,
    /// Same attributes, another secret: `true` = ours is newer, replace.
    Conflict(bool),
}

fn decide(
    have: &[Have],
    label: &str,
    attrs: &BTreeMap<String, String>,
    secret: &[u8],
    modified: u64,
) -> Step {
    if attrs.is_empty() {
        // nothing names it: the same label and secret is the same item
        return if have
            .iter()
            .any(|h| h.attributes.is_empty() && h.label == label && h.secret[..] == *secret)
        {
            Step::Duplicate
        } else {
            Step::Copy
        };
    }
    let same: Vec<&Have> = have.iter().filter(|h| h.attributes == *attrs).collect();
    if same.is_empty() {
        Step::Copy
    } else if same.iter().any(|h| h.secret[..] == *secret) {
        Step::Duplicate
    } else {
        Step::Conflict(same.iter().all(|h| modified > h.modified))
    }
}

/// Copy the other collections into `login` and point `default` at it.
/// `dry_run` counts and changes nothing (locked collections still ask to
/// be unlocked, to be read).
pub fn repair(conn: &Connection, dry_run: bool, wait: Duration) -> Result<Report, Error> {
    let r = Remote::open(conn, false).map_err(|_| Error::NoKeyring)?;
    let collections = r.collections().map_err(Error::Bus)?;
    let default = r.alias("default").map_err(Error::Bus)?;
    let mut report = Report {
        default_was: default.as_ref().map(|p| name_of(p.as_str())),
        ..Report::default()
    };
    if !collections.iter().any(|c| c.as_str() == LOGIN_PATH) {
        return Err(Error::NoLogin);
    }
    if default.as_ref().is_some_and(|d| d.as_str() == LOGIN_PATH) {
        report.already = true;
        report.fixed = true;
        return Ok(report);
    }
    let mut have: Vec<Have> = read_collection(&r, LOGIN_PATH, wait)
        .map_err(Error::Bus)?
        .ok_or(Error::LoginLocked)?
        .into_iter()
        .map(|i| Have {
            label: i.label,
            attributes: i.attributes,
            secret: i.secret,
            modified: i.modified,
        })
        .collect();
    for c in collections {
        let name = name_of(c.as_str());
        if c.as_str() == LOGIN_PATH || tail(c.as_str()) == "session" {
            continue;
        }
        report.sources.push(name.clone());
        let count = r.items(c.as_str()).map(|i| i.len()).unwrap_or(0);
        let Some(mut items) = read_collection(&r, c.as_str(), wait).map_err(Error::Bus)? else {
            report.locked.push(name);
            report.skipped += count;
            continue;
        };
        report.skipped += count.saturating_sub(items.len());
        // the newest first: within this keyring the newest copy wins
        items.sort_by_key(|i| std::cmp::Reverse(i.modified));
        for i in items {
            let step = decide(&have, &i.label, &i.attributes, &i.secret, i.modified);
            let replace = match step {
                Step::Duplicate => {
                    report.duplicates += 1;
                    continue;
                }
                Step::Conflict(false) => {
                    report.conflicts += 1;
                    continue;
                }
                Step::Conflict(true) => {
                    report.conflicts += 1;
                    report.replaced += 1;
                    true
                }
                Step::Copy => {
                    report.moved += 1;
                    false
                }
            };
            if !dry_run {
                r.create(
                    LOGIN_PATH,
                    &i.label,
                    &i.attributes,
                    &i.secret,
                    &i.content_type,
                    replace,
                )
                .map_err(|e| {
                    Error::Bus(format!("{e} (after {} items were copied)", report.moved))
                })?;
            }
            if replace {
                have.retain(|h| h.attributes != i.attributes);
            }
            have.push(Have {
                label: i.label,
                attributes: i.attributes,
                secret: i.secret,
                modified: i.modified,
            });
        }
    }
    if !dry_run && report.locked.is_empty() {
        r.set_alias("default", LOGIN_PATH).map_err(Error::Bus)?;
        report.fixed = true;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn have(label: &str, attrs: &[(&str, &str)], secret: &str, modified: u64) -> Have {
        Have {
            label: label.into(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            secret: Zeroizing::new(secret.as_bytes().to_vec()),
            modified,
        }
    }

    #[test]
    fn duplicates_conflicts_and_copies_are_told_apart() {
        let login = vec![
            have("cloud", &[("service", "ewe-cloud")], "pw", 100),
            have("note", &[], "free text", 50),
        ];
        let a = |p: &[(&str, &str)]| -> BTreeMap<String, String> {
            p.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert!(matches!(
            decide(&login, "cloud", &a(&[("service", "ewe-cloud")]), b"pw", 1),
            Step::Duplicate
        ));
        assert!(matches!(
            decide(
                &login,
                "cloud",
                &a(&[("service", "ewe-cloud")]),
                b"new",
                200
            ),
            Step::Conflict(true)
        ));
        assert!(matches!(
            decide(&login, "cloud", &a(&[("service", "ewe-cloud")]), b"old", 10),
            Step::Conflict(false)
        ));
        assert!(matches!(
            decide(&login, "mail", &a(&[("service", "ewe-mail")]), b"x", 1),
            Step::Copy
        ));
        assert!(matches!(
            decide(&login, "note", &a(&[]), b"free text", 1),
            Step::Duplicate
        ));
        assert!(matches!(
            decide(&login, "other", &a(&[]), b"free text", 1),
            Step::Copy
        ));
    }
}
