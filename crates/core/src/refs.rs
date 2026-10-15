//! Secret references, the `op://` of Safe (docs/PROTOCOL.md, "References"):
//! `ewe-safe read`, `run` and `inject` send them to the daemon's `resolve`
//! verb, which answers from the unlocked safe with [`resolve`], so every
//! caller follows the same rules.
//!
//! - `safe://Personal/GitHub/password`: the item titled GitHub in the
//!   folder Personal (folders nest: `safe://Work/Mail/Gmail/password`);
//! - `safe:///GitHub/password`: the item titled GitHub at the top;
//! - `safe://GitHub/password`: the item titled GitHub in any folder;
//! - `safe://4f9c0d1e-…/password`: the item with that id.
//!
//! Each part is percent-decoded: `%2F` is a `/` in a title, `%25` a `%`. A
//! `?` or `#` is kept for later options and must be written `%3F` / `%23`.
//! Names compare exactly first, then without case and outer spaces. Two
//! items that fit equally well are [`RefError::Ambiguous`], never a guess.
//!
//! Fields: `password`, `username`, `otp` (the current code), `notes`, `url`
//! (the first website), or a custom field's name; a name that is no field
//! but an attached text file's gives the file. `public_key` and
//! `private_key` are an SSH key item's (KeeAgent: a `public_key` field, and
//! the key file its `KeeAgent.settings` names).

use keepass::db::{EntryId, EntryRef, fields};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::item::{self, Summary};
use crate::otp::Totp;
use crate::safe::Safe;

pub const SCHEME: &str = "safe://";
/// The attachment KeePassXC's SSH agent reads (the KeeAgent format).
const KEEAGENT: &str = "KeeAgent.settings";

/// Which item a reference names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// `safe://<item-id>/<field>`
    Id(String),
    /// `safe://<title>/<field>`: in any folder
    Anywhere(String),
    /// `safe://<folder>/<title>/<field>`; `safe:///<title>/<field>` is the
    /// top (`folder` "")
    In { folder: String, title: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub target: Target,
    pub field: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefError {
    /// Not a reference; the sentence says why.
    Bad(String),
    /// No such item, or the item has no such field.
    NotFound(String),
    /// Several items (or fields) fit: the sentence, and the items' ids.
    Ambiguous(String, Vec<String>),
}

impl RefError {
    /// The PROTOCOL.md error code.
    pub fn code(&self) -> &'static str {
        match self {
            RefError::Bad(_) => "bad-request",
            RefError::NotFound(_) => "not-found",
            RefError::Ambiguous(..) => "ambiguous",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            RefError::Bad(m) | RefError::NotFound(m) | RefError::Ambiguous(m, _) => m,
        }
    }
}

/// One value a reference names. `field` is the name as asked.
pub struct Resolved {
    pub item_id: String,
    pub field: String,
    pub value: Zeroizing<String>,
    /// For `otp`: the seconds the code stays valid.
    pub expires_in: Option<u64>,
}

/// `text` starts with `safe://` (spaces around it allowed).
pub fn is_reference(text: &str) -> bool {
    let t = text.trim();
    t.len() >= SCHEME.len() && t[..SCHEME.len()].eq_ignore_ascii_case(SCHEME)
}

fn bad(m: impl Into<String>) -> RefError {
    RefError::Bad(m.into())
}

/// `%XX` → the byte; a `%` not followed by two hex digits stays a `%`.
fn decode(part: &str) -> Result<String, RefError> {
    let b = part.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| bad(format!("{part:?} isn't text once decoded.")))
}

/// Read a reference. `safe://` is case-blind; the rest is not.
pub fn parse(text: &str) -> Result<Reference, RefError> {
    let t = text.trim();
    if !is_reference(t) {
        return Err(bad("A reference starts with safe://."));
    }
    let rest = &t[SCHEME.len()..];
    if rest.contains(['?', '#']) {
        return Err(bad(
            "A reference has no ? or # part: write them %3F and %23 in a name.",
        ));
    }
    let parts: Vec<&str> = rest.split('/').collect();
    let usage = "A reference is safe://<folder>/<title>/<field> or safe://<item-id>/<field>.";
    let (field, path) = match parts.split_last() {
        Some((f, p)) if !p.is_empty() => (*f, p),
        _ => return Err(bad(usage)),
    };
    // a leading "/" (safe:///…) means "from the top"; no other part is empty
    let (top, path) = match path.split_first() {
        Some((first, more)) if first.is_empty() && !more.is_empty() => (true, more),
        _ => (false, path),
    };
    if field.is_empty() || path.iter().any(|p| p.is_empty()) {
        return Err(bad(usage));
    }
    let field = decode(field)?;
    let mut names = path
        .iter()
        .map(|p| decode(p))
        .collect::<Result<Vec<_>, _>>()?;
    let title = names.pop().unwrap_or_default();
    let target = if top || !names.is_empty() {
        Target::In {
            folder: names.join("/"),
            title,
        }
    } else if let Ok(u) = Uuid::parse_str(&title) {
        Target::Id(u.hyphenated().to_string())
    } else {
        Target::Anywhere(title)
    };
    Ok(Reference { target, field })
}

fn loose(s: &str) -> String {
    s.trim().to_lowercase()
}

/// "titled \"GitHub\" in Personal", for the messages.
fn describe(t: &Target) -> String {
    match t {
        Target::Id(id) => format!("with the id {id}"),
        Target::Anywhere(title) => format!("titled {title:?}"),
        Target::In { folder, title } if folder.is_empty() => {
            format!("titled {title:?} at the top")
        }
        Target::In { folder, title } => format!("titled {title:?} in {folder}"),
    }
}

/// The one item `t` names among `items` (the safe's, recycle bin left out).
pub fn find<'a>(items: &'a [Summary], t: &Target) -> Result<&'a Summary, RefError> {
    let fits = |exact: bool| -> Vec<&'a Summary> {
        let same = |a: &str, b: &str| if exact { a == b } else { loose(a) == loose(b) };
        items
            .iter()
            .filter(|s| match t {
                Target::Id(id) => {
                    Uuid::parse_str(&s.id).is_ok_and(|u| u.hyphenated().to_string() == *id)
                }
                Target::Anywhere(title) => same(&s.title, title),
                Target::In { folder, title } => same(&s.folder, folder) && same(&s.title, title),
            })
            .collect()
    };
    let mut found = fits(true);
    if found.is_empty() {
        found = fits(false);
    }
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(RefError::NotFound(format!(
            "Safe has no item {}.",
            describe(t)
        ))),
        many => Err(RefError::Ambiguous(
            format!(
                "{} items are {}: name one by its id (safe://<item-id>/<field>).",
                many.len(),
                describe(t)
            ),
            many.iter().map(|s| s.id.clone()).collect(),
        )),
    }
}

/// The value `r` names, from an unlocked safe.
pub fn resolve(safe: &Safe, r: &Reference) -> Result<Resolved, RefError> {
    let items = safe.items();
    let item = find(&items, &r.target)?;
    let uuid = Uuid::parse_str(&item.id).map_err(|_| RefError::NotFound(item.id.clone()))?;
    let entry = safe
        .database()
        .entry(EntryId::from(uuid))
        .ok_or_else(|| RefError::NotFound(format!("Safe has no item {}.", item.id)))?;
    let (value, expires_in) = value_of(&entry, item, &r.field)?;
    Ok(Resolved {
        item_id: item.id.clone(),
        field: r.field.clone(),
        value,
        expires_in,
    })
}

/// The KDBX names a reference may not reach as custom fields: the
/// standard fields have their own names above.
const STANDARD: &[&str] = &[
    fields::TITLE,
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
];

fn value_of(
    e: &EntryRef<'_>,
    item: &Summary,
    field: &str,
) -> Result<(Zeroizing<String>, Option<u64>), RefError> {
    let title = &item.title;
    let missing = || RefError::NotFound(format!("{title:?} has no field {field:?}."));
    let text = |v: Option<&str>| v.map(|s| Zeroizing::new(s.to_string())).ok_or_else(missing);
    match field.to_lowercase().as_str() {
        "password" => return Ok((text(e.get(fields::PASSWORD))?, None)),
        "username" => return Ok((text(e.get(fields::USERNAME))?, None)),
        "notes" => return Ok((text(e.get(fields::NOTES))?, None)),
        "url" => {
            let first = item::websites_of(e).into_iter().next();
            return Ok((text(first.as_deref())?, None));
        }
        "otp" => {
            let uri = e.get(item::OTP).filter(|u| !u.trim().is_empty());
            let totp = Totp::parse(uri.ok_or_else(missing)?).map_err(|err| {
                RefError::NotFound(format!("{title:?}'s one-time code can't be read: {err}."))
            })?;
            let (code, left) = totp.now();
            return Ok((code, Some(left)));
        }
        _ => {}
    }
    // a custom field: its exact name, then its name without case
    if let Some(v) = e.get(field).filter(|_| !STANDARD.contains(&field)) {
        return Ok((Zeroizing::new(v.to_string()), None));
    }
    let lower = field.to_lowercase();
    let mut like: Vec<&String> = e
        .fields
        .keys()
        .filter(|k| !STANDARD.contains(&k.as_str()) && k.to_lowercase() == lower)
        .collect();
    like.sort();
    match like.as_slice() {
        [one] => return Ok((text(e.get(one))?, None)),
        [] => {}
        _ => {
            return Err(RefError::Ambiguous(
                format!(
                    "{title:?} has several fields called {field:?} (in other cases): write it exactly."
                ),
                vec![item.id.clone()],
            ));
        }
    }
    // a file by its name; `private_key` is also an SSH key item's key file
    let file = e
        .attachment_by_name(field)
        .map(|a| a.get().clone())
        .or_else(|| (lower == "private_key").then(|| key_file(e)).flatten());
    match file {
        Some(bytes) => match String::from_utf8(bytes) {
            Ok(s) => Ok((Zeroizing::new(s), None)),
            Err(err) => {
                let mut b = err.into_bytes();
                zeroize::Zeroize::zeroize(&mut b);
                Err(RefError::NotFound(format!(
                    "{title:?}'s file {field:?} isn't text."
                )))
            }
        },
        None => Err(missing()),
    }
}

/// The key file of a KeeAgent entry: the attachment its settings name, or
/// the only other attachment.
fn key_file(e: &EntryRef<'_>) -> Option<Vec<u8>> {
    let settings = e.attachment_by_name(KEEAGENT)?;
    if let Some(name) = keeagent_attachment(settings.get())
        && let Some(a) = e.attachment_by_name(&name)
    {
        return Some(a.get().clone());
    }
    let others: Vec<_> = e
        .attachments_named()
        .filter(|(n, _)| *n != KEEAGENT)
        .collect();
    match others.as_slice() {
        [(_, a)] => Some(a.get().clone()),
        _ => None,
    }
}

/// `<AttachmentName>id_ed25519</AttachmentName>` from a KeeAgent.settings
/// file (UTF-8, or UTF-16 with a byte-order mark as KeeAgent writes it).
fn keeagent_attachment(xml: &[u8]) -> Option<String> {
    let utf16 = |b: &[u8], unit: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| unit(*c)).collect();
        String::from_utf16(&units).ok()
    };
    let text = match xml {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes)?,
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes)?,
        _ => String::from_utf8_lossy(xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml)).into_owned(),
    };
    let start = text.find("<AttachmentName>")? + "<AttachmentName>".len();
    let end = start + text[start..].find("</AttachmentName>")?;
    let name = text[start..end].trim();
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{Batch, Field as ImportField, File, Imported, Options};
    use crate::item::{Draft, Kind};
    use keepass::config::KdfConfig;

    const ID: &str = "4f9c0d1e-2b3a-4c5d-8e6f-0123456789ab";

    fn r(text: &str) -> Reference {
        parse(text).unwrap_or_else(|e| panic!("{text}: {e:?}"))
    }

    fn within(folder: &str, title: &str, field: &str) -> Reference {
        Reference {
            target: Target::In {
                folder: folder.into(),
                title: title.into(),
            },
            field: field.into(),
        }
    }

    #[test]
    fn the_shapes_of_a_reference() {
        assert_eq!(
            r("safe://Personal/GitHub/password"),
            within("Personal", "GitHub", "password")
        );
        assert_eq!(
            r("  SAFE://Work/Mail/Gmail/username "),
            within("Work/Mail", "Gmail", "username")
        );
        assert_eq!(r("safe:///GitHub/otp"), within("", "GitHub", "otp"));
        assert_eq!(
            r("safe://GitHub/password").target,
            Target::Anywhere("GitHub".into())
        );
        // an id, in any spelling a UUID has, becomes the lowercase hyphenated one
        assert_eq!(
            r(&format!("safe://{}/password", ID.to_uppercase())).target,
            Target::Id(ID.into())
        );
        assert_eq!(
            r("safe:///Work/Mail/Gmail/notes"),
            within("Work/Mail", "Gmail", "notes")
        );
    }

    #[test]
    fn percent_signs_decode_and_slashes_stay_inside_a_title() {
        assert_eq!(
            r("safe://Personal/AC%2FDC%20fan%20club/password"),
            within("Personal", "AC/DC fan club", "password")
        );
        assert_eq!(
            r("safe://Shop/100%25 real/username"),
            within("Shop", "100% real", "username")
        );
        // a % that isn't an escape stays as it is
        assert_eq!(
            r("safe://Shop/50% off/username"),
            within("Shop", "50% off", "username")
        );
        assert_eq!(r("safe://A/B/my%20field").field, "my field");
        assert_eq!(
            r("safe://A/B%3F/password").target,
            Target::In {
                folder: "A".into(),
                title: "B?".into()
            }
        );
    }

    #[test]
    fn what_is_not_a_reference() {
        for text in [
            "op://Personal/GitHub/password",
            "safe://",
            "safe://GitHub",
            "safe://GitHub/",
            "safe:///password",
            "safe://Personal//GitHub/password",
            "safe://Personal/GitHub/password/",
            "safe://Personal/GitHub/password?attribute=otp",
            "safe://Personal/GitHub#x/password",
            "safe://A/%FF%FE/password",
        ] {
            assert_eq!(
                parse(text).err().map(|e| e.code()),
                Some("bad-request"),
                "{text}"
            );
        }
        assert!(is_reference(" safe://x/y") && !is_reference("http://x"));
    }

    fn summary(id: &str, folder: &str, title: &str) -> Summary {
        Summary {
            id: id.into(),
            kind: Kind::Login,
            title: title.into(),
            username: String::new(),
            websites: Vec::new(),
            apps: Vec::new(),
            tags: Vec::new(),
            folder: folder.into(),
            has_password: true,
            has_otp: false,
            modified: None,
        }
    }

    #[test]
    fn finding_never_guesses() {
        let a = "00000000-0000-4000-8000-00000000000a";
        let b = "00000000-0000-4000-8000-00000000000b";
        let c = "00000000-0000-4000-8000-00000000000c";
        let d = "00000000-0000-4000-8000-00000000000d";
        let items = vec![
            summary(a, "Personal", "GitHub"),
            summary(b, "Remedium", "github.com"),
            summary(c, "Remedium", "github.com"),
            summary(d, "", "github"),
        ];
        let id = |t: Target| find(&items, &t).map(|s| s.id.clone());
        assert_eq!(id(within("Personal", "GitHub", "x").target), Ok(a.into()));
        // without case and outer spaces when nothing fits exactly
        assert_eq!(id(within("personal", " github ", "x").target), Ok(a.into()));
        assert_eq!(id(within("", "github", "x").target), Ok(d.into()));
        // anywhere: the exact spelling wins over the loose one
        assert_eq!(id(Target::Anywhere("GitHub".into())), Ok(a.into()));
        assert_eq!(id(Target::Anywhere("github".into())), Ok(d.into()));
        assert_eq!(id(Target::Id(c.into())), Ok(c.into()));
        match find(&items, &within("Remedium", "github.com", "x").target) {
            Err(RefError::Ambiguous(m, ids)) => {
                assert_eq!(ids, vec![b.to_string(), c.to_string()]);
                assert!(m.contains("2 items"), "{m}");
            }
            other => panic!("{:?}", other.map(|s| s.id.clone())),
        }
        // two loose fits are ambiguous too
        assert_eq!(
            find(&items, &Target::Anywhere("GITHUB".into()))
                .err()
                .map(|e| e.code()),
            Some("ambiguous")
        );
        assert_eq!(
            find(&items, &within("Work", "GitHub", "x").target)
                .err()
                .map(|e| e.code()),
            Some("not-found")
        );
    }

    fn cheap() -> KdfConfig {
        KdfConfig::Argon2id {
            iterations: 1,
            memory: 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        }
    }

    fn imported(
        folder: &str,
        draft: Draft,
        fields: Vec<(&str, &str)>,
        files: Vec<(&str, &[u8])>,
    ) -> Imported {
        Imported {
            folder: folder.into(),
            draft,
            fields: fields
                .into_iter()
                .map(|(n, v)| ImportField {
                    name: n.into(),
                    value: Zeroizing::new(v.into()),
                    protected: true,
                })
                .collect(),
            history: Vec::new(),
            files: files
                .into_iter()
                .map(|(n, d)| File {
                    name: n.into(),
                    data: Zeroizing::new(d.to_vec()),
                })
                .collect(),
            created: None,
            modified: None,
        }
    }

    fn a_safe() -> Safe {
        let mut safe = Safe::create("Safe", cheap());
        let github = Draft {
            kind: Kind::Login,
            title: "GitHub".into(),
            username: "sam".into(),
            password: Zeroizing::new("gh-pw".into()),
            websites: vec![
                "https://github.com/login".into(),
                "https://gist.github.com".into(),
            ],
            otp: Zeroizing::new("otpauth://totp/GitHub:sam?secret=JBSWY3DPEHPK3PXP".into()),
            notes: Zeroizing::new("recovery in the drawer".into()),
            ..Draft::default()
        };
        let ssh = Draft {
            kind: Kind::Login,
            title: "Work key".into(),
            ..Draft::default()
        };
        let settings = "\u{feff}<?xml version=\"1.0\" encoding=\"utf-16\"?><EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey><Location><SelectedType>attachment</SelectedType><AttachmentName>id_ed25519</AttachmentName></Location></EntrySettings>";
        let utf16: Vec<u8> = settings
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let batch = Batch {
            items: vec![
                imported(
                    "Personal",
                    github,
                    vec![("API token", "tok-1"), ("Recovery", "rec-2")],
                    vec![
                        ("backup.txt", b"codes 1 2 3"),
                        ("photo.png", &[0x89, 0x50, 0xFF, 0xFE]),
                    ],
                ),
                imported(
                    "Work",
                    ssh,
                    vec![("public_key", "ssh-ed25519 AAAA test")],
                    vec![
                        ("KeeAgent.settings", &utf16),
                        ("notes.txt", b"not the key"),
                        ("id_ed25519", b"-----BEGIN OPENSSH PRIVATE KEY-----\n"),
                    ],
                ),
            ],
            skipped: Vec::new(),
        };
        safe.import(&batch, &Options::default()).expect("import");
        safe
    }

    fn value(safe: &Safe, text: &str) -> Result<String, RefError> {
        resolve(safe, &r(text)).map(|v| v.value.to_string())
    }

    #[test]
    fn every_kind_of_field_resolves() {
        let safe = a_safe();
        let v = |t: &str| value(&safe, t).unwrap_or_else(|e| panic!("{t}: {e:?}"));
        assert_eq!(v("safe://Personal/GitHub/password"), "gh-pw");
        assert_eq!(v("safe://GitHub/username"), "sam");
        assert_eq!(v("safe://GitHub/Password"), "gh-pw");
        assert_eq!(v("safe://GitHub/notes"), "recovery in the drawer");
        assert_eq!(v("safe://GitHub/url"), "https://github.com/login");
        assert_eq!(v("safe://GitHub/API token"), "tok-1");
        assert_eq!(v("safe://GitHub/api%20TOKEN"), "tok-1");
        assert_eq!(v("safe://GitHub/backup.txt"), "codes 1 2 3");
        let otp = resolve(&safe, &r("safe://GitHub/otp")).expect("otp");
        assert_eq!(otp.value.len(), 6);
        assert!(otp.expires_in.is_some_and(|s| (1..=30).contains(&s)));
        // the SSH key item: its public line, and the file KeeAgent names
        assert_eq!(
            v("safe://Work/Work key/public_key"),
            "ssh-ed25519 AAAA test"
        );
        assert!(v("safe://Work key/private_key").starts_with("-----BEGIN OPENSSH"));
        let id = resolve(&safe, &r("safe://GitHub/password"))
            .unwrap()
            .item_id;
        assert_eq!(v(&format!("safe://{id}/username")), "sam");
    }

    #[test]
    fn unknown_fields_and_binary_files_are_not_found() {
        let safe = a_safe();
        for t in [
            "safe://GitHub/pin",
            "safe://GitHub/photo.png",
            "safe://GitHub/private_key",
            "safe://Work key/otp",
            "safe://Nope/password",
            "safe://00000000-0000-4000-8000-000000000000/password",
        ] {
            assert_eq!(
                value(&safe, t).err().map(|e| e.code()),
                Some("not-found"),
                "{t}"
            );
        }
        // the standard fields are reached by their own names only
        assert_eq!(
            value(&safe, "safe://GitHub/Title").err().map(|e| e.code()),
            Some("not-found")
        );
    }

    #[test]
    fn keeagent_settings_in_both_encodings() {
        let xml = "<EntrySettings><Location><AttachmentName> id_rsa </AttachmentName></Location></EntrySettings>";
        assert_eq!(keeagent_attachment(xml.as_bytes()), Some("id_rsa".into()));
        let be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain(xml.encode_utf16().flat_map(|u| u.to_be_bytes()))
            .collect();
        assert_eq!(keeagent_attachment(&be), Some("id_rsa".into()));
        assert_eq!(keeagent_attachment(b"<EntrySettings/>"), None);
    }
}
