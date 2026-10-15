//! Safe's two kinds of item, Login and Note, and how they sit in KDBX
//! fields (PLAN.md §5). The field names follow KeePassXC's conventions so
//! every other KeePass app understands them:
//!
//! | Safe | KDBX |
//! |---|---|
//! | title, username, password, notes | `Title`, `UserName`, `Password` (protected), `Notes` |
//! | websites | `URL`, then `KP2A_URL_1…n` |
//! | one-time code | `otp` (an `otpauth://` URI, protected) |
//! | apps (the `Super+P` pins) | tags `app:<window-class>` |
//! | kind Note | custom data `ewe.kind = note`; its text is protected |
//! | passkey | KeePassXC's `KPEX_PASSKEY_*` fields ([`crate::passkey`]) |
//!
//! Everything else in an entry (custom fields, attachments, history, icons,
//! auto-type) is left exactly as it was.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::NaiveDateTime;
use keepass::db::fields;
use keepass::db::{CustomDataItem, CustomDataValue, Entry, Value};
use zeroize::Zeroizing;

pub const KIND_KEY: &str = "ewe.kind";
pub const KIND_NOTE: &str = "note";
pub const OTP: &str = "otp";
pub const EXTRA_URL: &str = "KP2A_URL_";
pub const APP_TAG: &str = "app:";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    Login,
    Note,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Note => "note",
        }
    }
}

/// What a list shows. Never a secret: no password, no notes, no code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub id: String,
    pub kind: Kind,
    pub title: String,
    pub username: String,
    pub websites: Vec<String>,
    pub apps: Vec<String>,
    pub tags: Vec<String>,
    /// The folder path below the root, "" at the top ("Work/Mail").
    pub folder: String,
    pub has_password: bool,
    pub has_otp: bool,
    pub modified: Option<NaiveDateTime>,
    /// The item's passkey (KeePassXC's fields), never its key.
    pub passkey: Option<crate::passkey::Info>,
}

/// An item as the editor fills it in. The secret parts are wiped from
/// memory when it is dropped.
#[derive(Clone, Default)]
pub struct Draft {
    pub kind: Kind,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub websites: Vec<String>,
    pub apps: Vec<String>,
    pub tags: Vec<String>,
    pub notes: Zeroizing<String>,
    /// An `otpauth://` URI, empty for none.
    pub otp: Zeroizing<String>,
}

/// One value `reveal` can hand out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    Username,
    Password,
    Notes,
    /// The current one-time code (digits), not the secret behind it.
    OtpCode,
    /// Any other field by its KDBX name.
    Other(String),
}

impl Field {
    pub fn parse(name: &str) -> Field {
        match name {
            "username" => Field::Username,
            "password" => Field::Password,
            "notes" => Field::Notes,
            "otp" => Field::OtpCode,
            other => Field::Other(other.to_string()),
        }
    }
}

/// A custom-data value as keepass-rs will read it back: text that happens
/// to be valid base64 ("note", "true") comes back as bytes (SPIKE-0, F6).
/// Storing it in that form keeps memory equal to the file.
pub fn custom_value(text: &str) -> CustomDataValue {
    match STANDARD.decode(text) {
        Ok(bytes) => CustomDataValue::Binary(bytes),
        Err(_) => CustomDataValue::String(text.to_string()),
    }
}

/// The text a custom-data value has in the file, whichever form it is in.
pub fn custom_text(value: &CustomDataValue) -> String {
    match value {
        CustomDataValue::String(s) => s.clone(),
        CustomDataValue::Binary(b) => STANDARD.encode(b),
    }
}

pub fn kind_of(entry: &Entry) -> Kind {
    match entry
        .custom_data
        .get(KIND_KEY)
        .and_then(|i| i.value.as_ref())
    {
        Some(v) if custom_text(v) == KIND_NOTE => Kind::Note,
        _ => Kind::Login,
    }
}

fn text(entry: &Entry, key: &str) -> String {
    entry.get(key).unwrap_or_default().to_string()
}

/// `URL` first, then `KP2A_URL_1`, `KP2A_URL_2`, … in number order.
pub fn websites_of(entry: &Entry) -> Vec<String> {
    let mut extra: Vec<(u32, &str)> = entry
        .fields
        .iter()
        .filter_map(|(k, v)| {
            let n = k.strip_prefix(EXTRA_URL)?.parse().ok()?;
            Some((n, v.get().as_str()))
        })
        .collect();
    extra.sort_by_key(|(n, _)| *n);
    entry
        .get(fields::URL)
        .into_iter()
        .chain(extra.into_iter().map(|(_, v)| v))
        .filter(|u| !u.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// (apps, other tags): `app:<class>` tags are the windows a login is for.
pub fn split_tags(entry: &Entry) -> (Vec<String>, Vec<String>) {
    let mut apps = Vec::new();
    let mut tags = Vec::new();
    for t in &entry.tags {
        match t.strip_prefix(APP_TAG) {
            Some(class) if !class.is_empty() => apps.push(class.to_string()),
            _ => tags.push(t.clone()),
        }
    }
    (apps, tags)
}

pub fn summary_of(id: String, entry: &Entry, folder: String) -> Summary {
    let (apps, tags) = split_tags(entry);
    Summary {
        id,
        kind: kind_of(entry),
        title: text(entry, fields::TITLE),
        username: text(entry, fields::USERNAME),
        websites: websites_of(entry),
        apps,
        tags,
        folder,
        has_password: entry.get(fields::PASSWORD).is_some_and(|p| !p.is_empty()),
        has_otp: entry.get(OTP).is_some_and(|p| !p.is_empty()),
        modified: entry.times.last_modification,
        passkey: crate::passkey::info_of(entry),
    }
}

pub fn draft_of(entry: &Entry) -> Draft {
    let (apps, tags) = split_tags(entry);
    Draft {
        kind: kind_of(entry),
        title: text(entry, fields::TITLE),
        username: text(entry, fields::USERNAME),
        password: Zeroizing::new(text(entry, fields::PASSWORD)),
        websites: websites_of(entry),
        apps,
        tags,
        notes: Zeroizing::new(text(entry, fields::NOTES)),
        otp: Zeroizing::new(text(entry, OTP)),
    }
}

/// Write a draft into an entry, touching only the fields Safe owns.
pub fn apply(entry: &mut Entry, draft: &Draft) {
    entry.set_unprotected(fields::TITLE, draft.title.clone());
    entry.set_unprotected(fields::USERNAME, draft.username.clone());
    entry.set_protected(fields::PASSWORD, draft.password.as_str());

    let websites: Vec<&str> = draft
        .websites
        .iter()
        .map(|w| w.trim())
        .filter(|w| !w.is_empty())
        .collect();
    entry.set_unprotected(fields::URL, websites.first().copied().unwrap_or(""));
    entry.fields.retain(|k, _| !k.starts_with(EXTRA_URL));
    for (i, w) in websites.iter().skip(1).enumerate() {
        entry.set_unprotected(format!("{EXTRA_URL}{}", i + 1), *w);
    }

    match draft.kind {
        Kind::Note => {
            entry.set_protected(fields::NOTES, draft.notes.as_str());
            entry.custom_data.insert(
                KIND_KEY.to_string(),
                CustomDataItem {
                    value: Some(custom_value(KIND_NOTE)),
                    last_modification_time: Some(keepass::db::Times::now()),
                },
            );
        }
        Kind::Login => {
            let protected = entry
                .fields
                .get(fields::NOTES)
                .is_some_and(Value::is_protected);
            if protected {
                entry.set_protected(fields::NOTES, draft.notes.as_str());
            } else {
                entry.set_unprotected(fields::NOTES, draft.notes.as_str());
            }
            entry.custom_data.remove(KIND_KEY);
        }
    }

    if draft.otp.trim().is_empty() {
        entry.fields.remove(OTP);
    } else {
        entry.set_protected(OTP, draft.otp.trim());
    }

    let mut tags: Vec<String> = Vec::new();
    for t in &draft.tags {
        let t = t.trim();
        if !t.is_empty() && !t.starts_with(APP_TAG) && !tags.iter().any(|x| x == t) {
            tags.push(t.to_string());
        }
    }
    for a in &draft.apps {
        let tag = format!("{APP_TAG}{}", a.trim());
        if !a.trim().is_empty() && !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    entry.tags = tags;
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;

    /// Entries only exist inside a database.
    fn with_entry<R>(f: impl FnOnce(&mut Entry) -> R) -> R {
        let mut db = Database::new();
        let id = db.root_mut().add_entry().id();
        let mut e = db.entry_mut(id).expect("entry");
        f(&mut e)
    }

    fn login() -> Draft {
        Draft {
            kind: Kind::Login,
            title: "Bank".into(),
            username: "sam".into(),
            password: Zeroizing::new("  spaces kept  ".into()),
            websites: vec![
                "https://bank.example".into(),
                " ".into(),
                "https://login.bank.example".into(),
                "androidapp://com.bank".into(),
            ],
            apps: vec!["org.example.Bank".into()],
            tags: vec!["money".into(), "money".into(), "app:sneaky".into()],
            notes: Zeroizing::new("hall cupboard".into()),
            otp: Zeroizing::new("otpauth://totp/Bank:sam?secret=JBSWY3DPEHPK3PXP".into()),
        }
    }

    #[test]
    fn a_login_maps_onto_keepassxc_fields() {
        with_entry(|e| {
            apply(e, &login());
            assert_eq!(e.get(fields::URL), Some("https://bank.example"));
            assert_eq!(e.get("KP2A_URL_1"), Some("https://login.bank.example"));
            assert_eq!(e.get("KP2A_URL_2"), Some("androidapp://com.bank"));
            assert!(e.fields[fields::PASSWORD].is_protected());
            assert!(e.fields[OTP].is_protected());
            assert!(!e.fields[fields::NOTES].is_protected());
            assert_eq!(
                e.tags,
                vec!["money".to_string(), "app:org.example.Bank".to_string()]
            );
            assert_eq!(kind_of(e), Kind::Login);

            let back = draft_of(e);
            assert_eq!(back.password.as_str(), "  spaces kept  ");
            assert_eq!(back.websites.len(), 3);
            assert_eq!(back.apps, vec!["org.example.Bank".to_string()]);
            assert_eq!(back.tags, vec!["money".to_string()]);
        });
    }

    #[test]
    fn fewer_websites_remove_the_stale_extra_urls() {
        with_entry(|e| {
            apply(e, &login());
            let mut d = login();
            d.websites = vec!["https://only.example".into()];
            d.otp = Zeroizing::new(String::new());
            apply(e, &d);
            assert_eq!(websites_of(e), vec!["https://only.example".to_string()]);
            assert!(e.get("KP2A_URL_1").is_none());
            assert!(e.get(OTP).is_none());
        });
    }

    #[test]
    fn a_note_is_marked_and_its_text_protected() {
        with_entry(|e| {
            let d = Draft {
                kind: Kind::Note,
                title: "Wi-Fi".into(),
                notes: Zeroizing::new("router in the hall".into()),
                ..Draft::default()
            };
            apply(e, &d);
            assert_eq!(kind_of(e), Kind::Note);
            assert!(e.fields[fields::NOTES].is_protected());
            // turning it back into a login drops the marker
            apply(
                e,
                &Draft {
                    kind: Kind::Login,
                    ..d
                },
            );
            assert_eq!(kind_of(e), Kind::Login);
            assert!(!e.custom_data.contains_key(KIND_KEY));
        });
    }

    #[test]
    fn fields_safe_does_not_own_are_left_alone() {
        with_entry(|e| {
            e.set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", "pem");
            e.set_unprotected("Custom", "kept");
            apply(e, &login());
            assert_eq!(e.get("KPEX_PASSKEY_PRIVATE_KEY_PEM"), Some("pem"));
            assert_eq!(e.get("Custom"), Some("kept"));
        });
    }

    #[test]
    fn a_summary_carries_no_secret() {
        with_entry(|e| {
            apply(e, &login());
            let s = summary_of("id".into(), e, "Work".into());
            let shown = format!("{s:?}");
            assert!(!shown.contains("spaces kept"));
            assert!(!shown.contains("JBSWY3DP"));
            assert!(!shown.contains("hall cupboard"));
            assert!(s.has_password && s.has_otp);
        });
    }
}
