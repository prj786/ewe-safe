//! Safe's kinds of item, Login, Note and SSH key, and how they sit in KDBX
//! fields (PLAN.md §5; an SSH key's own parts are in [`crate::ssh`]). The field names follow KeePassXC's conventions so
//! every other KeePass app understands them:
//!
//! | Safe | KDBX |
//! |---|---|
//! | title, username, password, notes | `Title`, `UserName`, `Password` (protected), `Notes` |
//! | websites | `URL`, then `KP2A_URL_1…n` |
//! | one-time code | `otp` (an `otpauth://` URI, protected) |
//! | apps (the `Super+P` pins) | tags `app:<window-class>` |
//! | kind Note | custom data `ewe.kind = note`; its text is protected |
//! | kind SSH key | custom data `ewe.kind = ssh-key` (or a `KeeAgent.settings` attachment); its text is protected |
//! | passkey | KeePassXC's `KPEX_PASSKEY_*` fields ([`crate::passkey`]) |
//! | kind Card, kind Address | custom data `ewe.kind = card` / `address`; their fields are [`crate::card`]'s; the notes protected |
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
pub const KIND_SSH: &str = "ssh-key";
pub const KIND_CARD: &str = "card";
pub const KIND_ADDRESS: &str = "address";
pub const OTP: &str = "otp";
pub const EXTRA_URL: &str = "KP2A_URL_";
pub const APP_TAG: &str = "app:";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    Login,
    Note,
    /// A KeeAgent entry (crate::ssh).
    SshKey,
    /// A payment card (crate::card).
    Card,
    /// A postal address with a name, a phone and an e-mail (crate::card).
    Address,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Note => "note",
            Kind::SshKey => KIND_SSH,
            Kind::Card => KIND_CARD,
            Kind::Address => KIND_ADDRESS,
        }
    }

    pub fn parse(name: &str) -> Option<Kind> {
        match name {
            "login" => Some(Kind::Login),
            "note" => Some(Kind::Note),
            KIND_SSH => Some(Kind::SshKey),
            KIND_CARD => Some(Kind::Card),
            KIND_ADDRESS => Some(Kind::Address),
            _ => None,
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
    /// An SSH key's public part; None for the other kinds.
    pub ssh: Option<crate::ssh::Info>,
    /// A card's brand, last four digits, expiry and holder; None for the
    /// other kinds. Never the number, the code or the PIN.
    pub card: Option<crate::card::CardInfo>,
    /// An address's name, first line, city and country; None for the
    /// other kinds.
    pub address: Option<crate::card::AddressInfo>,
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
    /// A card's fields (kind Card only).
    pub card: crate::card::Card,
    /// An address's fields (kind Address only).
    pub address: crate::card::Address,
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

/// The kind the entry's marker names. An SSH key another app made has no
/// marker: [`crate::ssh::refine`] knows it by its `KeeAgent.settings`.
pub fn kind_of(entry: &Entry) -> Kind {
    match entry
        .custom_data
        .get(KIND_KEY)
        .and_then(|i| i.value.as_ref())
        .map(custom_text)
        .as_deref()
    {
        Some(KIND_NOTE) => Kind::Note,
        Some(KIND_SSH) => Kind::SshKey,
        Some(KIND_CARD) => Kind::Card,
        Some(KIND_ADDRESS) => Kind::Address,
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
    let kind = kind_of(entry);
    Summary {
        id,
        kind,
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
        // filled by crate::ssh::refine, which needs the entry's attachments
        ssh: None,
        card: (kind == Kind::Card).then(|| crate::card::card_info(entry)),
        address: (kind == Kind::Address).then(|| crate::card::address_info(entry)),
    }
}

pub fn draft_of(entry: &Entry) -> Draft {
    let (apps, tags) = split_tags(entry);
    let kind = kind_of(entry);
    Draft {
        kind,
        title: text(entry, fields::TITLE),
        username: text(entry, fields::USERNAME),
        password: Zeroizing::new(text(entry, fields::PASSWORD)),
        websites: websites_of(entry),
        apps,
        tags,
        notes: Zeroizing::new(text(entry, fields::NOTES)),
        otp: Zeroizing::new(text(entry, OTP)),
        card: if kind == Kind::Card {
            crate::card::card_of(entry)
        } else {
            crate::card::Card::default()
        },
        address: if kind == Kind::Address {
            crate::card::address_of(entry)
        } else {
            crate::card::Address::default()
        },
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
        Kind::Note | Kind::SshKey | Kind::Card | Kind::Address => {
            entry.set_protected(fields::NOTES, draft.notes.as_str());
            let marker = match draft.kind {
                Kind::Note => KIND_NOTE,
                Kind::Card => KIND_CARD,
                Kind::Address => KIND_ADDRESS,
                _ => KIND_SSH,
            };
            entry.custom_data.insert(
                KIND_KEY.to_string(),
                CustomDataItem {
                    value: Some(custom_value(marker)),
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

    match draft.kind {
        Kind::Card => crate::card::apply_card(entry, &draft.card),
        Kind::Address => crate::card::apply_address(entry, &draft.address),
        _ => {}
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
            ..Draft::default()
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

    fn card() -> Draft {
        Draft {
            kind: Kind::Card,
            title: "Visa".into(),
            notes: Zeroizing::new("for travel".into()),
            card: crate::card::Card {
                holder: " Sam Moe ".into(),
                number: Zeroizing::new("4242 4242 4242 4242".into()),
                expiry: "8/29".into(),
                security_code: Zeroizing::new("123".into()),
                pin: Zeroizing::new("9876".into()),
                brand: String::new(),
            },
            ..Draft::default()
        }
    }

    #[test]
    fn a_card_maps_onto_plain_fields_with_its_secrets_protected() {
        with_entry(|e| {
            apply(e, &card());
            assert_eq!(kind_of(e), Kind::Card);
            assert_eq!(e.get("Cardholder"), Some("Sam Moe"));
            assert_eq!(e.get("Number"), Some("4242424242424242"));
            assert_eq!(e.get("Expiry"), Some("08/2029"));
            assert_eq!(e.get("Brand"), Some("visa"), "from the number");
            for (k, protected) in [
                ("Number", true),
                ("Security code", true),
                ("PIN", true),
                ("Notes", true),
                ("Cardholder", false),
                ("Expiry", false),
                ("Brand", false),
            ] {
                assert_eq!(e.fields[k].is_protected(), protected, "{k}");
            }
            let back = draft_of(e);
            assert_eq!(back.card.number.as_str(), "4242424242424242");
            assert_eq!(back.card.pin.as_str(), "9876");
            assert!(back.address.is_empty());

            // an empty value takes the field out
            let mut d = card();
            d.card.pin = Zeroizing::new(String::new());
            d.card.brand = "mc".into();
            apply(e, &d);
            assert!(e.get("PIN").is_none());
            assert_eq!(e.get("Brand"), Some("mastercard"), "a brand given wins");
        });
    }

    #[test]
    fn a_card_summary_shows_the_last_digits_and_no_secret() {
        with_entry(|e| {
            apply(e, &card());
            let s = summary_of("id".into(), e, String::new());
            let c = s.card.clone().expect("card");
            assert_eq!(
                (c.brand.as_str(), c.last4.as_str(), c.expiry.as_str()),
                ("visa", "4242", "08/2029")
            );
            assert_eq!(c.holder, "Sam Moe");
            assert!(c.has_number && c.has_security_code && c.has_pin);
            assert!(!s.has_password && s.username.is_empty() && s.address.is_none());
            let shown = format!("{s:?}");
            for secret in ["4242424242424242", "123", "9876", "for travel"] {
                assert!(!shown.contains(secret), "{secret}");
            }
        });
    }

    #[test]
    fn an_address_is_plain_and_its_country_a_code() {
        with_entry(|e| {
            let mut a = crate::card::Address::default();
            for (k, v) in [
                ("full_name", "Sam Moe"),
                ("line1", "12 Main St"),
                ("city", "Tbilisi"),
                ("country", "ge"),
                ("email", "sam@example.org"),
            ] {
                assert!(a.set(k, v));
            }
            assert!(!a.set("planet", "earth"));
            apply(
                e,
                &Draft {
                    kind: Kind::Address,
                    title: "Home".into(),
                    address: a,
                    ..Draft::default()
                },
            );
            assert_eq!(kind_of(e), Kind::Address);
            assert_eq!(e.get("Country"), Some("GE"));
            assert_eq!(e.get("Address line 1"), Some("12 Main St"));
            assert!(e.get("Address line 2").is_none(), "empty parts stay out");
            assert!(!e.fields["Full name"].is_protected());
            let s = summary_of("id".into(), e, String::new());
            let i = s.address.expect("address");
            assert_eq!(
                (
                    i.name.as_str(),
                    i.line1.as_str(),
                    i.city.as_str(),
                    i.country.as_str()
                ),
                ("Sam Moe", "12 Main St", "Tbilisi", "GE")
            );
            assert_eq!(draft_of(e).address.email, "sam@example.org");
        });
    }
}
