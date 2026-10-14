//! Bringing another password manager's items in (docs/IMPORT.md). This
//! version reads 1Password three ways: its 1PUX export (a zip of JSON and
//! files), its CSV export, and the item JSON its `op` CLI prints (the daemon
//! runs `op`; this module only maps what it printed). Nothing here touches
//! the disk or the network, and the secrets it holds are wiped when dropped.
//!
//! | 1Password | Safe |
//! |---|---|
//! | Login, Password | a Login: username, password, every website, the first one-time code, tags, notes; other fields become custom fields, protected when 1Password conceals them |
//! | Secure Note | a Note |
//! | every other category (Credit Card, Identity, …) | a Note listing its fields; the secret ones are also kept as protected custom fields |
//! | vault | a folder |
//! | archived item | the folder `Archive` |
//! | item in the trash | skipped |
//! | password history | the item's history, oldest first |
//! | documents, attachments | attachments |
//! | favourite | the tag `Favorite` |

use std::collections::{BTreeSet, HashSet};
use std::io::{Cursor, Read};

use chrono::{DateTime, NaiveDateTime};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::item::{Draft, Kind, Summary};
use crate::otp::Totp;
use crate::search;

/// An attachment bigger than this stays out: the whole safe travels to its
/// place on every save.
pub const MAX_ATTACHMENT: u64 = 25 * 1024 * 1024;
/// `export.data` bigger than this isn't read.
const MAX_DATA: u64 = 1024 * 1024 * 1024;
pub const ARCHIVE: &str = "Archive";
pub const FAVORITE: &str = "Favorite";
const UNTITLED: &str = "(untitled)";
/// Names an imported custom field never takes: KDBX's own, and the ones
/// KeePass apps give a meaning.
const RESERVED: &[&str] = &["Title", "UserName", "Password", "URL", "Notes", "otp"];
const RESERVED_PREFIXES: &[&str] = &["KP2A_URL", "KPEX_", "KPH:", "_etm_"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// 1Password's 1PUX export.
    OnePux,
    /// 1Password 8's CSV export (logins and passwords only).
    OnePasswordCsv,
    /// Live from the 1Password app through `op`.
    Op,
}

impl Format {
    pub const NAMES: &'static [&'static str] = &["1pux", "1password-csv", "op"];

    pub fn parse(name: &str) -> Option<Format> {
        match name {
            "1pux" => Some(Format::OnePux),
            "1password-csv" => Some(Format::OnePasswordCsv),
            "op" => Some(Format::Op),
            _ => None,
        }
    }
}

/// Why an export can't be read: a sentence for the user, never a value.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportError(pub String);

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ImportError {}

fn err(message: impl Into<String>) -> ImportError {
    ImportError(message.into())
}

pub struct Field {
    pub name: String,
    pub value: Zeroizing<String>,
    pub protected: bool,
}

pub struct OldPassword {
    pub value: Zeroizing<String>,
    /// When it stopped being the password, if the export says.
    pub time: Option<NaiveDateTime>,
}

/// A file asked for during an import: its bytes (wiped when dropped), or
/// why it can't be had.
pub type Fetched = Result<Zeroizing<Vec<u8>>, String>;

pub struct File {
    pub name: String,
    pub data: Zeroizing<Vec<u8>>,
}

/// One item, ready to be added.
pub struct Imported {
    /// Where it goes below the import's folder ("Personal", "Archive").
    pub folder: String,
    pub draft: Draft,
    pub fields: Vec<Field>,
    /// Oldest first.
    pub history: Vec<OldPassword>,
    pub files: Vec<File>,
    pub created: Option<NaiveDateTime>,
    pub modified: Option<NaiveDateTime>,
}

/// Something left out, and why. Never a value: the title says which.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub title: String,
    pub reason: String,
}

#[derive(Default)]
pub struct Batch {
    pub items: Vec<Imported>,
    pub skipped: Vec<Skipped>,
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Everything goes below this folder ("" is the top).
    pub folder: String,
    pub skip_duplicates: bool,
}

/// What an import adds (or, as a dry run, would add). Counts and titles
/// only (PROTOCOL.md `import`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub logins: usize,
    pub notes: usize,
    pub attachments: usize,
    pub otps: usize,
    /// Items whose website and username an item in the safe already has.
    pub duplicates: usize,
    pub skipped: Vec<Skipped>,
    /// The folders the items go to.
    pub folders: Vec<String>,
}

/// The items an import adds, with their folders, and its report.
pub struct Plan {
    pub report: Report,
    pub add: Vec<(usize, String)>,
}

/// Overwrite every string in a parsed JSON tree; keys stay (they name
/// fields, they don't hold values).
pub fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => m.values_mut().for_each(wipe),
        _ => {}
    }
}

fn st<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn unix(secs: i64) -> Option<NaiveDateTime> {
    DateTime::from_timestamp(secs, 0).map(|d| d.naive_utc())
}

/// A Unix time given as a number or as digits.
fn unix_of(v: Option<&Value>) -> Option<NaiveDateTime> {
    match v? {
        Value::Number(n) => unix(n.as_i64()?),
        Value::String(s) => unix(s.trim().parse().ok()?),
        _ => None,
    }
}

fn rfc3339(s: &str) -> Option<NaiveDateTime> {
    DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|d| d.naive_utc())
}

fn join(a: &str, b: &str) -> String {
    let parts: Vec<&str> = [a, b]
        .iter()
        .flat_map(|p| p.split('/'))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    parts.join("/")
}

/// "CREDIT_CARD" → "Credit card".
fn pretty(category: &str) -> String {
    let lower = category.replace('_', " ").to_lowercase();
    let mut c = lower.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => "Item".to_string(),
    }
}

/// 1PUX category ids (`categoryUuid`).
fn category_1pux(id: &str) -> (Kind, &'static str) {
    match id {
        "001" => (Kind::Login, "Login"),
        "005" => (Kind::Login, "Password"),
        "003" => (Kind::Note, "Secure note"),
        "002" => (Kind::Note, "Credit card"),
        "004" => (Kind::Note, "Identity"),
        "006" => (Kind::Note, "Document"),
        "100" => (Kind::Note, "Software license"),
        "101" => (Kind::Note, "Bank account"),
        "102" => (Kind::Note, "Database"),
        "103" => (Kind::Note, "Driver license"),
        "104" => (Kind::Note, "Outdoor license"),
        "105" => (Kind::Note, "Membership"),
        "106" => (Kind::Note, "Passport"),
        "107" => (Kind::Note, "Reward program"),
        "108" => (Kind::Note, "Social security number"),
        "109" => (Kind::Note, "Wireless router"),
        "110" => (Kind::Note, "Server"),
        "111" => (Kind::Note, "Email account"),
        "112" => (Kind::Note, "API credential"),
        "113" => (Kind::Note, "Medical record"),
        "114" => (Kind::Note, "SSH key"),
        "115" => (Kind::Note, "Crypto wallet"),
        _ => (Kind::Note, "Item"),
    }
}

/// A one-time code as an `otpauth://` URI: kept as is when it is one,
/// built from a bare secret otherwise. None when Safe can't read it.
fn otp_uri(raw: &str, title: &str, username: &str) -> Option<Zeroizing<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let uri = if raw.starts_with("otpauth://") {
        Zeroizing::new(raw.to_string())
    } else {
        let secret = Zeroizing::new(
            raw.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect::<String>()
                .to_uppercase(),
        );
        let issuer = if title.trim().is_empty() {
            "Safe"
        } else {
            title.trim()
        };
        let label = if username.trim().is_empty() {
            issuer.to_string()
        } else {
            format!("{issuer}:{}", username.trim())
        };
        let mut u = url::Url::parse("otpauth://totp/x").ok()?;
        u.set_path(&format!("/{label}"));
        u.query_pairs_mut()
            .append_pair("secret", &secret)
            .append_pair("issuer", issuer);
        Zeroizing::new(u.to_string())
    };
    Totp::parse(&uri).is_ok().then_some(uri)
}

/// One field's value as Safe keeps it.
enum Rendered {
    Text {
        value: Zeroizing<String>,
        secret: bool,
    },
    Otp(Zeroizing<String>),
    /// A file to attach: (1PUX document id or `op` file id, its name).
    File(String, String),
}

fn text(value: &str, secret: bool) -> Option<Rendered> {
    (!value.trim().is_empty()).then(|| Rendered::Text {
        value: Zeroizing::new(value.to_string()),
        secret,
    })
}

/// "202704" or 202704 → "2027-04".
fn month_year(v: &Value) -> Option<String> {
    let digits = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().replace('/', ""),
        _ => return None,
    };
    (digits.len() == 6 && digits.chars().all(|c| c.is_ascii_digit()))
        .then(|| format!("{}-{}", &digits[..4], &digits[4..]))
        .or_else(|| (!digits.is_empty()).then_some(digits))
}

fn date(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.trim().chars().all(|c| c.is_ascii_digit()) => {
            (!s.trim().is_empty()).then(|| s.trim().to_string())
        }
        other => unix_of(Some(other)).map(|t| t.format("%Y-%m-%d").to_string()),
    }
}

fn address(v: &Value) -> String {
    let line = |parts: &[&str]| -> String {
        parts
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let city = [st(v, "city"), st(v, "state"), st(v, "zip")];
    let city_line = if st(v, "city").trim().is_empty() {
        line(&city[1..])
    } else {
        let rest = line(&city[1..]);
        if rest.is_empty() {
            st(v, "city").trim().to_string()
        } else {
            format!("{}, {rest}", st(v, "city").trim())
        }
    };
    [
        st(v, "street").trim(),
        city_line.as_str(),
        st(v, "country").trim(),
    ]
    .iter()
    .filter(|p| !p.is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join("\n")
}

/// A 1PUX section field's value (`{"concealed": "…"}`, `{"email": {…}}`, …),
/// as (label suffix, value) pairs: an SSH key is three.
fn render_1pux(value: &Value) -> Vec<(&'static str, Rendered)> {
    let Some((key, v)) = value.as_object().and_then(|o| o.iter().next()) else {
        return Vec::new();
    };
    let one = |r: Option<Rendered>| r.map(|r| vec![("", r)]).unwrap_or_default();
    match key.as_str() {
        "totp" => one(v
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .map(|s| Rendered::Otp(Zeroizing::new(s.to_string())))),
        "file" => {
            let id = st(v, "documentId");
            if id.is_empty() {
                return Vec::new();
            }
            vec![(
                "",
                Rendered::File(id.to_string(), st(v, "fileName").to_string()),
            )]
        }
        "concealed" | "creditCardNumber" => one(v.as_str().and_then(|s| text(s, true))),
        "email" => {
            let addr = v
                .as_str()
                .unwrap_or_else(|| st(v, "email_address"))
                .to_string();
            one(text(&addr, false))
        }
        "address" => one(text(&address(v), false)),
        "date" => one(date(v).and_then(|d| text(&d, false))),
        "monthYear" => one(month_year(v).and_then(|d| text(&d, false))),
        "sshKey" => {
            let meta = v.get("metadata").unwrap_or(&Value::Null);
            let private = Some(st(v, "privateKey"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| st(meta, "privateKey"));
            [
                ("", text(private, true)),
                (" (public key)", text(st(meta, "publicKey"), false)),
                (" (fingerprint)", text(st(meta, "fingerprint"), false)),
            ]
            .into_iter()
            .filter_map(|(s, r)| r.map(|r| (s, r)))
            .collect()
        }
        // a link to another 1Password item, by its 1Password id: nothing
        // to keep once the items live in Safe
        "reference" => Vec::new(),
        _ => match v {
            Value::String(s) => one(text(s, false)),
            Value::Null => Vec::new(),
            Value::Number(n) => one(text(&n.to_string(), false)),
            Value::Bool(b) => one(text(if *b { "yes" } else { "no" }, false)),
            other => one(text(&other.to_string(), false)),
        },
    }
}

/// The custom-field name `wanted` gets in this item: never one of KDBX's
/// own, never one taken.
fn unique(taken: &mut HashSet<String>, wanted: &str) -> String {
    let trimmed = wanted.trim();
    // a name another KeePass app reads a meaning into keeps its words, not
    // the meaning
    let base = if trimmed.is_empty() {
        "Field".to_string()
    } else if RESERVED_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
        format!("Field: {trimmed}")
    } else {
        trimmed.to_string()
    };
    let clash = |n: &str, taken: &HashSet<String>| {
        taken.contains(n) || RESERVED.iter().any(|r| r.eq_ignore_ascii_case(n))
    };
    let mut name = base.clone();
    let mut n = 2;
    while clash(&name, taken) {
        name = format!("{base} ({n})");
        n += 1;
    }
    taken.insert(name.clone());
    name
}

/// One item being put together from an export.
struct Builder {
    kind: Kind,
    category: String,
    title: String,
    username: String,
    password: Zeroizing<String>,
    websites: Vec<String>,
    tags: Vec<String>,
    notes: Zeroizing<String>,
    otp: Zeroizing<String>,
    /// A Note's field listing, by section.
    lines: Zeroizing<String>,
    section_shown: String,
    fields: Vec<Field>,
    names: HashSet<String>,
    history: Vec<OldPassword>,
    files: Vec<File>,
    folder: String,
    created: Option<NaiveDateTime>,
    modified: Option<NaiveDateTime>,
}

impl Builder {
    fn new(kind: Kind, category: &str, title: &str, folder: &str) -> Builder {
        let title = title.trim();
        Builder {
            kind,
            category: category.to_string(),
            title: if title.is_empty() { UNTITLED } else { title }.to_string(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
            websites: Vec::new(),
            tags: Vec::new(),
            notes: Zeroizing::new(String::new()),
            otp: Zeroizing::new(String::new()),
            lines: Zeroizing::new(String::new()),
            section_shown: String::new(),
            fields: Vec::new(),
            names: HashSet::new(),
            history: Vec::new(),
            files: Vec::new(),
            folder: folder.to_string(),
            created: None,
            modified: None,
        }
    }

    fn website(&mut self, url: &str) {
        let url = url.trim();
        if !url.is_empty() && !self.websites.iter().any(|w| w == url) {
            self.websites.push(url.to_string());
        }
    }

    fn tag(&mut self, tag: &str) {
        let tag = tag.trim();
        if !tag.is_empty() && !self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
            self.tags.push(tag.to_string());
        }
    }

    fn custom(&mut self, name: &str, value: &str, protected: bool) {
        let name = unique(&mut self.names, name);
        self.fields.push(Field {
            name,
            value: Zeroizing::new(value.to_string()),
            protected,
        });
    }

    /// One field: a Login keeps it as a custom field; a Note lists it, and
    /// keeps a secret one as a protected custom field too.
    fn field(&mut self, section: &str, label: &str, value: Rendered) {
        let label = label.trim();
        let section = section.trim();
        match value {
            Rendered::Otp(raw) => {
                if self.otp.is_empty()
                    && let Some(uri) = otp_uri(&raw, &self.title, &self.username)
                {
                    self.otp = uri;
                    return;
                }
                // a second code, or one Safe can't read: kept, not lost
                let name = if label.is_empty() {
                    "One-time password"
                } else {
                    label
                };
                self.custom(name, &raw, true);
            }
            Rendered::File(..) => {}
            Rendered::Text { value, secret } => {
                let shown = if label.is_empty() { "Field" } else { label };
                match self.kind {
                    Kind::Login => {
                        let name = if section.is_empty() {
                            shown.to_string()
                        } else {
                            format!("{section}: {shown}")
                        };
                        self.custom(&name, &value, secret);
                    }
                    Kind::Note => {
                        if !section.is_empty() && self.section_shown != section {
                            if !self.lines.is_empty() {
                                self.lines.push('\n');
                            }
                            self.lines.push_str(section);
                            self.lines.push('\n');
                            self.section_shown = section.to_string();
                        }
                        self.lines.push_str(shown);
                        if value.contains('\n') {
                            self.lines.push_str(":\n");
                            for l in value.lines() {
                                self.lines.push_str("  ");
                                self.lines.push_str(l);
                                self.lines.push('\n');
                            }
                        } else {
                            self.lines.push_str(": ");
                            self.lines.push_str(&value);
                            self.lines.push('\n');
                        }
                        if secret {
                            let name = if section.is_empty() {
                                shown.to_string()
                            } else {
                                format!("{section}: {shown}")
                            };
                            self.custom(&name, &value, true);
                        }
                    }
                }
            }
        }
    }

    fn old_password(&mut self, value: &str, time: Option<NaiveDateTime>) {
        if value.is_empty() || *value == *self.password {
            return;
        }
        self.history.push(OldPassword {
            value: Zeroizing::new(value.to_string()),
            time,
        });
    }

    fn finish(mut self) -> Imported {
        self.history.sort_by_key(|h| h.time);
        let notes = match self.kind {
            Kind::Login => self.notes.clone(),
            Kind::Note => {
                let mut text = Zeroizing::new(String::new());
                let secure_note = self.category == "Secure note";
                if secure_note {
                    text.push_str(self.notes.trim_end());
                    if !self.lines.is_empty() {
                        if !text.is_empty() {
                            text.push_str("\n\n");
                        }
                        text.push_str(self.lines.trim_end());
                    }
                } else {
                    text.push_str(&self.category);
                    text.push('\n');
                    text.push_str(self.lines.trim_end());
                    if !self.notes.trim().is_empty() {
                        text.push_str("\n\n");
                        text.push_str(self.notes.trim_end());
                    }
                }
                Zeroizing::new(text.trim().to_string())
            }
        };
        // a password on a Note (a Server's, a router's) stays a field
        if self.kind == Kind::Note && !self.password.is_empty() {
            let pw = self.password.clone();
            self.custom("Login password", &pw, true);
        }
        Imported {
            folder: self.folder,
            draft: Draft {
                kind: self.kind,
                title: self.title,
                username: self.username,
                password: if self.kind == Kind::Login {
                    self.password
                } else {
                    Zeroizing::new(String::new())
                },
                websites: self.websites,
                apps: Vec::new(),
                tags: self.tags,
                notes,
                otp: self.otp,
            },
            fields: self.fields,
            history: self.history,
            files: self.files,
            created: self.created,
            modified: self.modified,
        }
    }
}

// ── 1PUX ────────────────────────────────────────────────────────────────

fn read_entry(
    zip: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
    limit: u64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let f = zip
        .by_name(name)
        .map_err(|e| format!("it can't be read from the export ({e})"))?;
    if f.size() > limit {
        return Err(format!(
            "it is bigger than {} MB: the whole safe travels on every save",
            limit / (1024 * 1024)
        ));
    }
    // the exact size up front: a buffer that grew would leave copies behind
    let mut buf = Zeroizing::new(Vec::with_capacity(f.size() as usize));
    f.take(limit + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("it can't be read from the export ({e})"))?;
    if buf.len() as u64 > limit {
        return Err("it is bigger than the export said".into());
    }
    Ok(buf)
}

/// A 1PUX file by its document id: `files/<id>__<name>` (the separator has
/// been two and three underscores), or `files/<id>`.
fn find_file(names: &[String], prefix: &str, id: &str, name: &str) -> Option<String> {
    let start = format!("{prefix}files/{id}");
    let mut hits: Vec<&String> = names
        .iter()
        .filter(|n| {
            n.strip_prefix(&start)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('_'))
        })
        .collect();
    hits.sort_by_key(|n| (!n.ends_with(name), n.len()));
    hits.first().map(|n| (*n).clone())
}

fn item_1pux(
    item: &Value,
    folder: &str,
    file: &mut dyn FnMut(&str, &str) -> Fetched,
    skipped: &mut Vec<Skipped>,
) -> Result<Imported, Skipped> {
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let details = item.get("details").unwrap_or(&Value::Null);
    let title = st(overview, "title");
    let state = st(item, "state");
    let trashed = item.get("trashed").and_then(Value::as_bool) == Some(true);
    if trashed || !(state.is_empty() || state == "active" || state == "archived") {
        return Err(Skipped {
            title: if title.trim().is_empty() {
                UNTITLED.into()
            } else {
                title.trim().into()
            },
            reason: "it is in 1Password's trash".into(),
        });
    }
    let (kind, category) = category_1pux(st(item, "categoryUuid"));
    let folder = if state == "archived" {
        ARCHIVE.to_string()
    } else {
        folder.to_string()
    };
    let mut b = Builder::new(kind, category, title, &folder);
    b.created = unix_of(item.get("createdAt"));
    b.modified = unix_of(item.get("updatedAt"));

    b.website(st(overview, "url"));
    for u in overview
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        b.website(st(u, "url"));
    }
    for t in overview
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        b.tag(t.as_str().unwrap_or(""));
    }
    if item.get("favIndex").and_then(Value::as_i64).unwrap_or(0) > 0 {
        b.tag(FAVORITE);
    }

    let login_fields: Vec<&Value> = details
        .get("loginFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    for f in &login_fields {
        match st(f, "designation") {
            "username" if b.username.is_empty() => b.username = st(f, "value").trim().to_string(),
            "password" if b.password.is_empty() => {
                b.password = Zeroizing::new(st(f, "value").to_string())
            }
            _ => {}
        }
    }
    if b.password.is_empty() {
        b.password = Zeroizing::new(st(details, "password").to_string());
    }
    b.notes = Zeroizing::new(st(details, "notesPlain").to_string());

    // the other web-form fields the browser extension saved
    for f in &login_fields {
        let d = st(f, "designation");
        if d == "username" || d == "password" || st(f, "fieldType") == "C" {
            continue;
        }
        if let Some(r) = text(st(f, "value"), st(f, "fieldType") == "P") {
            let name = st(f, "name");
            b.field("Web form", if name.is_empty() { "field" } else { name }, r);
        }
    }

    let mut wanted: Vec<(String, String)> = Vec::new();
    for s in details
        .get("sections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let section = st(s, "title");
        for f in s
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let label = Some(st(f, "title"))
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| st(f, "id"));
            for (suffix, r) in render_1pux(f.get("value").unwrap_or(&Value::Null)) {
                match r {
                    Rendered::File(id, name) => wanted.push((id, name)),
                    r => b.field(section, &format!("{label}{suffix}"), r),
                }
            }
        }
    }

    let mut history: Vec<(String, Option<NaiveDateTime>)> = details
        .get("passwordHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|h| (st(h, "value").to_string(), unix_of(h.get("time"))))
        .collect();
    for (v, t) in &history {
        b.old_password(v, *t);
    }
    for (v, _) in history.iter_mut() {
        v.zeroize();
    }

    if let Some(doc) = details.get("documentAttributes")
        && !st(doc, "documentId").is_empty()
    {
        wanted.push((
            st(doc, "documentId").to_string(),
            st(doc, "fileName").to_string(),
        ));
    }
    for (id, name) in wanted {
        let name = if name.trim().is_empty() {
            id.clone()
        } else {
            name
        };
        match file(&id, &name) {
            Ok(data) => b.files.push(File { name, data }),
            Err(why) => skipped.push(Skipped {
                title: format!("{} — {name}", b.title),
                reason: why,
            }),
        }
    }
    Ok(b.finish())
}

/// 1Password's 1PUX export: a zip with `export.data` (accounts → vaults →
/// items) and the files. Vaults become folders (below the account's name
/// when the file holds more than one account).
pub fn read_1pux(bytes: &[u8]) -> Result<Batch, ImportError> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|_| err("This isn't a 1PUX file: it isn't a zip archive."))?;
    let names: Vec<String> = zip.file_names().map(str::to_string).collect();
    let data_name = names
        .iter()
        .filter(|n| *n == "export.data" || n.ends_with("/export.data"))
        .min_by_key(|n| n.len())
        .cloned()
        .ok_or_else(|| err("This isn't a 1PUX file: it has no export.data."))?;
    let prefix = data_name
        .strip_suffix("export.data")
        .unwrap_or("")
        .to_string();
    let data = read_entry(&mut zip, &data_name, MAX_DATA)
        .map_err(|why| err(format!("The export's data can't be read: {why}.")))?;
    let mut root: Value = serde_json::from_slice(&data).map_err(|e| {
        err(format!(
            "The export's data isn't valid JSON (line {}, column {}).",
            e.line(),
            e.column()
        ))
    })?;
    drop(data);

    let mut batch = Batch::default();
    let empty = Vec::new();
    let accounts = root
        .get("accounts")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let many = accounts.len() > 1;
    let mut fetch = |id: &str, name: &str| -> Fetched {
        let entry = find_file(&names, &prefix, id, name)
            .ok_or_else(|| "the file isn't in the export".to_string())?;
        read_entry(&mut zip, &entry, MAX_ATTACHMENT)
    };
    for account in accounts {
        let attrs = account.get("attrs").unwrap_or(&Value::Null);
        let account_name = Some(st(attrs, "accountName"))
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| st(attrs, "name"));
        for vault in account
            .get("vaults")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let vault_name = Some(st(vault.get("attrs").unwrap_or(&Value::Null), "name"))
                .filter(|n| !n.trim().is_empty())
                .unwrap_or("Vault");
            let folder = if many {
                join(account_name, vault_name)
            } else {
                vault_name.trim().to_string()
            };
            for item in vault
                .get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                match item_1pux(item, &folder, &mut fetch, &mut batch.skipped) {
                    Ok(i) => batch.items.push(i),
                    Err(s) => batch.skipped.push(s),
                }
            }
        }
    }
    wipe(&mut root);
    Ok(batch)
}

// ── CSV ─────────────────────────────────────────────────────────────────

/// RFC 4180 records: a quoted field may hold commas, doubled quotes and
/// line breaks. A byte-order mark at the start is dropped.
pub fn csv_records(text: &str) -> Vec<Vec<Zeroizing<String>>> {
    let mut records = Vec::new();
    let mut record: Vec<Zeroizing<String>> = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut started = false;
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    let take = |f: &mut Zeroizing<String>| std::mem::replace(f, Zeroizing::new(String::new()));
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' if !started => {
                quoted = true;
                started = true;
            }
            ',' => {
                record.push(take(&mut field));
                started = false;
            }
            '\r' => {}
            '\n' => {
                record.push(take(&mut field));
                records.push(std::mem::take(&mut record));
                started = false;
            }
            other => {
                field.push(other);
                started = true;
            }
        }
    }
    if started || !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

fn yes(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "true" | "yes" | "1")
}

/// 1Password 8's CSV export (`Title,Url,Username,Password,OTPAuth,Favorite,
/// Archived,Tags,Notes`; logins and passwords only). Columns are found by
/// name, so their order doesn't matter.
pub fn read_1password_csv(text: &str) -> Result<Batch, ImportError> {
    let rows = csv_records(text);
    let Some((header, rows)) = rows.split_first() else {
        return Err(err("The CSV file is empty."));
    };
    let col = |names: &[&str]| {
        header
            .iter()
            .position(|h| names.iter().any(|n| h.trim().eq_ignore_ascii_case(n)))
    };
    let title = col(&["title"]);
    let password = col(&["password"]);
    if title.is_none() || password.is_none() {
        return Err(err(
            "This doesn't look like 1Password's CSV export: it needs Title and Password columns.",
        ));
    }
    let url = col(&["url", "website", "urls"]);
    let username = col(&["username"]);
    let otp = col(&["otpauth", "one-time password", "otp"]);
    let favorite = col(&["favorite"]);
    let archived = col(&["archived"]);
    let tags = col(&["tags"]);
    let notes = col(&["notes", "notesplain"]);
    let mut batch = Batch::default();
    for row in rows {
        if row.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let cell = |c: Option<usize>| c.and_then(|i| row.get(i)).map(|v| v.as_str()).unwrap_or("");
        let folder = if yes(cell(archived)) { ARCHIVE } else { "" };
        let mut b = Builder::new(Kind::Login, "Login", cell(title), folder);
        b.username = cell(username).trim().to_string();
        b.password = Zeroizing::new(cell(password).to_string());
        b.website(cell(url));
        for t in cell(tags).split([';', ',']) {
            b.tag(t);
        }
        if yes(cell(favorite)) {
            b.tag(FAVORITE);
        }
        b.notes = Zeroizing::new(cell(notes).to_string());
        if let Some(r) = Some(cell(otp))
            .filter(|o| !o.trim().is_empty())
            .map(|o| Rendered::Otp(Zeroizing::new(o.to_string())))
        {
            b.field("", "One-time password", r);
        }
        batch.items.push(b.finish());
    }
    Ok(batch)
}

// ── op ──────────────────────────────────────────────────────────────────

/// A file `op` must be asked for: an attachment (`op read`) or a Document
/// item's file (`op document get`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpFile {
    pub vault: String,
    pub item: String,
    /// The attachment's id; empty for a Document.
    pub file: String,
    pub name: String,
    pub document: bool,
    pub size: Option<u64>,
}

/// One `op item get --format json` item.
fn item_op(
    item: &Value,
    folder: &str,
    fetch: &mut dyn FnMut(&OpFile) -> Fetched,
    skipped: &mut Vec<Skipped>,
) -> Result<Imported, Skipped> {
    let title = st(item, "title");
    let state = st(item, "state").to_uppercase();
    if state == "DELETED" || state == "TRASHED" {
        return Err(Skipped {
            title: if title.trim().is_empty() {
                UNTITLED.into()
            } else {
                title.trim().into()
            },
            reason: "it is in 1Password's trash".into(),
        });
    }
    let category = st(item, "category").to_uppercase();
    let (kind, label) = match category.as_str() {
        "LOGIN" => (Kind::Login, "Login".to_string()),
        "PASSWORD" => (Kind::Login, "Password".to_string()),
        "SECURE_NOTE" => (Kind::Note, "Secure note".to_string()),
        other => (Kind::Note, pretty(other)),
    };
    let folder = if state == "ARCHIVED" { ARCHIVE } else { folder };
    let mut b = Builder::new(kind, &label, title, folder);
    b.created = rfc3339(st(item, "created_at"));
    b.modified = rfc3339(st(item, "updated_at"));

    let urls: Vec<&Value> = item
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    for u in urls
        .iter()
        .filter(|u| u.get("primary") == Some(&Value::Bool(true)))
    {
        b.website(st(u, "href"));
    }
    for u in &urls {
        b.website(st(u, "href"));
    }
    for t in item
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        b.tag(t.as_str().unwrap_or(""));
    }
    if item.get("favorite").and_then(Value::as_bool) == Some(true) {
        b.tag(FAVORITE);
    }

    let fields: Vec<&Value> = item
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    // the built-in username, password and notes first: a one-time code's
    // label wants the username
    for f in &fields {
        let value = st(f, "value");
        match st(f, "purpose") {
            "USERNAME" if b.username.is_empty() => b.username = value.trim().to_string(),
            "PASSWORD" if b.password.is_empty() => b.password = Zeroizing::new(value.to_string()),
            "NOTES" => b.notes = Zeroizing::new(value.to_string()),
            _ => {}
        }
    }
    for f in &fields {
        let purpose = st(f, "purpose");
        if purpose == "USERNAME" || purpose == "NOTES" {
            continue;
        }
        if purpose == "PASSWORD" {
            let history = f
                .get("password_details")
                .and_then(|d| d.get("history"))
                .and_then(Value::as_array);
            for h in history.into_iter().flatten() {
                match h {
                    Value::String(s) => b.old_password(s, None),
                    other => b.old_password(st(other, "value"), unix_of(other.get("time"))),
                }
            }
            continue;
        }
        let section = f
            .get("section")
            .map(|s| st(s, "label"))
            .unwrap_or("")
            .to_string();
        let label = Some(st(f, "label"))
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| st(f, "id"));
        let value = f.get("value").unwrap_or(&Value::Null);
        let r = match st(f, "type").to_uppercase().as_str() {
            "OTP" => value
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .map(|s| Rendered::Otp(Zeroizing::new(s.to_string()))),
            "CONCEALED" | "CREDIT_CARD_NUMBER" | "SSHKEY" => {
                value.as_str().and_then(|s| text(s, true))
            }
            "DATE" => date(value).and_then(|d| text(&d, false)),
            "MONTH_YEAR" => month_year(value).and_then(|d| text(&d, false)),
            "REFERENCE" => None,
            _ => match value {
                Value::String(s) => text(s, false),
                Value::Null => None,
                Value::Object(_) => text(&address(value), false),
                other => text(&other.to_string(), false),
            },
        };
        if let Some(r) = r {
            b.field(&section, label, r);
        }
    }

    let vault = item
        .get("vault")
        .map(|v| st(v, "id"))
        .unwrap_or("")
        .to_string();
    let id = st(item, "id").to_string();
    let files: Vec<&Value> = item
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let mut wanted: Vec<OpFile> = Vec::new();
    if category == "DOCUMENT" {
        let name = files
            .first()
            .map(|f| st(f, "name"))
            .filter(|n| !n.trim().is_empty())
            .unwrap_or(title)
            .to_string();
        wanted.push(OpFile {
            vault: vault.clone(),
            item: id.clone(),
            file: String::new(),
            name,
            document: true,
            size: files
                .first()
                .and_then(|f| f.get("size"))
                .and_then(Value::as_u64),
        });
    } else {
        for f in &files {
            wanted.push(OpFile {
                vault: vault.clone(),
                item: id.clone(),
                file: st(f, "id").to_string(),
                name: st(f, "name").to_string(),
                document: false,
                size: f.get("size").and_then(Value::as_u64),
            });
        }
    }
    for w in wanted {
        let shown = if w.name.trim().is_empty() {
            "file".to_string()
        } else {
            w.name.clone()
        };
        let got = if w.size.is_some_and(|s| s > MAX_ATTACHMENT) {
            Err(format!(
                "it is bigger than {} MB: the whole safe travels on every save",
                MAX_ATTACHMENT / (1024 * 1024)
            ))
        } else {
            fetch(&w)
        };
        match got {
            Ok(data) => b.files.push(File { name: shown, data }),
            Err(why) => skipped.push(Skipped {
                title: format!("{} — {shown}", b.title),
                reason: why,
            }),
        }
    }
    Ok(b.finish())
}

/// Items `op item get --format json` printed, each with the folder its
/// vault becomes; `fetch` asks `op` for a file.
pub fn read_op(items: &[(Value, String)], fetch: &mut dyn FnMut(&OpFile) -> Fetched) -> Batch {
    let mut batch = Batch::default();
    for (item, folder) in items {
        match item_op(item, folder, fetch, &mut batch.skipped) {
            Ok(i) => batch.items.push(i),
            Err(s) => batch.skipped.push(s),
        }
    }
    batch
}

// ── the plan ────────────────────────────────────────────────────────────

fn site(url: &str) -> String {
    let h = search::host(url);
    h.strip_prefix("www.").map(str::to_string).unwrap_or(h)
}

/// What an import of `batch` into a safe holding `existing` adds. A
/// duplicate has a website host and a username an item already has; it is
/// added unless `skip_duplicates`.
pub fn plan(batch: &Batch, existing: &[Summary], opts: &Options) -> Plan {
    let known: HashSet<(String, String)> = existing
        .iter()
        .filter(|s| !s.username.trim().is_empty())
        .flat_map(|s| {
            s.websites
                .iter()
                .map(|w| (site(w), s.username.trim().to_lowercase()))
        })
        .filter(|(h, _)| !h.is_empty())
        .collect();
    let mut report = Report {
        skipped: batch.skipped.clone(),
        ..Report::default()
    };
    let mut folders = BTreeSet::new();
    let mut add = Vec::new();
    for (i, item) in batch.items.iter().enumerate() {
        let d = &item.draft;
        let user = d.username.trim().to_lowercase();
        let dup = !user.is_empty()
            && d.websites
                .iter()
                .any(|w| known.contains(&(site(w), user.clone())));
        if dup {
            report.duplicates += 1;
            if opts.skip_duplicates {
                report.skipped.push(Skipped {
                    title: d.title.clone(),
                    reason: "Safe already has its website and username".into(),
                });
                continue;
            }
        }
        match d.kind {
            Kind::Login => report.logins += 1,
            Kind::Note => report.notes += 1,
        }
        if !d.otp.is_empty() {
            report.otps += 1;
        }
        report.attachments += item.files.len();
        let folder = join(&opts.folder, &item.folder);
        if !folder.is_empty() {
            folders.insert(folder.clone());
        }
        add.push((i, folder));
    }
    report.folders = folders.into_iter().collect();
    Plan { report, add }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_keep_commas_quotes_and_line_breaks() {
        let rows =
            csv_records("\u{feff}Title,Notes\r\n\"A, B\",\"say \"\"hi\"\"\nline 2\"\r\nplain,\n");
        let v: Vec<Vec<&str>> = rows
            .iter()
            .map(|r| r.iter().map(|f| f.as_str()).collect())
            .collect();
        assert_eq!(
            v,
            vec![
                vec!["Title", "Notes"],
                vec!["A, B", "say \"hi\"\nline 2"],
                vec!["plain", ""],
            ]
        );
    }

    #[test]
    fn a_bare_secret_becomes_an_otpauth_uri() {
        let uri = otp_uri("jbsw y3dp ehpk 3pxp", "Git Hub", "sam").expect("readable");
        assert!(uri.starts_with("otpauth://totp/Git%20Hub:sam?secret=JBSWY3DPEHPK3PXP"));
        assert!(Totp::parse(&uri).is_ok());
        assert!(otp_uri("not base32 !!", "x", "").is_none());
        let kept = "otpauth://totp/X:sam?secret=JBSWY3DPEHPK3PXP&issuer=X";
        assert_eq!(otp_uri(kept, "y", "z").expect("kept").as_str(), kept);
    }

    #[test]
    fn values_render_as_text() {
        let r = |v: Value| match render_1pux(&v).pop() {
            Some((_, Rendered::Text { value, secret })) => (value.to_string(), secret),
            _ => (String::new(), false),
        };
        assert_eq!(
            r(serde_json::json!({"monthYear": 202704})),
            ("2027-04".into(), false)
        );
        assert_eq!(
            r(serde_json::json!({"date": 1767225600})),
            ("2026-01-01".into(), false)
        );
        assert_eq!(
            r(serde_json::json!({"email": {"email_address": "sam@example.org", "provider": null}})),
            ("sam@example.org".into(), false)
        );
        assert_eq!(
            r(serde_json::json!({"creditCardNumber": "4111"})),
            ("4111".into(), true)
        );
        assert_eq!(
            r(
                serde_json::json!({"address": {"street": "1 Hill Rd", "city": "Ewetown", "state": "", "zip": "123", "country": "nz"}})
            ),
            ("1 Hill Rd\nEwetown, 123\nnz".into(), false)
        );
        assert!(render_1pux(&serde_json::json!({"reference": "abc"})).is_empty());
        assert_eq!(render_1pux(&serde_json::json!({"sshKey": {"privateKey": "k", "metadata": {"publicKey": "p", "fingerprint": "f"}}})).len(), 3);
    }

    #[test]
    fn custom_field_names_never_take_kdbx_own() {
        let mut taken = HashSet::new();
        assert_eq!(unique(&mut taken, "Password"), "Password (2)");
        assert_eq!(unique(&mut taken, "PIN"), "PIN");
        assert_eq!(unique(&mut taken, "PIN"), "PIN (2)");
        assert_eq!(unique(&mut taken, "KP2A_URL_1"), "Field: KP2A_URL_1");
        assert_eq!(unique(&mut taken, " "), "Field");
    }

    #[test]
    fn wipe_overwrites_every_string() {
        let mut v = serde_json::json!({"a": ["secret", {"b": "more"}], "n": 1});
        wipe(&mut v);
        let shown = v.to_string();
        assert!(!shown.contains("secret") && !shown.contains("more"));
    }

    #[test]
    fn folders_join_without_empty_parts() {
        assert_eq!(join("", "Personal"), "Personal");
        assert_eq!(join("1Password/", "/Archive"), "1Password/Archive");
        assert_eq!(join("", ""), "");
    }
}
