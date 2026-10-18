//! Cards and addresses (docs/SYSTEM.md §4, docs/FORMAT.md "Cards and
//! addresses"): two more kinds of item in the same KDBX file, so the copy in
//! the place is encrypted like everything else. Every KeePass app shows
//! their fields as plain custom fields:
//!
//! | Safe | KDBX | protected |
//! |---|---|---|
//! | kind | custom data `ewe.kind = card` / `address` | — |
//! | cardholder, number, expiry, security code, PIN, brand | `Cardholder`, `Number`, `Expiry` (`MM/YYYY`), `Security code`, `PIN`, `Brand` | number, code, PIN |
//! | an address | `Full name`, `Organization`, `Address line 1`, `Address line 2`, `City`, `Region`, `Postal code`, `Country`, `Phone`, `Email` | no |
//! | both | `Notes` | yes |
//!
//! A list ([`CardInfo`]) shows a card's brand, its last four digits, the
//! expiry and the holder: never the number, the code or the PIN. The number's
//! check (Luhn) only warns: a card Safe thinks is wrong is still kept.

use keepass::db::{Entry, EntryId, EntryRef, fields};
use zeroize::Zeroizing;

use crate::item::{self, Kind};
use crate::safe::{Error, Safe};

pub const CARDHOLDER: &str = "Cardholder";
pub const NUMBER: &str = "Number";
pub const EXPIRY: &str = "Expiry";
pub const SECURITY_CODE: &str = "Security code";
pub const PIN: &str = "PIN";
pub const BRAND: &str = "Brand";

pub const FULL_NAME: &str = "Full name";
pub const ORGANIZATION: &str = "Organization";
pub const LINE1: &str = "Address line 1";
pub const LINE2: &str = "Address line 2";
pub const CITY: &str = "City";
pub const REGION: &str = "Region";
pub const POSTAL_CODE: &str = "Postal code";
pub const COUNTRY: &str = "Country";
pub const PHONE: &str = "Phone";
pub const EMAIL: &str = "Email";

/// The brands Safe names (`Brand`); `other` for the rest.
pub const BRANDS: &[&str] = &[
    "visa",
    "mastercard",
    "amex",
    "discover",
    "jcb",
    "unionpay",
    "diners",
    "maestro",
    "mir",
    "other",
];

/// A card's fields: (protocol name, KDBX name, protected).
pub const CARD_FIELDS: &[(&str, &str, bool)] = &[
    ("holder", CARDHOLDER, false),
    ("number", NUMBER, true),
    ("expiry", EXPIRY, false),
    ("security_code", SECURITY_CODE, true),
    ("pin", PIN, true),
    ("brand", BRAND, false),
];

/// An address's fields: (protocol name, KDBX name). None is protected.
pub const ADDRESS_FIELDS: &[(&str, &str)] = &[
    ("full_name", FULL_NAME),
    ("organization", ORGANIZATION),
    ("line1", LINE1),
    ("line2", LINE2),
    ("city", CITY),
    ("region", REGION),
    ("postal_code", POSTAL_CODE),
    ("country", COUNTRY),
    ("phone", PHONE),
    ("email", EMAIL),
];

/// A new address's title when none is given.
pub const ADDRESS_TITLE: &str = "Home";

/// Why a card's value can't be taken: a sentence for the user, never the value.
#[derive(Debug, PartialEq, Eq)]
pub struct CardError(pub String);

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CardError {}

/// A card as the editor fills it in. The secrets are wiped when dropped.
#[derive(Clone, Default)]
pub struct Card {
    pub holder: String,
    /// Digits only (see [`number`]).
    pub number: Zeroizing<String>,
    /// `MM/YYYY`, or "" for none.
    pub expiry: String,
    pub security_code: Zeroizing<String>,
    pub pin: Zeroizing<String>,
    /// One of [`BRANDS`], or "" to take it from the number.
    pub brand: String,
}

impl PartialEq for Card {
    fn eq(&self, o: &Card) -> bool {
        self.holder == o.holder
            && *self.number == *o.number
            && self.expiry == o.expiry
            && *self.security_code == *o.security_code
            && *self.pin == *o.pin
            && self.brand == o.brand
    }
}

/// An address, every part plain text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Address {
    pub full_name: String,
    pub organization: String,
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub region: String,
    pub postal_code: String,
    /// ISO 3166-1 alpha-2 (upper case) when it is one, else as typed.
    pub country: String,
    pub phone: String,
    pub email: String,
}

impl Address {
    /// A part by its protocol name ("line1"); None for a name that is none.
    pub fn get(&self, key: &str) -> Option<&str> {
        Some(match key {
            "full_name" => &self.full_name,
            "organization" => &self.organization,
            "line1" => &self.line1,
            "line2" => &self.line2,
            "city" => &self.city,
            "region" => &self.region,
            "postal_code" => &self.postal_code,
            "country" => &self.country,
            "phone" => &self.phone,
            "email" => &self.email,
            _ => return None,
        })
    }

    /// Set a part by its protocol name; false for a name that is none.
    pub fn set(&mut self, key: &str, value: &str) -> bool {
        let slot = match key {
            "full_name" => &mut self.full_name,
            "organization" => &mut self.organization,
            "line1" => &mut self.line1,
            "line2" => &mut self.line2,
            "city" => &mut self.city,
            "region" => &mut self.region,
            "postal_code" => &mut self.postal_code,
            "country" => &mut self.country,
            "phone" => &mut self.phone,
            "email" => &mut self.email,
            _ => return false,
        };
        *slot = if key == "country" {
            country(value)
        } else {
            value.trim().to_string()
        };
        true
    }

    pub fn is_empty(&self) -> bool {
        ADDRESS_FIELDS
            .iter()
            .all(|(k, _)| self.get(k).unwrap_or("").is_empty())
    }
}

/// What a list shows of a card. Never the number, the code or the PIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardInfo {
    pub brand: String,
    /// The number's last four digits ("" when it has fewer than ten).
    pub last4: String,
    /// `MM/YYYY`, or "".
    pub expiry: String,
    pub holder: String,
    pub has_number: bool,
    pub has_security_code: bool,
    pub has_pin: bool,
}

/// What a list shows of an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressInfo {
    pub name: String,
    pub line1: String,
    pub city: String,
    pub country: String,
}

// ── values ──────────────────────────────────────────────────────────────

/// A card number as typed ("4242 4242-4242.4242") made digits only.
/// Anything but digits, spaces, dashes and dots is refused.
pub fn number(text: &str) -> Result<Zeroizing<String>, CardError> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for c in text.chars() {
        match c {
            '0'..='9' => out.push(c),
            ' ' | '-' | '.' | '\t' | '\u{a0}' => {}
            _ => {
                return Err(CardError(
                    "A card number has only digits (spaces are fine).".into(),
                ));
            }
        }
    }
    Ok(out)
}

/// The Luhn check every card number passes (ISO/IEC 7812).
pub fn luhn(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let sum: u32 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// A warning for a number that looks mistyped; None when it looks right (or
/// is empty). Safe keeps the number either way.
pub fn check(digits: &str) -> Option<String> {
    if digits.is_empty() {
        return None;
    }
    if !(12..=19).contains(&digits.len()) {
        return Some("A card number has 12 to 19 digits. Check it for a typo.".into());
    }
    if !luhn(digits) {
        return Some("The card number doesn't pass the card check. Check it for a typo.".into());
    }
    None
}

/// The brand a number belongs to, from its first digits (the card
/// networks' published ranges); `other` when Safe doesn't know it.
pub fn brand_of(digits: &str) -> &'static str {
    let p = |n: usize| -> u32 {
        digits
            .get(..n)
            .filter(|s| s.len() == n && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    let (p2, p3, p4, p6) = (p(2), p(3), p(4), p(6));
    if digits.starts_with('4') {
        "visa"
    } else if (2200..=2204).contains(&p4) {
        "mir"
    } else if (51..=55).contains(&p2) || (2221..=2720).contains(&p4) {
        "mastercard"
    } else if p2 == 34 || p2 == 37 {
        "amex"
    } else if p4 == 6011 || (644..=649).contains(&p3) || p2 == 65 || (622126..=622925).contains(&p6)
    {
        "discover"
    } else if (3528..=3589).contains(&p4) {
        "jcb"
    } else if p2 == 62 || p2 == 81 {
        "unionpay"
    } else if (300..=305).contains(&p3) || p4 == 3095 || [36, 38, 39].contains(&p2) {
        "diners"
    } else if [50, 56, 57, 58, 67].contains(&p2) || p4 == 6304 || p4 == 6390 {
        "maestro"
    } else {
        "other"
    }
}

/// A brand as a person or another app names it ("MC", "American Express",
/// "Diners Club") → one of [`BRANDS`]; None for a name Safe doesn't know.
pub fn brand(text: &str) -> Option<&'static str> {
    let key: String = text
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase();
    Some(match key.as_str() {
        "visa" | "visaelectron" | "electron" => "visa",
        "mastercard" | "mc" | "master" => "mastercard",
        "amex" | "americanexpress" => "amex",
        "discover" | "discovercard" => "discover",
        "jcb" => "jcb",
        "unionpay" | "chinaunionpay" | "cup" => "unionpay",
        "diners" | "dinersclub" | "dinersclubinternational" | "carteblanche" => "diners",
        "maestro" => "maestro",
        "mir" => "mir",
        "other" => "other",
        _ => return None,
    })
}

/// How a brand is written for people ("Visa", "Diners Club").
pub fn brand_name(brand: &str) -> &'static str {
    match brand {
        "visa" => "Visa",
        "mastercard" => "Mastercard",
        "amex" => "Amex",
        "discover" => "Discover",
        "jcb" => "JCB",
        "unionpay" => "UnionPay",
        "diners" => "Diners Club",
        "maestro" => "Maestro",
        "mir" => "Mir",
        _ => "Card",
    }
}

/// The last four digits a list may show; "" when the number has fewer than
/// ten (four digits of a short one would say too much).
pub fn last4(digits: &str) -> String {
    if digits.len() >= 10 && digits.bytes().all(|b| b.is_ascii_digit()) {
        digits[digits.len() - 4..].to_string()
    } else {
        String::new()
    }
}

/// A new card's title when none is given: "Visa •• 4242".
pub fn card_title(brand_id: &str, digits: &str) -> String {
    let name = brand_name(brand_id);
    match last4(digits) {
        l if l.is_empty() => name.to_string(),
        l => format!("{name} •• {l}"),
    }
}

/// An expiry as typed → `MM/YYYY`: `MM/YY`, `MM/YYYY`, `M/YY`, with `/`,
/// `-`, `.` or nothing between, and 1Password's `YYYY-MM`. "" stays "".
pub fn expiry(text: &str) -> Result<String, CardError> {
    let bad = || CardError("The expiry is a month and a year: MM/YY or MM/YYYY.".into());
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if t.is_empty() {
        return Ok(String::new());
    }
    let parts: Vec<&str> = t.split(['/', '-', '.']).collect();
    let num = |s: &str| -> Option<u32> {
        (!s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let (month, year) = match parts.as_slice() {
        [a, b] if a.len() == 4 => (num(b).ok_or_else(bad)?, num(a).ok_or_else(bad)?),
        [a, b] if a.len() <= 2 && (b.len() == 2 || b.len() == 4) => {
            (num(a).ok_or_else(bad)?, num(b).ok_or_else(bad)?)
        }
        [one] if one.len() == 4 => (
            num(&one[..2]).ok_or_else(bad)?,
            num(&one[2..]).ok_or_else(bad)?,
        ),
        [one] if one.len() == 6 => {
            let (mm, yyyy) = (
                num(&one[..2]).ok_or_else(bad)?,
                num(&one[2..]).ok_or_else(bad)?,
            );
            if (1..=12).contains(&mm) && yyyy >= 1970 {
                (mm, yyyy)
            } else {
                // 1Password's own form: 202704
                (
                    num(&one[4..]).ok_or_else(bad)?,
                    num(&one[..4]).ok_or_else(bad)?,
                )
            }
        }
        _ => return Err(bad()),
    };
    let year = if year < 100 { 2000 + year } else { year };
    if !(1..=12).contains(&month) || !(1970..=2199).contains(&year) {
        return Err(bad());
    }
    Ok(format!("{month:02}/{year:04}"))
}

/// `MM/YYYY` → ("08", "2029"); None for anything else.
pub fn expiry_parts(expiry: &str) -> Option<(String, String)> {
    let e = self::expiry(expiry).ok().filter(|e| !e.is_empty())?;
    let (m, y) = e.split_once('/')?;
    Some((m.to_string(), y.to_string()))
}

/// A country as Safe keeps it: two letters become an upper-case ISO code
/// ("ge" → "GE"), anything else stays as typed.
pub fn country(text: &str) -> String {
    let t = text.trim();
    if t.chars().count() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) {
        t.to_ascii_uppercase()
    } else {
        t.to_string()
    }
}

/// (given, family) from a full name: the last word is the family name.
pub fn split_name(full: &str) -> (String, String) {
    let words: Vec<&str> = full.split_whitespace().collect();
    match words.as_slice() {
        [] => (String::new(), String::new()),
        [one] => (one.to_string(), String::new()),
        [rest @ .., last] => (rest.join(" "), last.to_string()),
    }
}

// ── entries ─────────────────────────────────────────────────────────────

fn text(entry: &Entry, key: &str) -> String {
    entry.get(key).unwrap_or_default().to_string()
}

/// Write a field, or take it out when the value is empty (other KeePass
/// apps then show no empty rows).
fn put(entry: &mut Entry, key: &str, value: &str, protected: bool) {
    if value.is_empty() {
        entry.fields.remove(key);
    } else if protected {
        entry.set_protected(key, value);
    } else {
        entry.set_unprotected(key, value);
    }
}

/// Write a card's fields into its entry ([`crate::item::apply`] does the
/// rest). The brand comes from the number when none is given.
pub(crate) fn apply_card(entry: &mut Entry, card: &Card) {
    let digits = number(&card.number).unwrap_or_else(|_| card.number.clone());
    put(entry, CARDHOLDER, card.holder.trim(), false);
    put(entry, NUMBER, &digits, true);
    let exp = expiry(&card.expiry).unwrap_or_else(|_| card.expiry.trim().to_string());
    put(entry, EXPIRY, &exp, false);
    put(entry, SECURITY_CODE, card.security_code.trim(), true);
    put(entry, PIN, card.pin.trim(), true);
    let b = brand(&card.brand)
        .or_else(|| (!digits.is_empty()).then(|| brand_of(&digits)))
        .unwrap_or("");
    put(entry, BRAND, b, false);
}

/// Write an address's fields into its entry.
pub(crate) fn apply_address(entry: &mut Entry, a: &Address) {
    for (k, name) in ADDRESS_FIELDS {
        let v = a.get(k).unwrap_or("");
        let v = if *k == "country" {
            country(v)
        } else {
            v.trim().to_string()
        };
        put(entry, name, &v, false);
    }
}

pub fn card_of(entry: &Entry) -> Card {
    Card {
        holder: text(entry, CARDHOLDER),
        number: Zeroizing::new(text(entry, NUMBER)),
        expiry: text(entry, EXPIRY),
        security_code: Zeroizing::new(text(entry, SECURITY_CODE)),
        pin: Zeroizing::new(text(entry, PIN)),
        brand: text(entry, BRAND),
    }
}

pub fn address_of(entry: &Entry) -> Address {
    let mut a = Address::default();
    for (k, name) in ADDRESS_FIELDS {
        a.set(k, entry.get(name).unwrap_or(""));
    }
    a
}

/// A card's summary part: the number is read only for its last digits and
/// its brand.
pub fn card_info(entry: &Entry) -> CardInfo {
    let raw = Zeroizing::new(text(entry, NUMBER));
    let digits = number(&raw).unwrap_or_default();
    let stored = text(entry, BRAND);
    let b = brand(&stored)
        .or_else(|| (!digits.is_empty()).then(|| brand_of(&digits)))
        .unwrap_or("other");
    let exp = text(entry, EXPIRY);
    CardInfo {
        brand: b.to_string(),
        last4: last4(&digits),
        expiry: expiry(&exp).unwrap_or(exp),
        holder: text(entry, CARDHOLDER),
        has_number: !raw.trim().is_empty(),
        has_security_code: entry.get(SECURITY_CODE).is_some_and(|v| !v.is_empty()),
        has_pin: entry.get(PIN).is_some_and(|v| !v.is_empty()),
    }
}

pub fn address_info(entry: &Entry) -> AddressInfo {
    AddressInfo {
        name: text(entry, FULL_NAME),
        line1: text(entry, LINE1),
        city: text(entry, CITY),
        country: text(entry, COUNTRY),
    }
}

/// The KDBX field a protocol name means on this kind of item ("number" on
/// a card → `Number`; `reveal --field`, `copy --field`). The KDBX names
/// work as they are.
pub fn alias(kind: Kind, name: &str) -> Option<&'static str> {
    match kind {
        Kind::Card => CARD_FIELDS.iter().find(|(p, _, _)| *p == name).map(|f| f.1),
        Kind::Address => ADDRESS_FIELDS.iter().find(|(p, _)| *p == name).map(|f| f.1),
        _ => None,
    }
}

// ── filling a form (the browser's `fields`) ─────────────────────────────

/// What the browser fills from a card: never the PIN.
pub struct CardFill {
    pub holder: String,
    pub number: Zeroizing<String>,
    pub expiry_month: String,
    pub expiry_year: String,
    pub security_code: Zeroizing<String>,
    pub brand: String,
}

pub fn card_fill(entry: &Entry) -> CardFill {
    let c = card_of(entry);
    let digits = number(&c.number).unwrap_or_else(|_| c.number.clone());
    let (m, y) = expiry_parts(&c.expiry).unwrap_or_default();
    let info = card_info(entry);
    CardFill {
        holder: c.holder.clone(),
        number: digits,
        expiry_month: m,
        expiry_year: y,
        security_code: Zeroizing::new(c.security_code.trim().to_string()),
        brand: info.brand,
    }
}

// ── notes an earlier 1Password import made (`convert`) ──────────────────

/// One note `convert` turned into a card or an address (or would).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Converted {
    pub id: String,
    pub title: String,
    pub kind: Kind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConvertReport {
    pub converted: Vec<Converted>,
    /// (title, why): looked like an imported card or identity, but Safe
    /// can't read it as one.
    pub skipped: Vec<(String, String)>,
}

/// What a converted note becomes.
struct Conversion {
    kind: Kind,
    card: Card,
    address: Address,
    notes: Zeroizing<String>,
    /// Custom fields whose value moved into the card's own fields.
    moved: Vec<String>,
}

/// The `label: value` lines of an imported note, by line number; a
/// value on the lines below its label ("address:") is joined with `\n`.
fn labelled(lines: &[&str]) -> Vec<(usize, usize, String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.starts_with(' ') {
            i += 1;
            continue;
        }
        if let Some(label) = l.strip_suffix(':') {
            let mut j = i + 1;
            let mut value = Vec::new();
            while j < lines.len() && lines[j].starts_with("  ") {
                value.push(lines[j].trim());
                j += 1;
            }
            if !value.is_empty() {
                out.push((i, j, label.trim().to_lowercase(), value.join("\n")));
                i = j;
                continue;
            }
        } else if let Some((label, value)) = l.split_once(": ") {
            out.push((
                i,
                i + 1,
                label.trim().to_lowercase(),
                value.trim().to_string(),
            ));
        }
        i += 1;
    }
    out
}

/// The note's text without the lines `convert` took: the importer's first
/// line, the labels that became fields, any line holding a moved secret;
/// a section left with only its title goes too.
fn rest_of(lines: &[&str], gone: &[bool]) -> Zeroizing<String> {
    let mut blocks: Vec<Vec<(&str, bool)>> = vec![Vec::new()];
    for (l, g) in lines.iter().zip(gone) {
        if l.trim().is_empty() {
            blocks.push(Vec::new());
        } else if let Some(b) = blocks.last_mut() {
            b.push((l, *g));
        }
    }
    let mut kept: Vec<String> = Vec::new();
    for b in blocks {
        let left: Vec<&str> = b.iter().filter(|(_, g)| !g).map(|(l, _)| *l).collect();
        let only_title =
            left.len() == 1 && b.len() > 1 && !left[0].contains(": ") && !left[0].ends_with(':');
        if left.is_empty() || only_title {
            continue;
        }
        kept.push(left.join("\n"));
    }
    Zeroizing::new(kept.join("\n\n"))
}

/// The protected custom fields of an entry (not KDBX's own): (name, value).
fn secrets<'a>(e: &'a EntryRef<'_>) -> Vec<(&'a str, &'a str)> {
    e.fields
        .iter()
        .filter(|(k, v)| {
            v.is_protected() && ![fields::PASSWORD, fields::NOTES, item::OTP].contains(&k.as_str())
        })
        .map(|(k, v)| (k.as_str(), v.get().as_str()))
        .collect()
}

/// The last part of an imported field's name ("Additional Details: PIN" →
/// "pin").
fn short(name: &str) -> String {
    name.rsplit(": ")
        .next()
        .unwrap_or(name)
        .trim()
        .to_lowercase()
}

fn as_card(e: &EntryRef<'_>, lines: &[&str]) -> Result<Conversion, String> {
    let secret = secrets(e);
    let numbers: Vec<&(&str, &str)> = secret
        .iter()
        .filter(|(_, v)| number(v).is_ok_and(|d| (12..=19).contains(&d.len())))
        .collect();
    let (num_field, num_value) = match numbers.as_slice() {
        [] => return Err("Safe found no card number in it".into()),
        [one] => **one,
        _ => return Err("it holds more than one card number".into()),
    };
    let mut c = Card {
        number: number(num_value).map_err(|e| e.0)?,
        ..Card::default()
    };
    let mut moved = vec![num_field.to_string()];
    let mut values: Vec<&str> = vec![num_value];
    for (name, value) in &secret {
        let s = short(name);
        if ["verification number", "security code", "cvv", "cvc"].contains(&s.as_str())
            && c.security_code.is_empty()
        {
            c.security_code = Zeroizing::new(value.trim().to_string());
        } else if s == "pin" && c.pin.is_empty() {
            c.pin = Zeroizing::new(value.trim().to_string());
        } else {
            continue;
        }
        moved.push(name.to_string());
        values.push(value);
    }
    let mut gone = vec![false; lines.len()];
    gone[0] = true;
    for (from, to, label, value) in labelled(lines) {
        let took = match label.as_str() {
            "cardholder name" | "cardholder" | "name on card" if c.holder.is_empty() => {
                c.holder = value.clone();
                true
            }
            "expiry date" | "expiry" | "expires" | "expiration date" if c.expiry.is_empty() => {
                match expiry(&value) {
                    Ok(x) => {
                        c.expiry = x;
                        true
                    }
                    Err(_) => false,
                }
            }
            "type" if c.brand.is_empty() => match brand(&value) {
                Some(b) => {
                    c.brand = b.to_string();
                    true
                }
                None => false,
            },
            _ => values.iter().any(|v| v.trim() == value.trim()),
        };
        if took {
            gone[from..to].iter_mut().for_each(|g| *g = true);
        }
    }
    let notes = rest_of(lines, &gone);
    Ok(Conversion {
        kind: Kind::Card,
        card: c,
        address: Address::default(),
        notes,
        moved,
    })
}

/// "street / city, state zip / country", as the importer wrote an
/// address, back into its parts. A guess where parts are missing; the note
/// as it was stays in the item's history.
fn address_parts(value: &str, a: &mut Address) {
    let mut ls: Vec<&str> = value
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if let Some(last) = ls.last()
        && ls.len() > 1
        && last.len() == 2
        && last.chars().all(|c| c.is_ascii_alphabetic())
    {
        a.country = country(last);
        ls.pop();
    }
    let split_zip = |rest: &str, a: &mut Address| {
        let words: Vec<&str> = rest.split_whitespace().collect();
        let mut n = words.len();
        while n > 0 && words[n - 1].chars().any(|c| c.is_ascii_digit()) {
            n -= 1;
        }
        a.region = words[..n].join(" ");
        a.postal_code = words[n..].join(" ");
    };
    let city_at = ls.iter().rposition(|l| l.contains(", "));
    let street_end = match city_at {
        Some(i) => {
            let (city, rest) = ls[i].split_once(", ").unwrap_or((ls[i], ""));
            a.city = city.trim().to_string();
            split_zip(rest, a);
            i
        }
        None if ls.len() >= 2 => {
            let last = ls[ls.len() - 1];
            if last.chars().any(|c| c.is_ascii_digit()) {
                split_zip(last, a);
            } else {
                a.city = last.to_string();
            }
            ls.len() - 1
        }
        None => ls.len(),
    };
    let street = &ls[..street_end];
    a.line1 = street.first().copied().unwrap_or("").to_string();
    a.line2 = street.get(1..).unwrap_or(&[]).join(", ");
}

fn as_address(lines: &[&str]) -> Result<Conversion, String> {
    let mut a = Address::default();
    let mut parts: [String; 3] = Default::default();
    let mut found = false;
    let mut gone = vec![false; lines.len()];
    gone[0] = true;
    for (from, to, label, value) in labelled(lines) {
        let slot = match label.as_str() {
            "first name" => &mut parts[0],
            "initial" => &mut parts[1],
            "last name" => &mut parts[2],
            "company" => &mut a.organization,
            "email" | "e-mail" => &mut a.email,
            "default phone" => &mut a.phone,
            "cell" | "home" | "business" if a.phone.is_empty() => &mut a.phone,
            "address" if a.line1.is_empty() && a.city.is_empty() => {
                address_parts(&value, &mut a);
                found = true;
                gone[from..to].iter_mut().for_each(|g| *g = true);
                continue;
            }
            _ => continue,
        };
        if slot.is_empty() {
            *slot = value;
            found = true;
            gone[from..to].iter_mut().for_each(|g| *g = true);
        }
    }
    if !found {
        return Err("Safe found no name or address in it".into());
    }
    a.full_name = parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Conversion {
        kind: Kind::Address,
        card: Card::default(),
        address: a,
        notes: rest_of(lines, &gone),
        moved: Vec::new(),
    })
}

/// A note an earlier 1Password import made from a Credit Card or an
/// Identity: its text starts with the category the importer wrote on its
/// own first line ("Credit card", "Identity"). A card also needs exactly
/// one protected field holding a card number.
fn from_1password(e: &EntryRef<'_>) -> Option<Result<Conversion, String>> {
    if item::kind_of(e) != Kind::Note {
        return None;
    }
    let notes = e.get(fields::NOTES).unwrap_or("");
    let lines: Vec<&str> = notes.lines().collect();
    let first = lines.first()?.trim();
    if first.eq_ignore_ascii_case("credit card") {
        Some(as_card(e, &lines))
    } else if first.eq_ignore_ascii_case("identity") {
        Some(as_address(&lines))
    } else {
        None
    }
}

impl Safe {
    /// Turn the notes an earlier 1Password import made from Credit Cards
    /// and Identities into cards and addresses, in place: same id, title,
    /// tags and folder; the card's number, code and PIN move from their
    /// protected fields into the card's own; the note's lines that became
    /// fields leave its text, the rest stays; every other field stays. The
    /// note as it was goes to the item's history. `dry_run` changes nothing.
    pub fn convert_1password(&mut self, dry_run: bool) -> Result<ConvertReport, Error> {
        let mut found: Vec<(EntryId, String, Conversion)> = Vec::new();
        let mut report = ConvertReport::default();
        for e in self.database().iter_all_entries() {
            if self.in_bin(e.parent().id()) {
                continue;
            }
            let title = e.get(fields::TITLE).unwrap_or("").to_string();
            match from_1password(&e) {
                None => {}
                Some(Ok(c)) => found.push((e.id(), title, c)),
                Some(Err(why)) => report.skipped.push((title, why)),
            }
        }
        report.skipped.sort();
        found.sort_by_key(|(_, t, _)| t.to_lowercase());
        if !dry_run && !found.is_empty() {
            self.writable()?;
        }
        let max = self.history_max();
        for (id, title, c) in found {
            if !dry_run {
                let mut e = self
                    .db_mut()
                    .entry_mut(id)
                    .ok_or_else(|| Error::NotFound(id.to_string()))?;
                let mut d = item::draft_of(&e);
                d.kind = c.kind;
                d.card = c.card.clone();
                d.address = c.address.clone();
                d.notes = c.notes.clone();
                e.edit_tracking(|t| {
                    item::apply(t, &d);
                    for name in &c.moved {
                        t.fields.remove(name);
                    }
                    t.times.last_modification = Some(keepass::db::Times::now());
                });
                crate::safe::settle_history(&mut e, max);
            }
            report.converted.push(Converted {
                id: id.to_string(),
                title,
                kind: c.kind,
            });
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_keep_digits_and_refuse_letters() {
        assert_eq!(
            number("4242 4242-4242.4242").unwrap().as_str(),
            "4242424242424242"
        );
        assert_eq!(number("").unwrap().as_str(), "");
        assert!(number("4242 x").is_err());
    }

    #[test]
    fn luhn_and_the_warning() {
        assert!(luhn("4242424242424242"));
        assert!(luhn("378282246310005"));
        assert!(!luhn("4242424242424241"));
        assert_eq!(check("4242424242424242"), None);
        assert!(check("4242424242424241").unwrap().contains("card check"));
        assert!(check("4242").unwrap().contains("12 to 19"));
        assert_eq!(check(""), None);
    }

    #[test]
    fn brands_from_the_first_digits() {
        for (n, b) in [
            ("4242424242424242", "visa"),
            ("5555555555554444", "mastercard"),
            ("2223003122003222", "mastercard"),
            ("378282246310005", "amex"),
            ("6011111111111117", "discover"),
            ("6445644564456445", "discover"),
            ("3566002020360505", "jcb"),
            ("6200000000000005", "unionpay"),
            ("30569309025904", "diners"),
            ("36227206271667", "diners"),
            ("6759649826438453", "maestro"),
            ("2200123412341234", "mir"),
            ("9999999999999995", "other"),
            ("", "other"),
        ] {
            assert_eq!(brand_of(n), b, "{n}");
        }
    }

    #[test]
    fn brand_names_people_write() {
        assert_eq!(brand("MC"), Some("mastercard"));
        assert_eq!(brand("American Express"), Some("amex"));
        assert_eq!(brand("diners-club"), Some("diners"));
        assert_eq!(brand("carteblanche"), Some("diners"));
        assert_eq!(brand("laser"), None);
        assert_eq!(brand(""), None);
        for b in BRANDS {
            assert_eq!(brand(b), Some(*b));
        }
    }

    #[test]
    fn expiry_forms() {
        for (t, want) in [
            ("08/29", "08/2029"),
            ("8/29", "08/2029"),
            ("08/2029", "08/2029"),
            ("08-2029", "08/2029"),
            ("0829", "08/2029"),
            ("082029", "08/2029"),
            ("202908", "08/2029"),
            ("2029-08", "08/2029"),
            (" 12 / 30 ", "12/2030"),
            ("", ""),
        ] {
            assert_eq!(expiry(t).unwrap(), want, "{t}");
        }
        for t in ["13/29", "00/29", "08/2", "aug 29", "08/29/1", "1/2/3"] {
            assert!(expiry(t).is_err(), "{t}");
        }
        assert_eq!(expiry_parts("08/2029"), Some(("08".into(), "2029".into())));
        assert_eq!(expiry_parts(""), None);
    }

    #[test]
    fn last4_and_titles() {
        assert_eq!(last4("4242424242424242"), "4242");
        assert_eq!(last4("123456789"), "", "too short to show any of it");
        assert_eq!(card_title("visa", "4242424242424242"), "Visa •• 4242");
        assert_eq!(card_title("other", ""), "Card");
    }

    #[test]
    fn names_and_countries() {
        assert_eq!(split_name("Sam Moe"), ("Sam".into(), "Moe".into()));
        assert_eq!(
            split_name(" Mary Ann  Moe "),
            ("Mary Ann".into(), "Moe".into())
        );
        assert_eq!(split_name("Sam"), ("Sam".into(), "".into()));
        assert_eq!(country("ge"), "GE");
        assert_eq!(country(" Georgia "), "Georgia");
    }
}
