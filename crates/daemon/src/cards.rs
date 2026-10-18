//! Cards and addresses over the socket (docs/SYSTEM.md §4, PROTOCOL.md):
//! the `card` and `address` objects `add` and `edit` take, the browser's
//! `fields` behind the card gate, and `convert`. Nothing here logs a value,
//! a title or a name.
//!
//! **The gate** (`[safe] confirm_cards`, on by default): a card's `fields`
//! needs a password typed in the last 5 minutes (`confirm`, stream L's
//! verb; `Session::confirm`), else `confirm-needed`. Like `ssh_confirm` it
//! cuts down on surprises; it is not a security boundary against a program
//! running as the user while Safe is unlocked.

use std::sync::Arc;

use safe_core::card::{self, Address, AddressInfo, Card, CardInfo};
use safe_core::{Draft, Kind};
use serde_json::{Map, Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::daemon::{Daemon, Fail, rd};
use crate::log;

type Args = Map<String, Value>;

pub const CONFIRM_NEEDED: &str = "confirm-needed";

/// The summary's `card` object: never the number, the code or the PIN.
pub fn card_json(c: &CardInfo) -> Value {
    json!({
        "brand": c.brand,
        "last4": c.last4,
        "expiry": c.expiry,
        "holder": c.holder,
        "has_number": c.has_number,
        "has_security_code": c.has_security_code,
        "has_pin": c.has_pin,
    })
}

/// The summary's `address` object.
pub fn address_json(a: &AddressInfo) -> Value {
    json!({"name": a.name, "line1": a.line1, "city": a.city, "country": a.country})
}

/// `show`'s `address`: the summary's object with every part.
pub fn full_address_json(info: &AddressInfo, a: &Address) -> Value {
    let mut v = address_json(info);
    for (k, _) in card::ADDRESS_FIELDS {
        v[*k] = json!(a.get(k).unwrap_or(""));
    }
    v
}

/// Every string left in a value, wiped (what a request held that wasn't
/// taken).
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => m.values_mut().for_each(wipe),
        _ => {}
    }
}

/// What a request's `card` object says. `None` = not sent (an edit leaves
/// it as it is); `""` clears.
#[derive(Default)]
pub struct CardArgs {
    holder: Option<String>,
    number: Option<Zeroizing<String>>,
    expiry: Option<String>,
    security_code: Option<Zeroizing<String>>,
    pin: Option<Zeroizing<String>>,
    brand: Option<String>,
}

/// `card` out of the request: its secrets move into wiped buffers first,
/// whatever comes next.
pub fn take_card(a: &mut Args) -> Result<Option<CardArgs>, Fail> {
    let mut m = match a.remove("card") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(m)) => m,
        Some(mut other) => {
            wipe(&mut other);
            return Err(Fail::bad(
                "card is an object: holder, number, expiry, security_code, pin, brand",
            ));
        }
    };
    let mut secret = |k: &str| match m.remove(k) {
        Some(Value::String(s)) => Some(Zeroizing::new(s)),
        Some(mut other) => {
            wipe(&mut other);
            None
        }
        None => None,
    };
    let (number, security_code, pin) = (secret("number"), secret("security_code"), secret("pin"));
    let text = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
    let out = CardArgs {
        holder: text("holder"),
        number,
        expiry: text("expiry"),
        security_code,
        pin,
        brand: text("brand"),
    };
    wipe(&mut Value::Object(m));
    Ok(Some(out))
}

/// `address` out of the request: (protocol name, value) for each part sent.
pub fn take_address(a: &mut Args) -> Result<Option<Vec<(String, String)>>, Fail> {
    match a.remove("address") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(Some(
            m.into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .filter(|(k, _)| card::ADDRESS_FIELDS.iter().any(|(p, _)| p == k))
                .collect(),
        )),
        Some(_) => Err(Fail::bad(
            "address is an object: full_name, organization, line1, line2, city, region, postal_code, country, phone, email",
        )),
    }
}

/// A `card` only on a card, an `address` only on an address.
pub fn check_kind(kind: Kind, card: bool, address: bool) -> Result<(), Fail> {
    if card && kind != Kind::Card {
        return Err(Fail::bad(
            "This item isn't a card: send card only for a card.",
        ));
    }
    if address && kind != Kind::Address {
        return Err(Fail::bad(
            "This item isn't an address: send address only for an address.",
        ));
    }
    Ok(())
}

impl CardArgs {
    /// Into `c` (a new card, or the one being edited): what was sent
    /// changes, `""` clears. A new number without a brand takes its brand
    /// from the number. Answers (changed, a warning for a mistyped number).
    pub fn apply(self, c: &mut Card) -> Result<(bool, Option<String>), Fail> {
        let before = c.clone();
        if let Some(h) = self.holder {
            c.holder = h.trim().to_string();
        }
        let mut warning = None;
        if let Some(n) = &self.number {
            let digits = card::number(n).map_err(|e| Fail::bad(e.0))?;
            if *digits != *c.number && self.brand.is_none() {
                c.brand = String::new();
            }
            warning = card::check(&digits);
            c.number = digits;
        }
        if let Some(e) = self.expiry {
            c.expiry = card::expiry(&e).map_err(|e| Fail::bad(e.0))?;
        }
        if let Some(s) = self.security_code {
            c.security_code = Zeroizing::new(s.trim().to_string());
        }
        if let Some(p) = self.pin {
            c.pin = Zeroizing::new(p.trim().to_string());
        }
        if let Some(b) = self.brand {
            c.brand = if b.trim().is_empty() {
                String::new()
            } else {
                card::brand(&b)
                    .ok_or_else(|| Fail::bad(format!("--brand is {}", card::BRANDS.join(", "))))?
                    .to_string()
            };
        }
        Ok((before != *c, warning))
    }
}

/// The parts sent, into `a`; answers whether anything changed.
pub fn apply_address(parts: Vec<(String, String)>, a: &mut Address) -> bool {
    let before = a.clone();
    for (k, v) in parts {
        a.set(&k, &v);
    }
    before != *a
}

/// The brand a card has (or will have once saved).
fn brand_id(c: &Card) -> &'static str {
    card::brand(&c.brand).unwrap_or_else(|| card::brand_of(&c.number))
}

/// A new card's or address's draft from the request; the title defaults
/// to "Visa •• 4242" or "Home". Answers a warning for a mistyped number.
pub fn fill_new(
    draft: &mut Draft,
    card_args: Option<CardArgs>,
    address: Option<Vec<(String, String)>>,
) -> Result<Option<String>, Fail> {
    let mut warning = None;
    if let Some(c) = card_args {
        warning = c.apply(&mut draft.card)?.1;
    }
    if let Some(parts) = address {
        apply_address(parts, &mut draft.address);
    }
    if draft.title.is_empty() {
        draft.title = match draft.kind {
            Kind::Card => card::card_title(brand_id(&draft.card), &draft.card.number),
            _ => card::ADDRESS_TITLE.to_string(),
        };
    }
    Ok(warning)
}

/// An edit's `card` or `address` onto the item's draft. A card still
/// titled as Safe titles a new one ("Visa •• 4242") follows its new number
/// unless a title is sent. Answers (changed, warning).
pub fn patch(
    draft: &mut Draft,
    card_args: Option<CardArgs>,
    address: Option<Vec<(String, String)>>,
    title_sent: bool,
) -> Result<(bool, Option<String>), Fail> {
    check_kind(draft.kind, card_args.is_some(), address.is_some())?;
    let mut changed = false;
    let mut warning = None;
    if let Some(c) = card_args {
        let was = card::card_title(brand_id(&draft.card), &draft.card.number);
        let (ch, w) = c.apply(&mut draft.card)?;
        if ch && !title_sent && draft.title == was {
            draft.title = card::card_title(brand_id(&draft.card), &draft.card.number);
        }
        changed |= ch;
        warning = w;
    }
    if let Some(parts) = address {
        changed |= apply_address(parts, &mut draft.address);
    }
    Ok((changed, warning))
}

// ── fields: the browser fills a form ────────────────────────────────────

/// The gate, on its own: a card's fields need a fresh confirm while
/// `confirm_cards` is on.
pub fn gate(confirm_cards: bool, confirmed: bool) -> Result<(), Fail> {
    if confirm_cards && !confirmed {
        return Err(Fail::new(
            CONFIRM_NEEDED,
            "Safe needs your password again before it fills a card.",
        )
        .hint("ewe-safe confirm --ask"));
    }
    Ok(())
}

/// `fields {item_id}`, socket only: what the browser fills from a card
/// (never its PIN) or an address. A card goes through the gate.
pub fn fields(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    let id = a
        .get("item_id")
        .or_else(|| a.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| Fail::bad("Which item? Give its item_id."))?
        .to_string();
    let kind = {
        let snap = rd(&d.snap);
        if !snap.set_up {
            return Err(Fail::not_set_up());
        }
        if snap.locked {
            return Err(Fail::locked());
        }
        // never from the recycle bin
        snap.items
            .iter()
            .find(|i| i.id == id)
            .map(|i| i.kind)
            .ok_or_else(|| Fail::new("not-found", format!("No item {id}.")))?
    };
    match kind {
        Kind::Card => gate(d.settings().confirm_cards, d.session.is_confirmed())?,
        Kind::Address => {}
        _ => return Err(Fail::bad("fields is for cards and addresses.")),
    }
    d.with_held(|h| {
        let e = h
            .safe
            .database()
            .iter_all_entries()
            .find(|e| e.id().to_string() == id)
            .ok_or_else(|| Fail::new("not-found", format!("No item {id}.")))?;
        let fields = if kind == Kind::Card {
            let f = card::card_fill(&e);
            json!({
                "holder": f.holder,
                "number": f.number.as_str(),
                "expiry_month": f.expiry_month,
                "expiry_year": f.expiry_year,
                "security_code": f.security_code.as_str(),
                "brand": f.brand,
            })
        } else {
            let a = card::address_of(&e);
            let (given, family) = card::split_name(&a.full_name);
            let mut v = json!({"given_name": given, "family_name": family});
            for (k, _) in card::ADDRESS_FIELDS {
                v[*k] = json!(a.get(k).unwrap_or(""));
            }
            v
        };
        let mut v = json!({"kind": kind.as_str(), "fields": fields});
        if kind == Kind::Card {
            // how long until a card asks again (0: the gate is off, or the
            // next card needs a confirm)
            v["confirmed_for"] = json!(d.session.confirmed_for());
        }
        Ok(v)
    })
}

// ── convert ─────────────────────────────────────────────────────────────

/// `convert --from-1password [--dry-run]`: the notes an earlier 1Password
/// import made from Credit Cards and Identities become cards and addresses
/// (safe_core::card, `Safe::convert_1password`).
pub fn convert(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    if a.get("from_1password").and_then(Value::as_bool) != Some(true) {
        return Err(Fail::bad(
            "convert needs --from-1password (the only source in this version)",
        ));
    }
    let dry = a.get("dry_run").and_then(Value::as_bool) == Some(true);
    let shown = |r: &card::ConvertReport| {
        let converted: Vec<Value> = r
            .converted
            .iter()
            .map(|c| json!({"item_id": c.id, "title": c.title, "kind": c.kind.as_str()}))
            .collect();
        let skipped: Vec<Value> = r
            .skipped
            .iter()
            .map(|(t, why)| json!({"title": t, "reason": why}))
            .collect();
        json!({"converted": converted, "skipped": skipped})
    };
    if dry {
        // a copy: the dry run changes nothing
        let r = d.with_held(|h| {
            let mut copy = h.safe.clone();
            copy.convert_1password(true).map_err(Fail::from)
        })?;
        let mut v = shown(&r);
        v["dry_run"] = json!(true);
        return Ok(v);
    }
    let (r, sync) = d.mutate(|safe| {
        let r = safe.convert_1password(false)?;
        let changed = !r.converted.is_empty();
        Ok((r, changed))
    })?;
    if !r.converted.is_empty() {
        log(&format!(
            "converted {} imported notes into cards and addresses",
            r.converted.len()
        ));
    }
    let mut v = shown(&r);
    v["sync"] = sync;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use safe_core::Safe;

    fn args(v: Value) -> Args {
        v.as_object().cloned().unwrap()
    }

    /// A daemon holding a safe with a card and an address, nothing on disk.
    fn daemon() -> (Arc<Daemon>, String, String, String) {
        let dir = std::env::temp_dir().join(format!("safed-cards-{}", std::process::id()));
        let d = Arc::new(Daemon::new(Paths {
            state: dir.join("state"),
            runtime: dir.join("run"),
            data: dir.join("data"),
        }));
        let mut safe = Safe::create("x", safe_core::kdf::argon2id(1));
        let mut card = Draft {
            kind: Kind::Card,
            ..Draft::default()
        };
        fill_new(
            &mut card,
            take_card(&mut args(json!({"card": {
                "holder": "Sam Moe", "number": "4242 4242 4242 4242", "expiry": "08/29",
                "security_code": "123", "pin": "9876"
            }})))
            .unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(card.title, "Visa •• 4242");
        let card_id = safe.add(&card).unwrap();
        let mut home = Draft {
            kind: Kind::Address,
            ..Draft::default()
        };
        fill_new(
            &mut home,
            None,
            take_address(&mut args(json!({"address": {
                "full_name": "Sam J Moe", "line1": "12 Main St", "city": "Tbilisi", "country": "ge"
            }})))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(home.title, "Home");
        let home_id = safe.add(&home).unwrap();
        let login = safe
            .add(&Draft {
                title: "Bank".into(),
                ..Draft::default()
            })
            .unwrap();
        d.hold_for_tests(safe, safe_core::safe::key("pw", None).unwrap());
        (d, card_id, home_id, login)
    }

    #[test]
    fn a_card_needs_a_fresh_confirm_and_never_hands_out_its_pin() {
        let (d, card, home, login) = daemon();
        let ask = |id: &str| fields(&d, &args(json!({"item_id": id})));

        // the gate is on by default and nothing was confirmed
        let e = ask(&card).expect_err("confirm-needed");
        assert_eq!(e.code, CONFIRM_NEEDED);
        assert_eq!(e.hint.as_deref(), Some("ewe-safe confirm --ask"));
        assert!(e.message.ends_with('.'));

        // an address needs no confirm
        let a = ask(&home).expect("address");
        assert_eq!(a["fields"]["given_name"], "Sam J");
        assert_eq!(a["fields"]["family_name"], "Moe");
        assert_eq!(a["fields"]["country"], "GE");

        // a password typed just now (stream L's `confirm`)
        d.session.confirm();
        let c = ask(&card).expect("card");
        let f = &c["fields"];
        assert_eq!(f["number"], "4242424242424242");
        assert_eq!(
            (f["expiry_month"].as_str(), f["expiry_year"].as_str()),
            (Some("08"), Some("2029"))
        );
        assert_eq!(f["security_code"], "123");
        assert_eq!(f["brand"], "visa");
        assert!(
            f.get("pin").is_none() && !c.to_string().contains("9876"),
            "never the PIN"
        );
        assert!(c["confirmed_for"].as_u64().unwrap() > 290);

        // the confirm goes with the lock
        d.session.clear_confirm();
        assert_eq!(ask(&card).err().unwrap().code, CONFIRM_NEEDED);

        // a login has no fields to fill; an id is needed
        assert_eq!(ask(&login).err().unwrap().code, "bad-request");
        assert_eq!(
            ask("4f9c0d1e-0000-0000-0000-000000000000")
                .err()
                .unwrap()
                .code,
            "not-found"
        );
        assert_eq!(
            fields(&d, &args(json!({}))).err().unwrap().code,
            "bad-request"
        );
    }

    #[test]
    fn the_gate_off_lets_the_card_through() {
        assert!(gate(false, false).is_ok());
        assert!(gate(true, true).is_ok());
        assert_eq!(gate(true, false).err().unwrap().code, CONFIRM_NEEDED);
    }

    #[test]
    fn edits_change_what_is_sent_and_a_default_title_follows_the_number() {
        let (d, card, _, _) = daemon();
        let mut draft = d.with_held(|h| Ok(h.safe.draft(&card)?)).unwrap();
        let (changed, warning) = patch(
            &mut draft,
            take_card(&mut args(
                json!({"card": {"number": "5555555555554445", "pin": ""}}),
            ))
            .unwrap(),
            None,
            false,
        )
        .unwrap();
        assert!(changed);
        assert!(warning.unwrap().contains("card check"), "a Luhn miss warns");
        assert_eq!(draft.title, "Mastercard •• 4445");
        assert_eq!(draft.card.pin.as_str(), "", "\"\" clears");
        assert_eq!(draft.card.security_code.as_str(), "123", "not sent: kept");
        assert_eq!(draft.card.brand, "", "taken from the new number on save");
        // nothing new: nothing changed
        let (changed, _) = patch(
            &mut draft,
            take_card(&mut args(json!({"card": {"holder": "Sam Moe"}}))).unwrap(),
            None,
            false,
        )
        .unwrap();
        assert!(!changed);
        // the wrong object for the kind, a bad expiry, a brand Safe doesn't know
        assert!(patch(&mut draft, None, Some(vec![]), false).is_err());
        for bad in [
            json!({"expiry": "13/29"}),
            json!({"brand": "laser"}),
            json!({"number": "42x"}),
        ] {
            let c = take_card(&mut args(json!({"card": bad}))).unwrap();
            assert_eq!(
                patch(&mut draft, c, None, false).err().unwrap().code,
                "bad-request"
            );
        }
    }
}
