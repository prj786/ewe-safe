//! Cards and addresses (docs/SYSTEM.md §4, docs/FORMAT.md "Cards and
//! addresses"): through a verified write and a read back, a merge of a card
//! edited on two machines, `convert` of the notes an earlier 1Password
//! import made, and — when `keepassxc-cli` is there (`SAFE_KEEPASSXC_CLI`,
//! else the PATH) — KeePassXC showing a card's fields.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chrono::{NaiveDate, NaiveDateTime};
use keepass::config::KdfConfig;
use keepass::db::{EntryId, fields};
use keepass::{Database, DatabaseKey};
use safe_core::card::{Address, Card};
use safe_core::import::{Batch, Field as ImportField, Imported, Options};
use safe_core::merge::merge;
use safe_core::safe::key;
use safe_core::{Draft, Field, Kind, Safe};
use zeroize::Zeroizing;

fn cheap() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

fn pw() -> DatabaseKey {
    key("correct horse", None).expect("key")
}

fn t(hour: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 1, 1)
        .and_then(|d| d.and_hms_opt(hour, 0, 0))
        .expect("time")
}

fn visa() -> Draft {
    Draft {
        kind: Kind::Card,
        title: "Visa •• 4242".into(),
        notes: Zeroizing::new("for travel".into()),
        tags: vec!["money".into()],
        card: Card {
            holder: "Sam Moe".into(),
            number: Zeroizing::new("4242424242424242".into()),
            expiry: "08/2029".into(),
            security_code: Zeroizing::new("123".into()),
            pin: Zeroizing::new("9876".into()),
            brand: String::new(),
        },
        ..Draft::default()
    }
}

fn home() -> Draft {
    let mut a = Address::default();
    for (k, v) in [
        ("full_name", "Sam Moe"),
        ("organization", "Flock Ltd"),
        ("line1", "12 Main St"),
        ("line2", "Flat 3"),
        ("city", "Tbilisi"),
        ("region", "Tbilisi"),
        ("postal_code", "0105"),
        ("country", "ge"),
        ("phone", "+995 555 00 00 00"),
        ("email", "sam@example.org"),
    ] {
        a.set(k, v);
    }
    Draft {
        kind: Kind::Address,
        title: "Home".into(),
        address: a,
        ..Draft::default()
    }
}

fn reveal(s: &Safe, id: &str, field: &str) -> String {
    s.reveal(id, &Field::parse(field))
        .unwrap_or_else(|e| panic!("{field}: {e}"))
        .to_string()
}

#[test]
fn a_card_and_an_address_survive_a_verified_write() {
    let mut s = Safe::create("x", cheap());
    let card = s.add(&visa()).expect("add card");
    let addr = s.add(&home()).expect("add address");
    let bytes = s.to_bytes(&pw()).expect("verified write");
    let back = Safe::open(&bytes, &pw()).expect("open");

    let sum = back.summary(&card).expect("summary");
    assert_eq!(sum.kind, Kind::Card);
    let info = sum.card.clone().expect("card info");
    assert_eq!(
        (
            info.brand.as_str(),
            info.last4.as_str(),
            info.expiry.as_str()
        ),
        ("visa", "4242", "08/2029")
    );
    assert_eq!(sum.tags, ["money"]);
    // the protocol's names and the KDBX names
    assert_eq!(reveal(&back, &card, "number"), "4242424242424242");
    assert_eq!(reveal(&back, &card, "Number"), "4242424242424242");
    assert_eq!(reveal(&back, &card, "security_code"), "123");
    assert_eq!(reveal(&back, &card, "Security code"), "123");
    assert_eq!(reveal(&back, &card, "pin"), "9876");
    assert_eq!(reveal(&back, &card, "notes"), "for travel");
    let e = back
        .database()
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Visa •• 4242"))
        .expect("entry");
    for (k, protected) in [
        ("Number", true),
        ("Security code", true),
        ("PIN", true),
        ("Notes", true),
        ("Cardholder", false),
        ("Expiry", false),
        ("Brand", false),
    ] {
        assert_eq!(
            e.fields[k].is_protected(),
            protected,
            "{k} after a read back"
        );
    }

    let a = back.summary(&addr).expect("address");
    assert_eq!(a.kind, Kind::Address);
    assert_eq!(a.address.clone().expect("info").country, "GE");
    assert_eq!(reveal(&back, &addr, "line2"), "Flat 3");
    assert_eq!(reveal(&back, &addr, "Postal code"), "0105");
    assert_eq!(back.draft(&addr).unwrap().address, home().address);

    // a list shows neither the number, nor the code, nor the PIN
    let shown = format!("{:?}", back.items());
    for secret in ["4242424242424242", "\"123\"", "9876", "for travel"] {
        assert!(!shown.contains(secret), "a list shows {secret}");
    }
    // nor does a search find a card by them
    assert!(back.search("4242424242424242").is_empty());
    assert_eq!(back.search("visa").len(), 1);
    assert_eq!(back.search("tbilisi").len(), 1);
}

#[test]
fn a_card_edited_on_two_machines_keeps_both_versions() {
    let mut s = Safe::create("x", cheap());
    let id = s.add(&visa()).expect("add");
    let bytes = s.to_bytes(&pw()).expect("write");
    let (mut here, mut there) = (
        Safe::open(&bytes, &pw()).unwrap(),
        Safe::open(&bytes, &pw()).unwrap(),
    );
    // here: a new security code; there, later: a new card number
    let mut d = here.draft(&id).unwrap();
    d.card.security_code = Zeroizing::new("999".into());
    here.update(&id, &d).unwrap();
    let mut d = there.draft(&id).unwrap();
    d.card.number = Zeroizing::new("5555 5555 5555 4444".into());
    d.card.brand = String::new();
    there.update(&id, &d).unwrap();
    let eid = EntryId::from(uuid::Uuid::parse_str(&id).unwrap());
    let timed = |s: &Safe, hour: u32| -> Database {
        let mut db = s.database().clone();
        db.entry_mut(eid).unwrap().times.last_modification = Some(t(hour));
        db
    };
    let (a, b) = (timed(&here, 10), timed(&there, 11));

    let mut results = Vec::new();
    for (ours, theirs) in [(&a, &b), (&b, &a)] {
        let (mut m, _) = merge(ours, theirs).expect("merge");
        m.config.kdf_config = cheap();
        let mut out = Vec::new();
        m.save(&mut out, pw()).expect("save");
        let back = Safe::open(&out, &pw()).expect("open the merged safe");
        let info = back.summary(&id).unwrap().card.expect("still a card");
        assert_eq!(
            (info.last4.as_str(), info.brand.as_str()),
            ("4444", "mastercard")
        );
        assert_eq!(
            reveal(&back, &id, "security_code"),
            "123",
            "the newer version wins"
        );
        let e = back.database().entry(eid).unwrap();
        assert!(e.fields["Number"].is_protected());
        let codes: Vec<&str> = e
            .history
            .as_ref()
            .expect("history")
            .get_entries()
            .iter()
            .filter_map(|h| h.get("Security code"))
            .collect();
        assert!(
            codes.contains(&"999"),
            "the other machine's edit is in history"
        );
        results.push(format!("{:?}", back.items()));
    }
    assert_eq!(results[0], results[1], "both ways give the same safe");
}

/// The notes 0.2's importer made from a 1Password Credit Card and Identity:
/// the category on the first line, every field listed, the secret ones also
/// protected custom fields (docs/IMPORT.md before cards existed).
fn imported_notes() -> Batch {
    let note = |title: &str, text: &str, fields: Vec<(&str, &str)>| Imported {
        folder: "Personal".into(),
        draft: Draft {
            kind: Kind::Note,
            title: title.into(),
            notes: Zeroizing::new(text.into()),
            tags: vec!["Favorite".into()],
            ..Draft::default()
        },
        fields: fields
            .into_iter()
            .map(|(n, v)| ImportField {
                name: n.into(),
                value: Zeroizing::new(v.into()),
                protected: true,
            })
            .collect(),
        history: Vec::new(),
        files: Vec::new(),
        created: None,
        modified: None,
        ssh: None,
    };
    Batch {
        items: vec![
            note(
                "Visa",
                "Credit card\ncardholder name: Sam Shepherd\ntype: visa\nnumber: 4111111111111111\nverification number: 123\nexpiry date: 2027-04\n\nContact Information\nissuing bank: Ewe Bank\nphone (local): +64 21 000 000\n\nAdditional Details\nPIN: 9876\n\nDaily card",
                vec![
                    ("number", "4111111111111111"),
                    ("verification number", "123"),
                    ("Additional Details: PIN", "9876"),
                ],
            ),
            note(
                "Sam Shepherd",
                "Identity\nIdentification\nfirst name: Sam\nlast name: Shepherd\nbirth date: 1990-01-01\n\nAddress\naddress:\n  1 Hill Rd\n  Ewetown, Canterbury 9012\n  nz\ndefault phone: +64 21 000 001\n\nInternet Details\nemail: sam@example.org",
                vec![],
            ),
            note("Gift card", "Credit card\nshop: Wool & Co", vec![]),
            note("Wi-Fi", "SSID: Flock\nPassword: baa-baa-77", vec![]),
        ],
        skipped: Vec::new(),
    }
}

#[test]
fn convert_turns_imported_notes_into_cards_and_addresses() {
    let mut s = Safe::create("x", cheap());
    s.import(&imported_notes(), &Options::default())
        .expect("import");
    let id_of =
        |s: &Safe, title: &str| s.items().into_iter().find(|i| i.title == title).unwrap().id;
    let visa = id_of(&s, "Visa");

    // a dry run says what, and changes nothing
    let before = format!("{:?}", s.items());
    let dry = s.convert_1password(true).expect("dry run");
    assert_eq!(format!("{:?}", s.items()), before);
    let kinds: Vec<(&str, Kind)> = dry
        .converted
        .iter()
        .map(|c| (c.title.as_str(), c.kind))
        .collect();
    assert_eq!(
        kinds,
        [("Sam Shepherd", Kind::Address), ("Visa", Kind::Card)]
    );
    assert_eq!(
        dry.skipped,
        [(
            "Gift card".to_string(),
            "Safe found no card number in it".to_string()
        )]
    );

    let r = s.convert_1password(false).expect("convert");
    assert_eq!(r.converted.len(), 2);
    let bytes = s.to_bytes(&pw()).expect("verified write");
    let back = Safe::open(&bytes, &pw()).expect("open");

    // the card: same id, title, folder and tags
    let sum = back.summary(&visa).expect("same id");
    assert_eq!(sum.kind, Kind::Card);
    assert_eq!(
        (sum.folder.as_str(), sum.tags.clone()),
        ("Personal", vec!["Favorite".to_string()])
    );
    let d = back.draft(&visa).unwrap();
    assert_eq!(d.card.holder, "Sam Shepherd");
    assert_eq!(d.card.number.as_str(), "4111111111111111");
    assert_eq!(d.card.security_code.as_str(), "123");
    assert_eq!(d.card.pin.as_str(), "9876");
    assert_eq!(d.card.expiry, "04/2027");
    assert_eq!(d.card.brand, "visa");
    assert_eq!(
        d.notes.as_str(),
        "Contact Information\nissuing bank: Ewe Bank\nphone (local): +64 21 000 000\n\nDaily card",
        "what became fields left the text; the rest stays"
    );
    let e = back
        .database()
        .entry(EntryId::from(uuid::Uuid::parse_str(&visa).unwrap()))
        .unwrap();
    for gone in ["number", "verification number", "Additional Details: PIN"] {
        assert!(e.get(gone).is_none(), "{gone} moved into the card");
    }
    let old = &e.history.as_ref().expect("history").get_entries()[0];
    assert!(
        old.get(fields::NOTES).unwrap().starts_with("Credit card\n"),
        "the note as it was is in history"
    );
    assert_eq!(old.get("number"), Some("4111111111111111"));

    // the address
    let sam = id_of(&back, "Sam Shepherd");
    let a = back.draft(&sam).unwrap().address;
    assert_eq!(a.full_name, "Sam Shepherd");
    assert_eq!(
        (a.line1.as_str(), a.city.as_str()),
        ("1 Hill Rd", "Ewetown")
    );
    assert_eq!(
        (a.region.as_str(), a.postal_code.as_str()),
        ("Canterbury", "9012")
    );
    assert_eq!(a.country, "NZ");
    assert_eq!(a.phone, "+64 21 000 001");
    assert_eq!(a.email, "sam@example.org");
    assert_eq!(
        back.draft(&sam).unwrap().notes.as_str(),
        "Identification\nbirth date: 1990-01-01"
    );

    // the rest stays as it was; a second run finds nothing
    assert_eq!(
        back.summary(&id_of(&back, "Wi-Fi")).unwrap().kind,
        Kind::Note
    );
    assert_eq!(
        back.summary(&id_of(&back, "Gift card")).unwrap().kind,
        Kind::Note
    );
    let mut again = back.clone();
    assert!(again.convert_1password(false).unwrap().converted.is_empty());
}

fn which(cmd: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(cmd))
            .find(|f| f.is_file())
    })
}

fn kpxc(cli: &Path, file: &Path, entry: &str) -> String {
    let mut child = Command::new(cli)
        .args(["show", "-q", "-s", "--all"])
        .arg(file)
        .arg(entry)
        .env("QT_QPA_PLATFORM", "offscreen")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"correct horse\n")
        .expect("password");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "keepassxc-cli: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn keepassxc_shows_a_cards_fields() {
    let Some(cli) = std::env::var_os("SAFE_KEEPASSXC_CLI")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| which("keepassxc-cli"))
    else {
        eprintln!("keepassxc-cli isn't installed (SAFE_KEEPASSXC_CLI): skipped");
        return;
    };
    let dir = std::env::temp_dir().join(format!("safe-cards-kpxc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("safe.kdbx");
    let mut s = Safe::create("x", cheap());
    s.add(&visa()).expect("add");
    s.add(&home()).expect("add");
    s.write_file(&file, &pw()).expect("write");
    let shown = kpxc(&cli, &file, "Visa •• 4242");
    for line in [
        "Cardholder: Sam Moe",
        "Number: 4242424242424242",
        "Expiry: 08/2029",
        "Security code: 123",
        "PIN: 9876",
        "Brand: visa",
    ] {
        assert!(shown.contains(line), "KeePassXC shows {line:?}:\n{shown}");
    }
    let shown = kpxc(&cli, &file, "Home");
    for line in ["Address line 1: 12 Main St", "City: Tbilisi", "Country: GE"] {
        assert!(shown.contains(line), "KeePassXC shows {line:?}:\n{shown}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
