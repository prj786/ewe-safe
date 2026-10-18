//! Import from 1Password (docs/IMPORT.md) against the synthetic fixtures in
//! tests/import (made by tests/import/make_fixtures.py; no real data).

use keepass::config::KdfConfig;
use keepass::db::fields;
use safe_core::import::{self, Batch, Fetched, Imported, OpFile, Options};
use safe_core::safe::{self, Safe};
use safe_core::{Draft, Field, Kind};
use serde_json::Value;
use zeroize::Zeroizing;

const PUX: &[u8] = include_bytes!("../../../tests/import/fixtures/sample.1pux");
const CSV: &str = include_str!("../../../tests/import/fixtures/1password.csv");
const OP: &str = include_str!("../../../tests/import/fixtures/op.json");

/// Every secret the fixtures hold: none may reach a report.
const SECRETS: &[&str] = &[
    "Disc-pw-Zq9!",
    "old-disc-1",
    "old-disc-2",
    "4242",
    "JBSWY3DPEHPK3PXP",
    "router-pw-55",
    "4111111111111111",
    "baa-baa-77",
    "forum-pw",
    "gone-pw",
    "OPENSSH PRIVATE",
    "gh-pw-X7",
    "bank-pw-1",
    "old-pw",
    "BACKUP-CODES",
];

fn cheap() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

fn find<'a>(b: &'a Batch, title: &str) -> &'a Imported {
    b.items
        .iter()
        .find(|i| i.draft.title == title)
        .unwrap_or_else(|| panic!("no {title}"))
}

fn field<'a>(i: &'a Imported, name: &str) -> Option<&'a str> {
    i.fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.as_str())
}

#[test]
fn a_1pux_export_maps_every_category() {
    let b = import::read_1pux(PUX).expect("read");
    let mut titles: Vec<&str> = b.items.iter().map(|i| i.draft.title.as_str()).collect();
    titles.sort();
    assert_eq!(
        titles,
        [
            "Discord",
            "GitHub",
            "Laptop key",
            "Old forum",
            "Passport scan",
            "Router admin",
            "Sam Shepherd",
            "Visa",
            "Wi-Fi at home"
        ]
    );

    let d = find(&b, "Discord");
    assert_eq!(d.draft.kind, Kind::Login);
    assert_eq!(d.folder, "Personal");
    assert_eq!(d.draft.username, "sam");
    assert_eq!(d.draft.password.as_str(), "Disc-pw-Zq9!");
    assert_eq!(
        d.draft.websites,
        [
            "https://discord.com/login",
            "https://discordapp.com",
            "https://canary.discord.com"
        ]
    );
    assert!(d.draft.otp.starts_with("otpauth://totp/Discord:sam"));
    assert_eq!(d.draft.tags, ["chat", "Favorite"]);
    assert_eq!(d.draft.notes.as_str(), "Discord *main* account");
    let pin = d
        .fields
        .iter()
        .find(|f| f.name == "Security: PIN")
        .expect("pin");
    assert_eq!((pin.value.as_str(), pin.protected), ("4242", true));
    assert_eq!(field(d, "Web form: server"), Some("eu-west"));
    assert!(
        field(d, "Web form: remember").is_none(),
        "checkboxes stay out"
    );
    let history: Vec<&str> = d.history.iter().map(|h| h.value.as_str()).collect();
    assert_eq!(history, ["old-disc-1", "old-disc-2"], "oldest first");
    assert!(d.history[0].time < d.history[1].time);
    assert_eq!(d.files.len(), 1);
    assert_eq!(d.files[0].name, "backup-codes.txt");
    assert_eq!(&d.files[0].data[..], b"BACKUP-CODES 1111 2222\n");
    assert!(d.created < d.modified);

    let r = find(&b, "Router admin");
    assert_eq!(
        (r.draft.kind, r.draft.password.as_str()),
        (Kind::Login, "router-pw-55")
    );

    // a Credit Card is a card: its own fields, the rest custom fields
    let v = find(&b, "Visa");
    assert_eq!(v.draft.kind, Kind::Card);
    let c = &v.draft.card;
    assert_eq!(c.holder, "Sam Shepherd");
    assert_eq!(c.number.as_str(), "4111111111111111");
    assert_eq!(c.security_code.as_str(), "123");
    assert_eq!(c.pin.as_str(), "9876");
    assert_eq!(c.expiry, "04/2027");
    assert_eq!(c.brand, "visa");
    assert_eq!(v.draft.notes.as_str(), "Daily card", "the notes alone");
    assert_eq!(
        field(v, "Contact Information: issuing bank"),
        Some("Ewe Bank")
    );
    assert_eq!(field(v, "valid from"), Some("2023-04"));
    assert_eq!(field(v, "Additional Details: credit limit"), Some("5000"));
    for taken in [
        "number",
        "verification number",
        "Additional Details: PIN",
        "type",
    ] {
        assert!(field(v, taken).is_none(), "{taken} is the card's own");
    }

    // an Identity is an address
    let id = find(&b, "Sam Shepherd");
    assert_eq!(id.draft.kind, Kind::Address);
    let a = &id.draft.address;
    assert_eq!(a.full_name, "Sam Shepherd");
    assert_eq!(a.organization, "Flock Ltd");
    assert_eq!((a.line1.as_str(), a.line2.as_str()), ("1 Hill Rd", ""));
    assert_eq!(
        (a.city.as_str(), a.postal_code.as_str()),
        ("Ewetown", "9012")
    );
    assert_eq!(a.country, "NZ");
    assert_eq!(a.phone, "+64 21 000 001");
    assert_eq!(a.email, "sam@example.org");
    assert_eq!(field(id, "Identification: birth date"), Some("1990-01-01"));
    let answer = id
        .fields
        .iter()
        .find(|f| f.name == "Internet Details: reminder answer")
        .expect("kept");
    assert!(answer.protected, "a concealed field stays protected");

    let n = find(&b, "Wi-Fi at home");
    assert_eq!(n.draft.kind, Kind::Note);
    assert_eq!(n.draft.notes.as_str(), "SSID: Flock\nPassword: baa-baa-77");
    assert_eq!(n.draft.tags, ["home"]);

    let p = find(&b, "Passport scan");
    assert_eq!(p.files[0].name, "passport.pdf");
    assert_eq!(
        &p.files[0].data[..],
        b"%PDF-1.4 fake\n",
        "three underscores too"
    );

    assert_eq!(find(&b, "Old forum").folder, "Archive");

    let k = find(&b, "Laptop key");
    assert!(
        field(k, "private key")
            .expect("key")
            .contains("OPENSSH PRIVATE KEY")
    );
    assert!(
        k.fields
            .iter()
            .find(|f| f.name == "private key")
            .unwrap()
            .protected
    );
    assert!(
        k.draft
            .notes
            .contains("private key (public key): ssh-ed25519")
    );

    let g = find(&b, "GitHub");
    assert_eq!(g.folder, "Work");
    assert!(
        g.draft
            .otp
            .starts_with("otpauth://totp/GitHub:sam-work?secret=JBSWY3DPEHPK3PXP"),
        "a bare secret becomes a URI: {}",
        g.draft.otp.as_str()
    );

    let skipped: Vec<(&str, &str)> = b
        .skipped
        .iter()
        .map(|s| (s.title.as_str(), s.reason.as_str()))
        .collect();
    assert!(skipped.contains(&("Thrown away", "it is in 1Password's trash")));
    assert!(
        skipped
            .iter()
            .any(|(t, r)| *t == "GitHub — missing.txt" && r.contains("isn't in the export"))
    );
}

#[test]
fn a_csv_export_maps_logins_and_the_archive() {
    let b = import::read_1password_csv(CSV).expect("read");
    assert_eq!(b.items.len(), 2, "the empty row is no item");
    let bank = find(&b, "Bank");
    assert_eq!(bank.draft.username, "sam");
    assert_eq!(bank.draft.password.as_str(), "bank-pw-1");
    assert_eq!(bank.draft.websites, ["https://bank.example"]);
    assert!(bank.draft.otp.starts_with("otpauth://totp/Bank:sam"));
    assert_eq!(bank.draft.tags, ["money", "work", "Favorite"]);
    assert_eq!(bank.draft.notes.as_str(), "Line 1\nLine 2, with a comma");
    assert_eq!(bank.folder, "");
    assert_eq!(find(&b, "Old site").folder, "Archive");
    assert!(import::read_1password_csv("Name,Value\nx,y\n").is_err());
}

fn op_items() -> Vec<(Value, String)> {
    let fx: Value = serde_json::from_str(OP).expect("fixture");
    fx["items"]
        .as_object()
        .unwrap()
        .values()
        .map(|i| {
            let folder = i["vault"]["name"].as_str().unwrap().to_string();
            (i.clone(), folder)
        })
        .collect()
}

#[test]
fn op_items_map_like_the_export() {
    let fx: Value = serde_json::from_str(OP).expect("fixture");
    let mut asked: Vec<OpFile> = Vec::new();
    let mut fetch = |f: &OpFile| -> Fetched {
        asked.push(f.clone());
        let body = if f.document {
            fx["documents"][&f.item].as_str()
        } else {
            fx["files"][format!("op://{}/{}/{}", f.vault, f.item, f.file)].as_str()
        };
        body.map(|b| Zeroizing::new(b.as_bytes().to_vec()))
            .ok_or_else(|| "no such file".to_string())
    };
    let b = import::read_op(&op_items(), &mut fetch);
    assert_eq!(b.items.len(), 5);
    let d = find(&b, "Discord");
    assert_eq!(d.draft.username, "sam");
    assert_eq!(d.draft.password.as_str(), "Disc-pw-Zq9!");
    assert_eq!(
        d.draft.websites[0], "https://discord.com/login",
        "the primary first"
    );
    assert!(d.draft.otp.starts_with("otpauth://"));
    assert_eq!(field(d, "Security: PIN"), Some("4242"));
    assert_eq!(d.history.len(), 2);
    assert_eq!(&d.files[0].data[..], b"BACKUP-CODES 1111 2222\n");
    assert_eq!(d.draft.tags, ["chat", "Favorite"]);
    assert!(d.modified.is_some());
    let p = find(&b, "Passport");
    assert_eq!(p.files[0].name, "passport.pdf");
    assert_eq!(find(&b, "Old forum").folder, "Archive");
    let v = find(&b, "Visa");
    assert_eq!(v.draft.kind, Kind::Card);
    assert_eq!(v.draft.card.number.as_str(), "4111111111111111");
    assert_eq!(v.draft.card.expiry, "04/2027");
    assert_eq!(v.draft.card.pin.as_str(), "9876");
    assert_eq!(v.draft.card.brand, "visa");
    assert_eq!(v.folder, "Work");
    let w = find(&b, "Sam at work");
    assert_eq!(w.draft.kind, Kind::Address);
    assert_eq!(w.draft.address.full_name, "Sam Shepherd");
    assert_eq!(w.draft.address.region, "Canterbury");
    assert_eq!(w.draft.address.country, "NZ");
    assert_eq!(w.draft.address.email, "sam@work.example");
    assert!(
        w.fields.is_empty(),
        "every field taken: {:?}",
        w.fields.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    assert!(asked.iter().any(|f| f.document && f.item == "i2"));
    assert!(asked.iter().any(|f| !f.document && f.file == "f1"));
}

fn existing_discord() -> Draft {
    Draft {
        kind: Kind::Login,
        title: "My Discord".into(),
        username: "SAM".into(),
        password: Zeroizing::new("already-here".into()),
        websites: vec!["https://www.discord.com".into()],
        ..Draft::default()
    }
}

#[test]
fn duplicates_are_counted_and_kept_or_skipped() {
    let b = import::read_1pux(PUX).expect("read");
    let mut s = Safe::create("x", cheap());
    s.add(&existing_discord()).expect("add");
    let p = import::plan(&b, &s.items(), &Options::default());
    assert_eq!(p.report.duplicates, 1);
    assert_eq!(p.report.logins, 4, "Discord, Router, Old forum, GitHub");
    assert_eq!(p.report.notes, 3, "Wi-Fi, Passport scan, Laptop key");
    assert_eq!((p.report.cards, p.report.addresses), (1, 1));
    assert_eq!(p.report.otps, 2);
    assert_eq!(p.report.attachments, 2);
    assert_eq!(p.report.folders, ["Archive", "Personal", "Work"]);
    let skip = import::plan(
        &b,
        &s.items(),
        &Options {
            folder: "1Password".into(),
            skip_duplicates: true,
        },
    );
    assert_eq!(skip.report.logins, 3);
    assert!(
        skip.report
            .skipped
            .iter()
            .any(|x| x.title == "Discord" && x.reason.contains("already"))
    );
    assert_eq!(
        skip.report.folders,
        ["1Password/Archive", "1Password/Personal", "1Password/Work"]
    );
    let shown = format!("{:?}", skip.report);
    for secret in SECRETS {
        assert!(!shown.contains(secret), "the report shows {secret}");
    }
}

#[test]
fn an_import_survives_a_verified_save_with_every_field() {
    let b = import::read_1pux(PUX).expect("read");
    let pw = safe::key("correct horse", None).expect("key");
    let mut s = Safe::create("x", cheap());
    let before = s.clone().to_bytes(&pw).expect("write");
    let report = s.import(&b, &Options::default()).expect("import");
    assert_eq!(
        report.logins + report.notes + report.cards + report.addresses,
        9
    );
    let bytes = s.to_bytes(&pw).expect("verified write");
    assert_ne!(before, bytes);
    let back = Safe::open(&bytes, &pw).expect("open");

    let id = |title: &str| {
        back.items()
            .into_iter()
            .find(|i| i.title == title)
            .unwrap_or_else(|| panic!("no {title}"))
    };
    let d = id("Discord");
    assert_eq!(d.folder, "Personal");
    assert_eq!(
        back.reveal(&d.id, &Field::Password).unwrap().as_str(),
        "Disc-pw-Zq9!"
    );
    assert_eq!(
        back.reveal(&d.id, &Field::Other("Security: PIN".into()))
            .unwrap()
            .as_str(),
        "4242"
    );
    assert_eq!(back.reveal(&d.id, &Field::OtpCode).unwrap().len(), 6);
    assert_eq!(id("Old forum").folder, "Archive");
    assert_eq!(id("GitHub").folder, "Work");
    let visa = id("Visa");
    assert_eq!(visa.kind, Kind::Card);
    let info = visa.card.clone().expect("card");
    assert_eq!(
        (info.last4.as_str(), info.expiry.as_str()),
        ("1111", "04/2027")
    );
    assert_eq!(
        back.reveal(&visa.id, &Field::Other("number".into()))
            .unwrap()
            .as_str(),
        "4111111111111111"
    );
    assert_eq!(id("Sam Shepherd").address.expect("address").city, "Ewetown");

    let db = back.database();
    let entry = db
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Discord"))
        .expect("entry");
    let hist: Vec<&str> = entry
        .history
        .as_ref()
        .expect("history")
        .get_entries()
        .iter()
        .filter_map(|h| h.get(fields::PASSWORD))
        .collect();
    assert_eq!(
        hist,
        ["old-disc-1", "old-disc-2"],
        "oldest first in the file"
    );
    let names: Vec<String> = entry
        .attachments_named()
        .map(|(n, _)| n.to_string())
        .collect();
    assert_eq!(names, ["backup-codes.txt"]);
    assert!(entry.fields["Security: PIN"].is_protected());
    assert_eq!(
        entry.times.creation.map(|t| t.and_utc().timestamp()),
        Some(1_500_000_000),
        "1Password's own times"
    );
}

#[test]
fn a_broken_export_is_an_error_not_a_panic() {
    assert!(import::read_1pux(b"not a zip").is_err());
    assert!(import::read_1password_csv("").is_err());
    // a zip without export.data
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file("readme.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut z, b"hi").unwrap();
        z.finish().unwrap();
    }
    let e = import::read_1pux(buf.get_ref()).err().expect("an error");
    assert!(e.0.contains("export.data"));
}
