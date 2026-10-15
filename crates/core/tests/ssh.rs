//! SSH keys in the safe (docs/FORMAT.md, "SSH keys"): stored the way
//! KeePassXC stores them, entries KeePassXC made read as SSH keys, the
//! notes an earlier 1Password import made turned into SSH keys without
//! loss, and the importer making SSH keys from now on. The keys are made
//! here, when the tests run.

use std::io::Write as _;

use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use keepass::config::KdfConfig;
use keepass::db::{EntryId, Value, fields};
use safe_core::import::{self, OpFile, Options};
use safe_core::safe::{self, Safe};
use safe_core::search;
use safe_core::ssh::{self, KeeAgent};
use safe_core::{Draft, Field, Kind};
use serde_json::{Value as Json, json};
use zeroize::Zeroizing;

fn cheap() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

fn pw() -> keepass::DatabaseKey {
    safe::key("correct horse", None).expect("key")
}

fn round_trip(s: &mut Safe) -> Safe {
    Safe::open(&s.to_bytes(&pw()).expect("write"), &pw()).expect("open")
}

fn eid(id: &str) -> EntryId {
    EntryId::from(uuid::Uuid::parse_str(id).expect("uuid"))
}

/// 1Password's form of a key: PKCS#8 PEM.
fn pkcs8(seed: u8) -> (String, ssh::KeyFile) {
    let k = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let pem = k
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("pem")
        .to_string();
    let kf = ssh::read_key(pem.as_bytes(), "").expect("read");
    (pem, kf)
}

fn verify(public_line: &str, data: &[u8], sig: &[u8]) {
    use ssh_key::encoding::Decode as _;
    let public = ssh_key::PublicKey::from_openssh(public_line).expect("public");
    let sig = ssh_key::Signature::decode(&mut &sig[..]).expect("decode");
    signature::Verifier::verify(&public, data, &sig).expect("verifies");
}

#[test]
fn a_new_key_is_a_keeagent_entry() {
    let mut s = Safe::create("x", cheap());
    s.add(&Draft {
        kind: Kind::Login,
        title: "GitHub".into(),
        username: "sam".into(),
        password: Zeroizing::new("pw".into()),
        websites: vec!["https://github.com".into()],
        ..Draft::default()
    })
    .expect("login");
    let kf = ssh::generate("ed25519", None, "GitHub key").expect("key");
    let id = s
        .add_ssh_key(&kf, "GitHub key", "", "Keys")
        .expect("add key");
    let back = round_trip(&mut s);

    let sum = back.summary(&id).expect("summary");
    assert_eq!(sum.kind, Kind::SshKey);
    assert_eq!(sum.folder, "Keys");
    let info = sum.ssh.expect("ssh");
    assert_eq!(info.public_key, kf.public_key);
    assert_eq!(info.fingerprint, kf.fingerprint);
    assert_eq!(info.key_type, "ed25519");
    assert!(info.agent);
    assert!(!sum.has_password, "no passphrase");

    // the entry, as KeePassXC reads it
    let e = back.database().entry(eid(&id)).expect("entry");
    let key = e.attachment_by_name("id_ed25519").expect("the key");
    assert_eq!(key.data.get().as_slice(), kf.openssh.as_bytes());
    let settings = e.attachment_by_name(ssh::SETTINGS).expect("settings");
    assert_eq!(
        settings.data.get().as_slice(),
        KeeAgent::for_attachment("id_ed25519").to_xml().as_slice()
    );
    assert!(!e.fields[ssh::PUBLIC_KEY].is_protected());
    assert!(!e.fields[ssh::FINGERPRINT].is_protected());

    // the private key is a value like any other, for `reveal`
    let shown = back
        .reveal(&id, &Field::Other(ssh::PRIVATE_KEY.into()))
        .expect("reveal");
    assert_eq!(shown.as_str(), kf.openssh.as_str());
    let (text, pass) = back.ssh_private(&id).expect("private");
    let data = b"to sign";
    verify(
        &kf.public_key,
        data,
        &ssh::sign(&text, &pass, data, 0).expect("sign"),
    );

    // `match` answers logins only; a list knows the kind
    let items = back.items();
    assert_eq!(search::match_logins(&items, "", "", "", "").len(), 1);
    assert_eq!(
        search::match_logins(&items, "", "", "", "key").len(),
        0,
        "never an SSH key"
    );
    assert_eq!(
        items
            .iter()
            .filter(|i| i.kind == Kind::SshKey)
            .map(|i| i.title.as_str())
            .collect::<Vec<_>>(),
        ["GitHub key"]
    );

    // an edit keeps the key and the kind
    let mut edited = back.clone();
    let mut d = edited.draft(&id).expect("draft");
    assert_eq!(d.kind, Kind::SshKey);
    d.title = "GitHub (work)".into();
    edited.update(&id, &d).expect("update");
    let again = round_trip(&mut edited);
    let sum = again.summary(&id).expect("summary");
    assert_eq!(
        (sum.kind, sum.title.as_str()),
        (Kind::SshKey, "GitHub (work)")
    );
    assert!(again.ssh_private(&id).is_ok());
}

#[test]
fn an_entry_keepassxc_made_is_an_ssh_key_too() {
    use ssh_key::getrandom::SysRng;
    // KeePassXC's way: a login entry, the key file as an attachment with
    // its passphrase in the password, no fields of Safe's, no marker
    let kf = ssh::generate("ecdsa", None, "sam@laptop").expect("key");
    let locked = ssh_key::PrivateKey::from_openssh(kf.openssh.as_str())
        .unwrap()
        .encrypt(&mut SysRng, "open sesame")
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap();
    let mut s = Safe::create("x", cheap());
    let id = s
        .add(&Draft {
            kind: Kind::Login,
            title: "Server".into(),
            username: "sam".into(),
            password: Zeroizing::new("open sesame".into()),
            ..Draft::default()
        })
        .expect("add");
    let mut off = s.clone();
    {
        let mut db = s.database().clone();
        let mut e = db.entry_mut(eid(&id)).expect("entry");
        e.add_attachment("id_ecdsa", Value::protected(locked.as_bytes().to_vec()));
        let mut st = KeeAgent {
            selected_type: "attachment".into(),
            attachment_name: "id_ecdsa".into(),
            add_at_open: true,
            allow_use: true,
            ..KeeAgent::default()
        };
        e.add_attachment(ssh::SETTINGS, Value::unprotected(st.to_xml()));
        s = Safe::open(
            &{
                let mut out = Vec::new();
                db.save(&mut out, pw()).expect("save");
                out
            },
            &pw(),
        )
        .expect("open");

        // the same, with KeePassXC's two switches off
        let mut db2 = off.database().clone();
        let mut e = db2.entry_mut(eid(&id)).expect("entry");
        e.add_attachment("id_ecdsa", Value::protected(locked.as_bytes().to_vec()));
        st.allow_use = false;
        st.add_at_open = false;
        e.add_attachment(ssh::SETTINGS, Value::unprotected(st.to_xml()));
        let mut out = Vec::new();
        db2.save(&mut out, pw()).expect("save");
        off = Safe::open(&out, &pw()).expect("open");
    }

    let sum = s.summary(&id).expect("summary");
    assert_eq!(sum.kind, Kind::SshKey, "known by its KeeAgent.settings");
    let info = sum.ssh.expect("ssh");
    assert_eq!(
        info.fingerprint, kf.fingerprint,
        "read from the key's public part"
    );
    assert_eq!(info.key_type, "ecdsa");
    assert!(info.agent);
    assert!(sum.has_password, "the passphrase");
    let (text, pass) = s.ssh_private(&id).expect("private");
    assert_eq!(pass.as_str(), "open sesame");
    let line = info.public_key.clone();
    let data = b"challenge";
    verify(
        &line,
        data,
        &ssh::sign(&text, &pass, data, 0).expect("sign"),
    );

    let copied = s
        .reveal(&id, &Field::Other(ssh::PUBLIC_KEY.into()))
        .expect("a public key without the field");
    assert_eq!(copied.as_str(), line);

    let info = off.summary(&id).expect("summary").ssh.expect("ssh");
    assert!(!info.agent, "AllowUseOfSshKey off: no agent may use it");
}

/// A note as `import` made one from 1Password's SSH Key category before
/// SSH keys existed: the category line, the field listing, the key also as
/// a protected field.
fn old_import_note(s: &mut Safe, title: &str, key: &str, public: &str) -> String {
    let notes = format!(
        "SSH key\nprivate key:\n{}\nprivate key (public key): {public}\nprivate key (fingerprint): SHA256:x\n\nmy laptop",
        key.lines()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let id = s
        .add_in(
            &Draft {
                kind: Kind::Note,
                title: title.into(),
                tags: vec!["Favorite".into()],
                notes: Zeroizing::new(notes),
                ..Draft::default()
            },
            "Personal",
        )
        .expect("note");
    let mut db = s.database().clone();
    db.entry_mut(eid(&id))
        .expect("entry")
        .set_protected("private key", key);
    let mut out = Vec::new();
    db.save(&mut out, pw()).expect("save");
    *s = Safe::open(&out, &pw()).expect("open");
    id
}

#[test]
fn adopt_turns_1password_notes_into_ssh_keys_without_loss() {
    let mut s = Safe::create("x", cheap());
    let (pem, kf) = pkcs8(3);
    let gh = old_import_note(&mut s, "GitHub key", &pem, &kf.public_key);
    let fake = old_import_note(
        &mut s,
        "Broken key",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
        "ssh-ed25519 AAAA",
    );
    let plain = s
        .add(&Draft {
            kind: Kind::Note,
            title: "Wi-Fi".into(),
            notes: Zeroizing::new("SSH key? no, the router".into()),
            ..Draft::default()
        })
        .expect("note");
    let before = s.draft(&gh).expect("draft");
    let fields_before: Vec<(String, String, bool)> = {
        let e = s.database().entry(eid(&gh)).unwrap();
        let mut v: Vec<_> = e
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.get().to_string(), v.is_protected()))
            .collect();
        v.sort();
        v
    };

    let dry = s.adopt_ssh_keys(true).expect("dry run");
    assert_eq!(dry.adopted.len(), 1);
    assert_eq!(dry.adopted[0].title, "GitHub key");
    assert_eq!(dry.adopted[0].id, gh);
    assert_eq!(dry.skipped.len(), 1);
    assert_eq!(dry.skipped[0].0, "Broken key");
    assert_eq!(
        s.summary(&gh).unwrap().kind,
        Kind::Note,
        "a dry run changes nothing"
    );

    let done = s.adopt_ssh_keys(false).expect("adopt");
    assert_eq!(done.adopted, dry.adopted);
    let mut back = round_trip(&mut s);

    let sum = back.summary(&gh).expect("same id");
    assert_eq!(sum.kind, Kind::SshKey);
    assert_eq!(
        (sum.folder.as_str(), sum.tags.clone()),
        ("Personal", vec!["Favorite".to_string()])
    );
    let info = sum.ssh.expect("ssh");
    assert_eq!(info.fingerprint, kf.fingerprint);
    assert!(info.agent);
    let after = back.draft(&gh).expect("draft");
    assert_eq!(
        after.notes.as_str(),
        before.notes.as_str(),
        "the note text stays"
    );
    assert_eq!(after.title, before.title);
    let e = back.database().entry(eid(&gh)).unwrap();
    for (k, v, protected) in &fields_before {
        if k == fields::NOTES {
            continue;
        }
        assert_eq!(e.get(k), Some(v.as_str()), "{k} kept");
        assert_eq!(e.fields[k].is_protected(), *protected, "{k} protection");
    }
    assert!(e.attachment_by_name("id_ed25519").is_some());
    assert!(e.attachment_by_name(ssh::SETTINGS).is_some());
    let hist = e.history.as_ref().expect("history").get_entries();
    let last = hist.last().expect("the note as it was");
    assert!(last.custom_data.contains_key(safe_core::item::KIND_KEY));
    assert_eq!(safe_core::item::kind_of(last), Kind::Note);

    let (text, pass) = back.ssh_private(&gh).expect("private");
    verify(
        &kf.public_key,
        b"m",
        &ssh::sign(&text, &pass, b"m", 0).unwrap(),
    );

    assert_eq!(back.summary(&fake).unwrap().kind, Kind::Note, "left alone");
    assert_eq!(back.summary(&plain).unwrap().kind, Kind::Note);
    let again = back.adopt_ssh_keys(false).expect("again");
    assert!(again.adopted.is_empty(), "nothing left to adopt");
}

fn op_ssh_item(id: &str, value: &str, openssh: Option<&str>, public: &str) -> Json {
    let mut key =
        json!({"id": "private_key", "type": "SSHKEY", "label": "private key", "value": value});
    if let Some(o) = openssh {
        key["ssh_formats"] = json!({"openssh": {"value": o}});
    }
    json!({
        "id": id, "title": format!("Key {id}"), "category": "SSH_KEY",
        "vault": {"id": "v1", "name": "Personal"},
        "fields": [
            key,
            {"id": "public_key", "type": "STRING", "label": "public key", "value": public},
            {"id": "fingerprint", "type": "STRING", "label": "fingerprint", "value": "SHA256:x"},
            {"id": "key_type", "type": "STRING", "label": "key type", "value": "ed25519"},
            {"id": "host", "type": "STRING", "label": "host", "value": "github.com"},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": "deploy"},
        ],
    })
}

#[test]
fn op_ssh_keys_become_ssh_key_items() {
    let (pem, kf) = pkcs8(5);
    let (_, other) = pkcs8(6);
    let items = vec![
        // PKCS#8, as op prints the value
        (
            op_ssh_item("a", &pem, None, &kf.public_key),
            "Personal".to_string(),
        ),
        // newer op versions also print the OpenSSH form
        (
            op_ssh_item("b", "", Some(&other.openssh), &other.public_key),
            "Personal".to_string(),
        ),
        // a value Safe can't read: op's own OpenSSH form is asked for
        (
            op_ssh_item("c", "garbage", None, &other.public_key),
            "Personal".to_string(),
        ),
        // nothing readable at all: the Note it always was
        (
            op_ssh_item(
                "d",
                "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
                None,
                "",
            ),
            "Personal".to_string(),
        ),
    ];
    let mut asked: Vec<OpFile> = Vec::new();
    let openssh = other.openssh.to_string();
    let mut fetch = |f: &OpFile| -> import::Fetched {
        asked.push(f.clone());
        if f.item == "c" {
            Ok(Zeroizing::new(openssh.as_bytes().to_vec()))
        } else {
            Err("no such file".into())
        }
    };
    let b = import::read_op(&items, &mut fetch);
    let find = |t: &str| b.items.iter().find(|i| i.draft.title == t).expect(t);

    let a = find("Key a");
    assert_eq!(a.draft.kind, Kind::SshKey);
    let key = a.ssh.as_ref().expect("key");
    assert_eq!(key.fingerprint, kf.fingerprint);
    assert!(
        key.openssh
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    assert_eq!(
        a.draft.notes.as_str(),
        "deploy\n\nhost: github.com",
        "what the key gives isn't listed"
    );
    assert!(a.fields.is_empty(), "the key isn't a field too");
    assert_eq!(
        find("Key b").ssh.as_ref().unwrap().fingerprint,
        other.fingerprint
    );
    assert_eq!(
        find("Key c").ssh.as_ref().unwrap().fingerprint,
        other.fingerprint
    );
    assert_eq!(
        asked
            .iter()
            .map(|f| (f.item.as_str(), f.file.as_str()))
            .collect::<Vec<_>>(),
        [
            ("c", "private key?ssh-format=openssh"),
            ("d", "private key?ssh-format=openssh")
        ],
        "op is asked only for a key Safe can't read"
    );
    let d = find("Key d");
    assert_eq!(d.draft.kind, Kind::Note);
    assert!(d.ssh.is_none());
    assert!(d.draft.notes.starts_with("SSH key\n"));
    assert!(d.draft.notes.contains("key type: ed25519"), "nothing lost");
    assert!(
        d.fields
            .iter()
            .any(|f| f.name == "private key" && f.protected)
    );
    assert!(
        b.skipped
            .iter()
            .any(|x| x.title == "Key d — SSH key" && x.reason.starts_with("kept as a note: ")),
        "the report says why: {:?}",
        b.skipped
    );

    let mut s = Safe::create("x", cheap());
    let r = s.import(&b, &Options::default()).expect("import");
    assert_eq!((r.ssh_keys, r.notes, r.logins, r.attachments), (3, 1, 0, 0));
    let back = round_trip(&mut s);
    let keys: Vec<_> = back
        .items()
        .into_iter()
        .filter(|i| i.kind == Kind::SshKey)
        .collect();
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|k| k.ssh.as_ref().is_some_and(|x| x.agent)));
}

#[test]
fn a_1pux_ssh_key_becomes_an_ssh_key_item() {
    let (pem, kf) = pkcs8(9);
    let export = json!({"accounts": [{"attrs": {"accountName": "Sam"}, "vaults": [{
        "attrs": {"name": "Personal"},
        "items": [{
            "uuid": "k1", "categoryUuid": "114", "state": "active", "createdAt": 1500000000, "updatedAt": 1700000000,
            "overview": {"title": "GitHub key", "tags": ["dev"]},
            "details": {"notesPlain": "work laptop", "sections": [{"title": "", "fields": [
                {"title": "private key", "id": "private_key", "value": {"sshKey": {
                    "privateKey": pem,
                    "metadata": {"privateKey": pem, "publicKey": kf.public_key, "fingerprint": kf.fingerprint, "keyType": "ed25519"}}}},
                {"title": "comment", "id": "c", "value": {"string": "for pushes"}},
            ]}]},
        }],
    }]}]});
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("export.data", zip::write::SimpleFileOptions::default())
        .expect("file");
    zip.write_all(export.to_string().as_bytes()).expect("write");
    let bytes = zip.finish().expect("zip").into_inner();

    let b = import::read_1pux(&bytes).expect("read");
    let k = &b.items[0];
    assert_eq!(k.draft.kind, Kind::SshKey);
    assert_eq!(k.folder, "Personal");
    assert_eq!(k.draft.tags, ["dev"]);
    assert_eq!(k.draft.notes.as_str(), "work laptop\n\ncomment: for pushes");
    assert_eq!(k.ssh.as_ref().unwrap().fingerprint, kf.fingerprint);
    let mut s = Safe::create("x", cheap());
    let r = s.import(&b, &Options::default()).expect("import");
    assert_eq!((r.ssh_keys, r.notes), (1, 0));
    let id = round_trip(&mut s).items()[0].id.clone();
    let back = round_trip(&mut s);
    assert_eq!(
        back.summary(&id).unwrap().ssh.unwrap().public_key,
        kf.public_key
    );
}
