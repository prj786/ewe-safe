//! Passkeys (docs/TRIO.md S1), SSH keys (S2) and `safe://` references (S3)
//! in one safe. Each stream tests itself; this file checks the seams
//! between them: both kinds of key side by side, a reference reads an SSH
//! key exactly as `reveal` does, and a merge (rule 3a) keeps both.

use std::time::Duration;

use keepass::config::KdfConfig;
use keepass::db::{EntryId, Value};
use safe_core::passkey::{self, Alg, Key, New};
use safe_core::refs;
use safe_core::safe::{self, Safe};
use safe_core::ssh::{self, KeeAgent};
use safe_core::{Draft, Field, Kind};
use zeroize::Zeroizing;

fn cheap() -> KdfConfig {
    KdfConfig::Aes { rounds: 1 }
}

fn pw() -> keepass::DatabaseKey {
    safe::key("correct horse", None).expect("key")
}

fn reopen(s: &mut Safe) -> Safe {
    Safe::open(&s.to_bytes(&pw()).expect("write"), &pw()).expect("open")
}

fn eid(id: &str) -> EntryId {
    EntryId::from(uuid::Uuid::parse_str(id).expect("uuid"))
}

/// "GitHub", a login with a passkey, and "GitHub key", an SSH key Safe
/// made. Returns their ids and the SSH key.
fn both(s: &mut Safe) -> (String, String, ssh::KeyFile) {
    let login = s
        .add(&Draft {
            kind: Kind::Login,
            title: "GitHub".into(),
            username: "sam".into(),
            password: Zeroizing::new("pw-1".into()),
            websites: vec!["https://github.com".into()],
            ..Draft::default()
        })
        .expect("login");
    let key = Key::generate(Alg::Es256).expect("passkey key");
    s.set_passkey(
        &login,
        &New {
            rp_id: "github.com".into(),
            username: "sam".into(),
            credential_id: passkey::b64url(&passkey::new_credential_id().expect("id")),
            pem: key.pem.clone(),
            user_handle: passkey::b64url(b"user-7"),
        },
    )
    .expect("passkey");
    let kf = ssh::generate("ed25519", None, "GitHub key").expect("ssh key");
    let key_id = s.add_ssh_key(&kf, "GitHub key", "", "").expect("ssh");
    (login, key_id, kf)
}

fn read(s: &Safe, text: &str) -> Result<String, &'static str> {
    let r = refs::parse(text).map_err(|e| e.code())?;
    refs::resolve(s, &r)
        .map(|v| v.value.to_string())
        .map_err(|e| e.code())
}

fn reveal(s: &Safe, id: &str, field: &str) -> String {
    s.reveal(id, &Field::Other(field.into()))
        .unwrap_or_else(|e| panic!("reveal {field}: {e}"))
        .to_string()
}

#[test]
fn a_passkey_and_an_ssh_key_live_side_by_side() {
    let mut s = Safe::create("Safe", cheap());
    let (login, key_id, kf) = both(&mut s);
    let s = reopen(&mut s);

    let l = s.summary(&login).expect("login");
    assert_eq!(l.kind, Kind::Login);
    assert_eq!(
        l.passkey.as_ref().map(|p| p.rp_id.as_str()),
        Some("github.com")
    );
    assert!(l.ssh.is_none(), "a login has no ssh part");

    let k = s.summary(&key_id).expect("key");
    assert_eq!(k.kind, Kind::SshKey);
    assert!(k.passkey.is_none(), "an SSH key has no passkey");
    let info = k.ssh.expect("ssh part");
    assert_eq!(info.fingerprint, kf.fingerprint);
    assert!(info.agent);

    // each list sees only its own
    let items = s.items();
    assert_eq!(items.iter().filter(|i| i.passkey.is_some()).count(), 1);
    assert_eq!(items.iter().filter(|i| i.kind == Kind::SshKey).count(), 1);
    let secret = s.passkey_secret(&login).expect("read").expect("a passkey");
    assert_eq!(secret.rp_id, "github.com");
    assert!(s.passkey_secret(&key_id).expect("read").is_none());
    let (text, _) = s.ssh_private(&key_id).expect("the key");
    assert_eq!(text.as_str(), kf.openssh.as_str());
    assert!(s.ssh_private(&login).is_err(), "a login is no SSH key");
}

#[test]
fn a_reference_reads_an_ssh_key_as_reveal_does() {
    let mut s = Safe::create("Safe", cheap());
    let (login, key_id, kf) = both(&mut s);

    // an SSH key KeePassXC made: no `public_key` field, no marker of ours
    let other = ssh::generate("ecdsa", None, "sam@laptop").expect("key");
    let made = s
        .add(&Draft {
            kind: Kind::Login,
            title: "Server".into(),
            ..Draft::default()
        })
        .expect("add");
    let mut db = s.database().clone();
    {
        let mut e = db.entry_mut(eid(&made)).expect("entry");
        e.add_attachment(
            "id_ecdsa",
            Value::protected(other.openssh.as_bytes().to_vec()),
        );
        let st = KeeAgent {
            selected_type: "attachment".into(),
            attachment_name: "id_ecdsa".into(),
            allow_use: true,
            ..KeeAgent::default()
        };
        e.add_attachment(ssh::SETTINGS, Value::unprotected(st.to_xml()));
    }
    let mut bytes = Vec::new();
    db.save(&mut bytes, pw()).expect("save");
    let s = Safe::open(&bytes, &pw()).expect("open");

    for (id, title, kf) in [(&key_id, "GitHub key", &kf), (&made, "Server", &other)] {
        let public = read(&s, &format!("safe://{title}/public_key")).expect("public_key");
        assert_eq!(public, reveal(&s, id, ssh::PUBLIC_KEY), "{title}");
        assert_eq!(public, kf.public_key, "{title}");
        let private = read(&s, &format!("safe://{title}/private_key")).expect("private_key");
        assert_eq!(private, reveal(&s, id, ssh::PRIVATE_KEY), "{title}");
        assert_eq!(private, kf.openssh.as_str(), "{title}");
        // by id too
        assert_eq!(
            read(&s, &format!("safe://{id}/private_key")).expect("by id"),
            private
        );
    }
    // a login with a passkey is no SSH key; its passkey is not a field
    // a reference names by these names
    assert_eq!(read(&s, "safe://GitHub/private_key"), Err("not-found"));
    assert_eq!(read(&s, "safe://GitHub/public_key"), Err("not-found"));
    assert_eq!(
        read(&s, &format!("safe://{login}/password")).as_deref(),
        Ok("pw-1")
    );
}

#[test]
fn a_merge_carries_a_passkey_and_keeps_an_ssh_key_whole() {
    let mut s = Safe::create("Safe", cheap());
    let login = s
        .add(&Draft {
            kind: Kind::Login,
            title: "GitHub".into(),
            username: "sam".into(),
            password: Zeroizing::new("pw-1".into()),
            ..Draft::default()
        })
        .expect("login");
    let kf = ssh::generate("ed25519", None, "GitHub key").expect("ssh key");
    let key_id = s.add_ssh_key(&kf, "GitHub key", "", "").expect("ssh");
    let base = reopen(&mut s);

    // this machine: a passkey at sign-in, and the key renamed
    let mut here = base.clone();
    let key = Key::generate(Alg::EdDsa).expect("passkey key");
    here.set_passkey(
        &login,
        &New {
            rp_id: "github.com".into(),
            username: "sam".into(),
            credential_id: passkey::b64url(b"cred-here"),
            pem: key.pem.clone(),
            user_handle: passkey::b64url(b"user-7"),
        },
    )
    .expect("passkey");
    let mut d = here.draft(&key_id).expect("draft");
    d.title = "GitHub key (laptop)".into();
    here.update(&key_id, &d).expect("rename");

    // the other machine, a second later: a new password, the key's notes
    std::thread::sleep(Duration::from_millis(1100));
    let mut there = base.clone();
    let mut d = there.draft(&login).expect("draft");
    d.password = Zeroizing::new("pw-2".into());
    there.update(&login, &d).expect("password");
    let mut d = there.draft(&key_id).expect("draft");
    d.notes = Zeroizing::new("for github.com".into());
    there.update(&key_id, &d).expect("notes");

    for (mut ours, theirs) in [(here.clone(), &there), (there.clone(), &here)] {
        ours.merge(theirs).expect("merge");
        let m = reopen(&mut ours);
        // rule 3: the newer login wins; rule 3a: the passkey comes along
        let l = m.summary(&login).expect("login");
        assert_eq!(
            l.passkey.map(|p| p.credential_id).as_deref(),
            Some("Y3JlZC1oZXJl")
        );
        assert_eq!(
            m.reveal(&login, &Field::Password)
                .expect("password")
                .as_str(),
            "pw-2"
        );
        // the SSH key: the newer version whole, its key and settings intact
        let k = m.summary(&key_id).expect("key");
        assert_eq!(k.kind, Kind::SshKey);
        assert_eq!(k.title, "GitHub key", "the newer version's title");
        assert!(k.passkey.is_none(), "no passkey carried onto an SSH key");
        let info = k.ssh.expect("ssh part");
        assert_eq!(info.fingerprint, kf.fingerprint);
        assert!(info.agent, "KeeAgent.settings still names the key");
        assert_eq!(
            m.ssh_private(&key_id).expect("key").0.as_str(),
            kf.openssh.as_str()
        );
        assert_eq!(
            read(&m, "safe://GitHub key/private_key").expect("read"),
            kf.openssh.as_str()
        );
        let draft = m.draft(&key_id).expect("draft");
        assert_eq!(draft.notes.as_str(), "for github.com");
        // the renamed version is in the item's history, not lost
        let e = m.database().entry(eid(&key_id)).expect("entry");
        let titles: Vec<String> = e
            .history
            .as_ref()
            .map(|h| {
                h.get_entries()
                    .iter()
                    .filter_map(|v| v.get(keepass::db::fields::TITLE).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            titles.iter().any(|t| t == "GitHub key (laptop)"),
            "{titles:?}"
        );
    }
}
