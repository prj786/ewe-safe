//! Passkeys (docs/FORMAT.md, "Passkeys") against other apps' code:
//!
//! - `tests/passkeys/keepassxc-2.7.12-passkeys.kdbx` was written by
//!   KeePassXC 2.7.12 (`keepassxc-cli import` of its own XML export, with
//!   the passkey fields added as KeePassXC's `addPasskeyToEntry` and
//!   `addPasskeyToGroup` write them; the keys made by Botan, the library
//!   KeePassXC signs with). Password `fixture`. Safe must sign with both
//!   of its passkeys (ES256 and EdDSA);
//! - OpenSSL, when installed, reads the keys Safe makes and checks Safe's
//!   signatures;
//! - `keepassxc-cli` (`SAFE_KEEPASSXC_CLI`, else the PATH), when there,
//!   shows a passkey Safe made, field by field, and rewrites the file
//!   without losing it;
//! - merges: a passkey survives another machine's edits and a phone app's
//!   rewrite.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use keepass::config::KdfConfig;
use keepass::db::{EntryId, fields};
use keepass::{Database, DatabaseKey};
use p256::pkcs8::DecodePublicKey as _;
use safe_core::passkey::{self, Alg, Flags, Key, New};
use safe_core::safe::key;
use safe_core::{Draft, Kind, Safe};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

const FIXTURE: &[u8] = include_bytes!("../../../tests/passkeys/keepassxc-2.7.12-passkeys.kdbx");
/// The fixture's public keys, as Botan printed them (`botan pkcs8 --pub-out`).
const GITHUB_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz7up5UtMbbBqNonc17A08HlibdhjUV/OARsMVHUW85SOIbjxv4oAxWbmOoMCDOyt6mG3PVpJFUGschXTtLjuGg==";
const WEBAUTHN_SPKI: &str = "MCowBQYDK2VwAyEAAUwXswVpEkb9gBbfN90PnBRQW61wRcUqDgK9p8bSNZM=";

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

fn verify(alg: Alg, spki: &[u8], msg: &[u8], sig: &[u8]) {
    match alg {
        Alg::Es256 => {
            use p256::ecdsa::signature::Verifier as _;
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki).expect("spki");
            let s = p256::ecdsa::Signature::from_der(sig).expect("a DER signature");
            vk.verify(msg, &s).expect("the ES256 signature verifies");
        }
        Alg::EdDsa => {
            use ed25519_dalek::Verifier as _;
            let vk = ed25519_dalek::VerifyingKey::from_public_key_der(spki).expect("spki");
            let s = ed25519_dalek::Signature::from_slice(sig).expect("64 bytes");
            vk.verify(msg, &s).expect("the EdDSA signature verifies");
        }
    }
}

/// Sign as `passkey-get` does and check the signature with `spki`.
fn signs_for(safe: &Safe, id: &str, rp: &str, spki: &[u8]) -> Alg {
    let secret = safe.passkey_secret(id).expect("read").expect("a passkey");
    let data = passkey::assertion_data(
        rp,
        Flags {
            up: true,
            uv: true,
            be: secret.be,
            bs: secret.bs,
        },
    );
    let hash = Sha256::digest(b"{\"type\":\"webauthn.get\",\"challenge\":\"abc\"}");
    let (alg, sig) = passkey::sign(&secret.pem, &data, &hash).expect("sign");
    let mut msg = data;
    msg.extend_from_slice(&hash);
    verify(alg, spki, &msg, &sig);
    alg
}

fn std_b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64")
}

fn id_of(safe: &Safe, title: &str) -> String {
    safe.items()
        .into_iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no {title}"))
        .id
}

fn entry_id(id: &str) -> EntryId {
    EntryId::from_uuid(Uuid::parse_str(id).expect("uuid"))
}

#[test]
fn passkeys_keepassxc_made_sign_in_safe() {
    let fixture_key = key("fixture", None).expect("key");
    let mut s = Safe::open(FIXTURE, &fixture_key).expect("the KeePassXC file opens");
    assert!(s.writable().is_ok(), "nothing in it Safe would lose");
    assert_eq!(s.database().meta.generator.as_deref(), Some("KeePassXC"));

    let github = id_of(&s, "GitHub");
    let info = s
        .summary(&github)
        .expect("summary")
        .passkey
        .expect("a passkey");
    assert_eq!(
        (
            info.rp_id.as_str(),
            info.username.as_str(),
            info.credential_id.as_str()
        ),
        (
            "github.com",
            "sam",
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
        )
    );
    let secret = s.passkey_secret(&github).expect("read").expect("secret");
    assert_eq!(secret.user_handle, passkey::b64url(b"github-user-4242"));
    assert!(secret.be && secret.bs);
    assert_eq!(
        signs_for(&s, &github, "github.com", &std_b64(GITHUB_SPKI)),
        Alg::Es256
    );

    // the passkey entry KeePassXC makes on its own, in its own group
    let wa = id_of(&s, "webauthn.io (Passkey)");
    let sum = s.summary(&wa).expect("summary");
    assert_eq!(sum.folder, "KeePassXC-Browser Passkeys");
    assert_eq!(sum.passkey.expect("a passkey").username, "Test User");
    assert_eq!(
        signs_for(&s, &wa, "webauthn.io", &std_b64(WEBAUTHN_SPKI)),
        Alg::EdDsa
    );

    // Safe's public key for the stored PEM is Botan's
    let pem = s.passkey_secret(&github).unwrap().unwrap().pem;
    assert_eq!(passkey::public_spki(&pem).unwrap().1, std_b64(GITHUB_SPKI));

    // remove: the fields and the tag go, the password stays, history keeps it
    assert!(s.remove_passkey(&github).expect("remove"));
    let back = Safe::open(&s.to_bytes(&pw()).expect("write"), &pw()).expect("open");
    let e = back.database().entry(entry_id(&github)).expect("entry");
    assert!(!e.fields.keys().any(|k| k.starts_with("KPEX_PASSKEY")));
    assert!(!e.tags.iter().any(|t| t == "Passkey"));
    assert_eq!(e.get(fields::PASSWORD), Some("hunter2"));
    let old = e.history.as_ref().expect("history").get_entries();
    assert!(
        old.last()
            .expect("a version")
            .get(passkey::PRIVATE_KEY_PEM)
            .is_some()
    );
    assert!(
        back.summary(&wa).unwrap().passkey.is_some(),
        "the other one stays"
    );
}

fn which(cmd: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(cmd))
            .find(|f| f.is_file())
    })
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("safe-passkey-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("dir");
    d
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn openssl_reads_safe_keys_and_checks_its_signatures() {
    let Some(openssl) = which("openssl") else {
        eprintln!("openssl isn't installed: skipped");
        return;
    };
    let dir = scratch("openssl");
    for alg in [Alg::Es256, Alg::EdDsa] {
        let key = Key::generate(alg).expect("key");
        let (k, pubder, pubpem) = (dir.join("k.pem"), dir.join("pub.der"), dir.join("pub.pem"));
        std::fs::write(&k, key.pem.as_bytes()).expect("write");
        // OpenSSL reads the PKCS#8 PEM and finds the same public key
        run(Command::new(&openssl)
            .args(["pkey", "-in"])
            .arg(&k)
            .args(["-pubout", "-outform", "DER", "-out"])
            .arg(&pubder));
        assert_eq!(std::fs::read(&pubder).expect("der"), key.spki, "{alg:?}");
        run(Command::new(&openssl)
            .args(["pkey", "-in"])
            .arg(&k)
            .args(["-pubout", "-out"])
            .arg(&pubpem));

        let data = passkey::assertion_data(
            "example.org",
            Flags {
                up: true,
                uv: true,
                be: true,
                bs: true,
            },
        );
        let hash = Sha256::digest(b"client data");
        let (_, sig) = passkey::sign(&key.pem, &data, &hash).expect("sign");
        let (msg, sigf) = (dir.join("msg"), dir.join("sig"));
        std::fs::write(&msg, [&data[..], &hash[..]].concat()).expect("write");
        std::fs::write(&sigf, &sig).expect("write");
        let said = match alg {
            Alg::Es256 => run(Command::new(&openssl)
                .args(["dgst", "-sha256", "-verify"])
                .arg(&pubpem)
                .arg("-signature")
                .arg(&sigf)
                .arg(&msg)),
            Alg::EdDsa => run(Command::new(&openssl)
                .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
                .arg(&pubpem)
                .arg("-rawin")
                .arg("-in")
                .arg(&msg)
                .arg("-sigfile")
                .arg(&sigf)),
        };
        assert!(said.contains("Verified"), "{alg:?}: {said}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A login with a passkey, as `passkey-create` saves it.
fn with_passkey(s: &mut Safe, alg: Alg) -> (String, Key, New) {
    let id = s
        .add(&Draft {
            kind: Kind::Login,
            title: "GitHub".into(),
            username: "sam".into(),
            password: Zeroizing::new("pw-1".into()),
            websites: vec!["https://github.com".into()],
            ..Draft::default()
        })
        .expect("add");
    let key = Key::generate(alg).expect("key");
    let new = New {
        rp_id: "github.com".into(),
        username: "sam".into(),
        credential_id: passkey::b64url(&passkey::new_credential_id().expect("id")),
        pem: key.pem.clone(),
        user_handle: passkey::b64url(b"user-7"),
    };
    s.set_passkey(&id, &new).expect("set");
    (id, key, new)
}

/// The passkey is all there: values, protection, the tag, and it signs.
fn intact(s: &Safe, id: &str, key: &Key, new: &New) {
    let e = s.database().entry(entry_id(id)).expect("entry");
    for (name, value, protected) in [
        (passkey::CREDENTIAL_ID, new.credential_id.as_str(), true),
        (passkey::PRIVATE_KEY_PEM, new.pem.as_str(), true),
        (passkey::USER_HANDLE, new.user_handle.as_str(), true),
        (passkey::RELYING_PARTY, "github.com", false),
        (passkey::USERNAME, "sam", false),
        (passkey::FLAG_BE, "1", false),
        (passkey::FLAG_BS, "1", false),
    ] {
        assert_eq!(e.get(name), Some(value), "{name}");
        assert_eq!(
            e.fields[name].is_protected(),
            protected,
            "{name} protection"
        );
    }
    assert!(e.tags.iter().any(|t| t == "Passkey"));
    signs_for(s, id, "github.com", &key.spki);
}

#[test]
fn a_passkey_survives_another_machines_edits() {
    let mut base = Safe::create("x", cheap());
    let mail = base
        .add(&Draft {
            kind: Kind::Login,
            title: "Mail".into(),
            password: Zeroizing::new("m-1".into()),
            ..Draft::default()
        })
        .expect("add");
    let bytes = base.to_bytes(&pw()).expect("write");
    let mut a = Safe::open(&bytes, &pw()).expect("a");
    let mut b = Safe::open(&bytes, &pw()).expect("b");
    // file times have whole seconds: the edits must be newer than the base
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let (gh, key, new) = with_passkey(&mut a, Alg::Es256);
    let mut d = b.draft(&mail).expect("draft");
    d.password = Zeroizing::new("m-2".into());
    b.update(&mail, &d).expect("edit on b");
    b.add(&Draft {
        kind: Kind::Login,
        title: "Bank".into(),
        ..Draft::default()
    })
    .expect("add on b");

    let (mut ab, mut ba) = (a.clone(), b.clone());
    ab.merge(&b).expect("merge b into a");
    ba.merge(&a).expect("merge a into b");
    for m in [&mut ab, &mut ba] {
        let back = Safe::open(&m.to_bytes(&pw()).expect("write"), &pw()).expect("open");
        intact(&back, &gh, &key, &new);
        assert_eq!(
            back.reveal(&mail, &safe_core::Field::Password)
                .unwrap()
                .as_str(),
            "m-2"
        );
        assert_eq!(back.items().len(), 3);
    }
}

#[test]
fn a_phone_rewrite_keeps_the_passkey() {
    let mut a = Safe::create("x", cheap());
    let (gh, key, new) = with_passkey(&mut a, Alg::EdDsa);
    let bytes = a.to_bytes(&pw()).expect("write");
    let mut a = Safe::open(&bytes, &pw()).expect("open");

    // the phone: reads the file with its own writer, sets every field of
    // the login again (as KeePassDX's addOrReplaceField does), uses it
    // (access time, usage count), changes its password, saves
    let mut phone = Database::parse(&bytes, pw()).expect("parse");
    {
        let mut e = phone.entry_mut(entry_id(&gh)).expect("entry");
        let all: Vec<(String, keepass::db::Value<String>)> = e.fields.drain().collect();
        for (k, v) in all.into_iter().rev() {
            e.fields.insert(k, v);
        }
        let later = chrono::Utc::now().naive_utc() + chrono::Duration::seconds(5);
        e.times.last_access = Some(later);
        e.times.usage_count = e.times.usage_count.map(|n| n + 3).or(Some(3));
        e.set_protected(fields::PASSWORD, "pw-from-phone");
        e.times.last_modification = Some(later);
    }
    let mut out = Vec::new();
    phone.save(&mut out, pw()).expect("phone saves");
    let phone = Safe::open(&out, &pw()).expect("Safe opens the phone's copy");

    let report = a.merge(&phone).expect("merge");
    assert_eq!(report.updated, 1, "the phone's newer version wins");
    let back = Safe::open(&a.to_bytes(&pw()).expect("write"), &pw()).expect("open");
    intact(&back, &gh, &key, &new);
    assert_eq!(
        back.reveal(&gh, &safe_core::Field::Password)
            .unwrap()
            .as_str(),
        "pw-from-phone"
    );
    // merging the same copy again changes nothing
    let mut again = back.clone();
    let r = again.merge(&phone).expect("merge again");
    assert_eq!((r.updated, r.diverged, r.added), (0, 0, 0));
}

fn keepassxc_cli() -> Option<PathBuf> {
    std::env::var_os("SAFE_KEEPASSXC_CLI")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| which("keepassxc-cli"))
}

fn kpxc(cli: &Path, args: &[&str], file: &Path, entry: &str) -> String {
    let mut c = Command::new(cli);
    c.args(args)
        .arg(file)
        .arg(entry)
        .env("QT_QPA_PLATFORM", "offscreen")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("keepassxc-cli");
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
        "keepassxc-cli {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn keepassxc_shows_a_safe_passkey_and_rewrites_the_file_without_losing_it() {
    let Some(cli) = keepassxc_cli() else {
        eprintln!("keepassxc-cli isn't installed (SAFE_KEEPASSXC_CLI): skipped");
        return;
    };
    let dir = scratch("keepassxc");
    let file = dir.join("safe.kdbx");
    let mut s = Safe::create("x", cheap());
    let (gh, key, new) = with_passkey(&mut s, Alg::Es256);
    s.write_file(&file, &pw()).expect("write");

    let shown = kpxc(&cli, &["show", "-q", "-s", "--all"], &file, "GitHub");
    for line in [
        format!("KPEX_PASSKEY_CREDENTIAL_ID: {}", new.credential_id),
        format!("KPEX_PASSKEY_USER_HANDLE: {}", new.user_handle),
        "KPEX_PASSKEY_RELYING_PARTY: github.com".to_string(),
        "KPEX_PASSKEY_USERNAME: sam".to_string(),
        "KPEX_PASSKEY_FLAG_BE: 1".to_string(),
        "KPEX_PASSKEY_FLAG_BS: 1".to_string(),
        "KPEX_PASSKEY_PRIVATE_KEY_PEM: -----BEGIN PRIVATE KEY-----".to_string(),
        "Tags: Passkey".to_string(),
    ] {
        assert!(
            shown.contains(&line),
            "KeePassXC shows {line:?}:\n{}",
            shown.replace(new.pem.as_str(), "<pem>")
        );
    }

    // KeePassXC rewrites the whole file (an edit of the login itself)
    kpxc(&cli, &["edit", "-q", "-u", "sam@kpxc"], &file, "GitHub");
    let back = Safe::open_file(&file, &pw()).expect("Safe opens KeePassXC's rewrite");
    assert_eq!(back.summary(&gh).unwrap().username, "sam@kpxc");
    intact(&back, &gh, &key, &new);
    let _ = std::fs::remove_dir_all(&dir);
}
