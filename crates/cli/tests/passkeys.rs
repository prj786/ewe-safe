//! Passkeys through the real daemon (docs/PROTOCOL.md: `passkey-list`,
//! `passkey-create`, `passkey-get`, `edit --remove-passkey`), as the ewe
//! browser calls them: over the socket, in a sandbox (own XDG dirs, a fake
//! `ewe-conf`, cheap key derivation, no logind, a safe on "this
//! computer"). Every answer is checked by code that didn't make it: the
//! attestation object by a CBOR reader of its own, every signature with
//! the public key the daemon handed out.
//!
//! Run from the workspace (`cargo test`), which builds both binaries.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use p256::pkcs8::DecodePublicKey as _;
use safe_core::passkey::{b64url, from_b64};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MASTER: &str = "correct horse battery";
const AAGUID: &str = "452b824e-42d3-4324-bc6c-581888ca2851";

static N: AtomicUsize = AtomicUsize::new(0);

fn cli_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ewe-safe"))
}

struct Sandbox {
    root: PathBuf,
    run: PathBuf,
    daemon: Option<Child>,
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).expect("script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("safe-pk-{}-{n}-{name}", std::process::id()));
        // the socket path must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/sp-{}-{n}", std::process::id()));
        for d in [&root, &run] {
            let _ = std::fs::remove_dir_all(d);
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        for d in ["state", "config", "data", "home", "bin"] {
            std::fs::create_dir_all(root.join(d)).expect("mkdir");
        }
        // init records the place through ewe-conf: a stand-in that keeps a file
        write_exec(
            &root.join("bin/ewe-conf"),
            "#!/bin/sh\necho \"$*\" >> \"$XDG_CONFIG_HOME/ewe-conf.argv\"\n[ \"$1\" = get ] && exit 1\nexit 0\n",
        );
        Sandbox {
            root,
            run,
            daemon: None,
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        let p = |d: &str| self.root.join(d).display().to_string();
        vec![
            ("HOME".into(), p("home")),
            ("PATH".into(), format!("{}:/usr/bin:/bin", p("bin"))),
            ("XDG_RUNTIME_DIR".into(), self.run.display().to_string()),
            ("XDG_STATE_HOME".into(), p("state")),
            ("XDG_CONFIG_HOME".into(), p("config")),
            ("XDG_DATA_HOME".into(), p("data")),
            ("EWE_SAFE_NO_LOGIND".into(), "1".into()),
            ("EWE_SAFE_KDF_ITERATIONS".into(), "2".into()),
        ]
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.root.join("daemon.log")).expect("log");
        let child = Command::new(cli_exe().with_file_name("ewe-safed"))
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("ewe-safed (build the workspace first)");
        self.daemon = Some(child);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.cli(&["ping"], None)["ok"] == true {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon didn't answer: {}", self.log());
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.root.join("daemon.log")).unwrap_or_default()
    }

    fn cli(&self, args: &[&str], stdin: Option<&str>) -> Value {
        let mut child = Command::new(cli_exe())
            .args(args)
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("ewe-safe");
        let input = stdin.unwrap_or("");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait");
        assert_eq!(out.status.code(), Some(0), "{args:?} exits 0");
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|_| panic!("{args:?} printed {}", String::from_utf8_lossy(&out.stdout)))
    }

    fn ok(&self, args: &[&str], stdin: Option<&str>) -> Value {
        let v = self.cli(args, stdin);
        assert_eq!(v["ok"], true, "{args:?}: {v}");
        v
    }

    /// One request on the socket, as the browser's main process sends it.
    fn sock(&self, verb: &str, args: Value) -> Value {
        let mut s = UnixStream::connect(self.run.join("ewe-safe.sock")).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let req = json!({"v": 1, "id": 7, "verb": verb, "args": args});
        s.write_all(format!("{req}\n").as_bytes()).expect("send");
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).expect("reply");
        let v: Value = serde_json::from_str(&line).expect("json");
        assert_eq!(v["id"], 7, "the envelope's id is the request's");
        v
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(mut c) = self.daemon.take() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.run);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A CBOR reader of its own (the daemon's writer is in safe-core).
#[derive(Debug, PartialEq)]
enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Map(Vec<(Cbor, Cbor)>),
}

fn cbor(b: &[u8], at: &mut usize) -> Cbor {
    let (major, info) = (b[*at] >> 5, b[*at] & 0x1f);
    *at += 1;
    let mut n = info as u64;
    if (24..=27).contains(&info) {
        n = 0;
        for _ in 0..(1usize << (info - 24)) {
            n = (n << 8) | b[*at] as u64;
            *at += 1;
        }
    }
    let mut take = |len: usize| {
        let v = b[*at..*at + len].to_vec();
        *at += len;
        v
    };
    match major {
        0 => Cbor::Int(n as i128),
        1 => Cbor::Int(-1 - n as i128),
        2 => Cbor::Bytes(take(n as usize)),
        3 => Cbor::Text(String::from_utf8(take(n as usize)).expect("utf-8")),
        5 => Cbor::Map((0..n).map(|_| (cbor(b, at), cbor(b, at))).collect()),
        m => panic!("major type {m}"),
    }
}

fn field(m: &Cbor, k: Cbor) -> &Cbor {
    let Cbor::Map(pairs) = m else {
        panic!("not a map")
    };
    &pairs.iter().find(|(x, _)| *x == k).expect("key").1
}

fn bytes(v: &Value) -> Vec<u8> {
    from_b64(v.as_str().expect("a string")).expect("base64url")
}

/// Check `passkey-create`'s answer as a relying party would; the credential
/// id and the SPKI public key.
fn check_attestation(r: &Value, rp: &str, uv: bool, alg: i64) -> (String, Vec<u8>) {
    let att_bytes = bytes(&r["attestation_object"]);
    let mut at = 0;
    let att = cbor(&att_bytes, &mut at);
    assert_eq!(at, att_bytes.len());
    assert_eq!(
        field(&att, Cbor::Text("fmt".into())),
        &Cbor::Text("none".into())
    );
    assert_eq!(
        field(&att, Cbor::Text("attStmt".into())),
        &Cbor::Map(vec![])
    );
    let Cbor::Bytes(auth) = field(&att, Cbor::Text("authData".into())) else {
        panic!("authData")
    };
    assert_eq!(
        auth,
        &bytes(&r["authenticator_data"]),
        "the same authenticator data"
    );
    assert_eq!(&auth[..32], &Sha256::digest(rp.as_bytes())[..]);
    let want = 0x01 | 0x08 | 0x10 | 0x40 | if uv { 0x04 } else { 0 };
    assert_eq!(auth[32], want, "UP BE BS AT, UV when verified");
    assert_eq!(&auth[33..37], &[0, 0, 0, 0], "sign count 0");
    assert_eq!(uuid_text(&auth[37..53]), AAGUID, "Safe's AAGUID");
    let len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
    let cred = &auth[55..55 + len];
    let credential_id = r["credential_id"].as_str().unwrap().to_string();
    assert_eq!(b64url(cred), credential_id);
    let mut at = 55 + len;
    let cose = cbor(auth, &mut at);
    assert_eq!(at, auth.len(), "the COSE key ends the data");
    assert_eq!(field(&cose, Cbor::Int(3)), &Cbor::Int(alg as i128));
    assert_eq!(r["public_key_algorithm"], alg);

    // the COSE key and the SPKI are the same key
    let spki = bytes(&r["public_key"]);
    match alg {
        -7 => {
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki).expect("spki");
            let p = vk.to_sec1_point(false);
            let (Cbor::Bytes(x), Cbor::Bytes(y)) =
                (field(&cose, Cbor::Int(-2)), field(&cose, Cbor::Int(-3)))
            else {
                panic!("x, y")
            };
            assert_eq!([&x[..], &y[..]].concat(), &p.as_bytes()[1..]);
        }
        -8 => {
            let vk = ed25519_dalek::VerifyingKey::from_public_key_der(&spki).expect("spki");
            assert_eq!(
                field(&cose, Cbor::Int(-2)),
                &Cbor::Bytes(vk.to_bytes().to_vec())
            );
        }
        _ => unreachable!(),
    }
    (credential_id, spki)
}

fn uuid_text(b: &[u8]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Check `passkey-get`'s signature over authenticatorData || hash.
fn check_assertion(g: &Value, rp: &str, hash: &[u8], spki: &[u8], alg: i64, uv: bool) {
    let auth = bytes(&g["authenticator_data"]);
    assert_eq!(auth.len(), 37, "no attested data on get");
    assert_eq!(&auth[..32], &Sha256::digest(rp.as_bytes())[..]);
    assert_eq!(auth[32], 0x01 | 0x08 | 0x10 | if uv { 0x04 } else { 0 });
    assert_eq!(&auth[33..], &[0, 0, 0, 0]);
    let msg = [&auth[..], hash].concat();
    let sig = bytes(&g["signature"]);
    match alg {
        -7 => {
            use p256::ecdsa::signature::Verifier as _;
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki).expect("spki");
            let s = p256::ecdsa::Signature::from_der(&sig).expect("DER");
            vk.verify(&msg, &s).expect("the ES256 signature verifies");
        }
        -8 => {
            use ed25519_dalek::Verifier as _;
            let vk = ed25519_dalek::VerifyingKey::from_public_key_der(spki).expect("spki");
            let s = ed25519_dalek::Signature::from_slice(&sig).expect("64 bytes");
            vk.verify(&msg, &s).expect("the EdDSA signature verifies");
        }
        _ => unreachable!(),
    }
}

fn hash_of(client_data: &str) -> (Vec<u8>, String) {
    let h = Sha256::digest(client_data.as_bytes()).to_vec();
    let s = b64url(&h);
    (h, s)
}

#[test]
fn passkeys_over_the_socket() {
    let mut s = Sandbox::new("socket");
    s.start();
    assert_eq!(
        s.sock("passkey-list", json!({"rp_id": "github.com"}))["error"],
        "not-set-up"
    );
    s.ok(
        &["init", "--place", "local"],
        Some(&format!("{MASTER}\n{MASTER}\n")),
    );
    let gh = s.ok(
        &[
            "add",
            "--title",
            "GitHub",
            "--url",
            "https://github.com/login",
            "--password-stdin",
        ],
        Some("hunter2\n"),
    )["item_id"]
        .as_str()
        .unwrap()
        .to_string();
    let note = s.ok(&["add", "--kind", "note", "--title", "Codes"], None)["item_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(s.ok(&["show", &gh], None)["item"]["passkey"], Value::Null);

    // create on the login the browser names (ES256 first in the site's list)
    let (_, create_hash) = hash_of(
        r#"{"type":"webauthn.create","challenge":"c1","origin":"https://github.com","crossOrigin":false}"#,
    );
    let base = json!({
        "rp_id": "github.com",
        "rp_name": "GitHub",
        "user_id": b64url(b"github-user-42"),
        "user_name": "sam",
        "user_display_name": "Sam",
        "client_data_hash": create_hash,
        "algorithms": [-7, -257],
        "exclude": [],
        "item_id": gh,
        "origin": "https://github.com",
        "user_verified": true,
    });
    let r = s.sock("passkey-create", base.clone());
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["item_id"], gh.as_str());
    assert!(r["sync"]["state"].is_string(), "the save's sync object");
    assert!(
        r.get("id") == Some(&json!(7)),
        "no field of its own is called id"
    );
    let (cred, spki) = check_attestation(&r, "github.com", true, -7);

    let item = &s.ok(&["show", &gh], None)["item"];
    assert_eq!(
        item["passkey"],
        json!({"rp_id": "github.com", "username": "sam"})
    );
    assert_eq!(
        item["username"], "sam",
        "an empty username takes the passkey's"
    );
    assert!(item["tags"].as_array().unwrap().contains(&json!("Passkey")));
    assert_eq!(item["has_password"], true, "the password stays");

    // list: the CLI and the socket, with and without allow
    let l = s.ok(&["passkey", "list", "--rp", "github.com"], None);
    assert_eq!(
        l["passkeys"],
        json!([{"item_id": gh, "title": "GitHub", "username": "sam", "rp_id": "github.com", "credential_id": cred}])
    );
    let allowed = s.sock(
        "passkey-list",
        json!({"rp_id": "github.com", "allow": [cred]}),
    );
    assert_eq!(allowed["passkeys"].as_array().unwrap().len(), 1);
    let other = s.sock(
        "passkey-list",
        json!({"rp_id": "github.com", "allow": ["b3RoZXI"]}),
    );
    assert_eq!(other["passkeys"], json!([]));
    assert_eq!(
        s.sock("passkey-list", json!({"rp_id": "gitlab.com"}))["passkeys"],
        json!([])
    );

    // get: a signature the site can check, the user handle back
    let (h, hs) = hash_of(
        r#"{"type":"webauthn.get","challenge":"c2","origin":"https://github.com","crossOrigin":false}"#,
    );
    let g = s.sock(
        "passkey-get",
        json!({"rp_id": "github.com", "credential_id": cred, "client_data_hash": hs, "user_verified": false}),
    );
    assert_eq!(g["ok"], true, "{g}");
    assert_eq!(
        (g["item_id"].as_str(), g["credential_id"].as_str()),
        (Some(gh.as_str()), Some(cred.as_str()))
    );
    assert_eq!(g["user_handle"], b64url(b"github-user-42"));
    check_assertion(&g, "github.com", &h, &spki, -7, false);

    // a second account on the same site is a second login; the passkey
    // used last comes first
    let mut work = base.clone();
    work["user_id"] = json!(b64url(b"github-user-43"));
    // names past WebAuthn's 64 bytes are cut, not refused
    work["user_name"] = json!(format!("sam-work-{}", "é".repeat(40)));
    work["rp_name"] = json!("G".repeat(80));
    work.as_object_mut().unwrap().remove("item_id");
    let r3 = s.sock("passkey-create", work);
    assert_eq!(r3["ok"], true, "{r3}");
    let cred3 = r3["credential_id"].as_str().unwrap().to_string();
    assert_ne!(r3["item_id"], gh.as_str());
    let work_item = &s.ok(&["show", r3["item_id"].as_str().unwrap()], None)["item"];
    assert_eq!(work_item["title"], "G".repeat(64));
    let cut = work_item["passkey"]["username"].as_str().unwrap();
    assert_eq!(
        cut,
        format!("sam-work-{}", "é".repeat(27)),
        "63 bytes: é is 2"
    );
    let order = || -> Vec<String> {
        s.sock("passkey-list", json!({"rp_id": "github.com"}))["passkeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["credential_id"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(order(), [cred3.clone(), cred.clone()]);
    let again = json!({"rp_id": "github.com", "credential_id": cred, "client_data_hash": hs});
    assert_eq!(s.sock("passkey-get", again)["ok"], true);
    assert_eq!(order(), [cred.clone(), cred3.clone()]);

    // a new login for a passkey (EdDSA first in the site's list)
    let mut wa = base.clone();
    wa["rp_id"] = json!("webauthn.io");
    wa["rp_name"] = json!("");
    wa["user_name"] = json!("Test User");
    wa["algorithms"] = json!([-8, -7]);
    wa["origin"] = json!("https://webauthn.io/register?x=1");
    wa["user_verified"] = json!(false);
    wa.as_object_mut().unwrap().remove("item_id");
    let r2 = s.sock("passkey-create", wa.clone());
    assert_eq!(r2["ok"], true, "{r2}");
    let (cred2, spki2) = check_attestation(&r2, "webauthn.io", false, -8);
    let new_id = r2["item_id"].as_str().unwrap().to_string();
    let item = &s.ok(&["show", &new_id], None)["item"];
    assert_eq!(
        (&item["title"], &item["username"], &item["urls"]),
        (
            &json!("webauthn.io"),
            &json!("Test User"),
            &json!(["https://webauthn.io"])
        )
    );
    let g2 = s.sock(
        "passkey-get",
        json!({"rp_id": "webauthn.io", "credential_id": cred2, "client_data_hash": hs, "user_verified": true}),
    );
    check_assertion(&g2, "webauthn.io", &h, &spki2, -8, true);

    // the browser's errors
    let count = || s.ok(&["list"], None)["items"].as_array().unwrap().len();
    let before = count();
    let mut ex = base.clone();
    ex["exclude"] = json!([cred]);
    ex.as_object_mut().unwrap().remove("item_id");
    assert_eq!(s.sock("passkey-create", ex)["error"], "excluded");
    let mut rsa = base.clone();
    rsa["algorithms"] = json!([-257]);
    assert_eq!(s.sock("passkey-create", rsa)["error"], "unsupported");
    assert_eq!(count(), before, "a refused create saves nothing");
    for (k, v) in [
        ("rp_id", json!("GitHub.com")),
        ("rp_id", json!("127.0.0.1")),
        ("client_data_hash", json!(b64url(&[1; 31]))),
        ("user_id", json!("")),
        ("algorithms", json!(["ES256"])),
        ("item_id", json!(note)),
    ] {
        let mut bad = base.clone();
        bad[k] = v.clone();
        assert_eq!(
            s.sock("passkey-create", bad)["error"],
            "bad-request",
            "{k} = {v}"
        );
    }
    let mut gone = base.clone();
    gone["item_id"] = json!("00000000-0000-0000-0000-000000000000");
    assert_eq!(s.sock("passkey-create", gone)["error"], "not-found");
    let get = |rp: &str, c: &str| {
        s.sock(
            "passkey-get",
            json!({"rp_id": rp, "credential_id": c, "client_data_hash": hs}),
        )
    };
    assert_eq!(get("github.com", "bm9wZQ")["error"], "not-found");
    assert_eq!(
        get("gitlab.com", &cred)["error"],
        "not-found",
        "another site's passkey"
    );
    assert_eq!(get("github.com", &cred2)["error"], "not-found");

    // the passkeys are in the file: lock, unlock, sign again
    s.ok(&["lock"], None);
    assert_eq!(get("github.com", &cred)["error"], "locked");
    assert_eq!(s.cli(&["passkey", "list"], None)["error"], "locked");
    s.ok(&["unlock"], Some(&format!("{MASTER}\n")));
    check_assertion(
        &get("github.com", &cred),
        "github.com",
        &h,
        &spki,
        -7,
        false,
    );
    assert_eq!(
        s.ok(&["passkey", "list"], None)["passkeys"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    // remove: the fields and the tag go, the login stays
    s.ok(&["edit", &gh, "--remove-passkey"], None);
    let item = &s.ok(&["show", &gh], None)["item"];
    assert_eq!(item["passkey"], Value::Null);
    assert!(!item["tags"].as_array().unwrap().contains(&json!("Passkey")));
    assert_eq!(
        s.cli(
            &[
                "reveal",
                &gh,
                "--field",
                "KPEX_PASSKEY_PRIVATE_KEY_PEM",
                "--json"
            ],
            None
        )["error"],
        "not-found"
    );
    assert_eq!(get("github.com", &cred)["error"], "not-found");
    let left = s.ok(&["passkey", "list", "--rp", "github.com"], None);
    assert_eq!(left["passkeys"][0]["credential_id"], cred3.as_str());
    assert_eq!(
        left["passkeys"].as_array().unwrap().len(),
        1,
        "the other account's stays"
    );
    assert_eq!(
        s.ok(&["reveal", &gh, "--field", "password", "--json"], None)["value"],
        "hunter2"
    );

    // nothing a passkey holds reaches the log
    let log = s.log();
    for secret in [
        cred.as_str(),
        cred2.as_str(),
        cred3.as_str(),
        "github-user-42",
        "PRIVATE KEY",
        "Z2l0aHVi",
    ] {
        assert!(!log.contains(secret), "{secret:?} in the daemon's log");
    }
}
