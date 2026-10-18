//! Cards and addresses with the real binaries (docs/SYSTEM.md §4,
//! docs/PROTOCOL.md): add, edit, show, reveal and list over the CLI, the
//! browser's `fields` over the socket with the card gate on and off,
//! `convert`, and the saved file opened again. Each test gets a sandbox
//! like tests/e2e.rs: its own XDG directories (a short runtime directory),
//! a fake `ewe-conf`, cheap key derivation, no logind. Never the live
//! session, keyring or ewe.conf.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const MASTER: &str = "correct horse battery";
const NUMBER: &str = "4242424242424242";
const CODE: &str = "731";
const PIN: &str = "9876";

static N: AtomicUsize = AtomicUsize::new(0);

fn cli_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ewe-safe"))
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).expect("script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

struct Sandbox {
    root: PathBuf,
    run: PathBuf,
    bin: PathBuf,
    daemons: Vec<Child>,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("safe-cards-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // the socket path must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/sc-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let bin = root.join("bin");
        for d in [&root, &run, &bin] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        for d in ["state", "config", "data", "home"] {
            std::fs::create_dir_all(root.join(d)).expect("mkdir");
        }
        write_exec(
            &bin.join("ewe-conf"),
            r#"#!/usr/bin/env python3
import json, os, sys
p = os.path.join(os.environ["XDG_CONFIG_HOME"], "fake-ewe-conf.json")
try:
    d = json.load(open(p))
except Exception:
    d = {}
a = sys.argv[1:]
if a[:2] == ["get", "safe"]:
    if "safe" in d:
        print(json.dumps(d["safe"]))
    else:
        print(json.dumps({"error": "no-key", "key": "safe"}))
        sys.exit(1)
elif a and a[0] == "set":
    d.setdefault("safe", {})[a[1].split(".", 1)[1]] = a[2]
    json.dump(d, open(p, "w"))
"#,
        );
        let r = root.display();
        write_exec(
            &bin.join("wl-copy"),
            &format!(
                "#!/bin/sh\nif [ \"$1\" = --clear ]; then rm -f {r}/clip; else cat > {r}/clip; fi\n"
            ),
        );
        write_exec(
            &bin.join("wl-paste"),
            &format!("#!/bin/sh\ncat {r}/clip 2>/dev/null\n"),
        );
        Sandbox {
            root,
            run,
            bin,
            daemons: Vec::new(),
        }
    }

    /// `[safe]` as the fake ewe-conf answers it (before the daemon starts).
    fn conf(&self, safe: Value) {
        std::fs::write(
            self.root.join("config/fake-ewe-conf.json"),
            json!({"safe": safe}).to_string(),
        )
        .expect("conf");
    }

    fn env(&self) -> Vec<(String, String)> {
        let p = |d: &str| self.root.join(d).display().to_string();
        vec![
            ("HOME".into(), p("home")),
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", self.bin.display()),
            ),
            ("XDG_RUNTIME_DIR".into(), self.run.display().to_string()),
            ("XDG_STATE_HOME".into(), p("state")),
            ("XDG_CONFIG_HOME".into(), p("config")),
            ("XDG_DATA_HOME".into(), p("data")),
            ("EWE_SAFE_NO_LOGIND".into(), "1".into()),
            ("EWE_SAFE_KDF_ITERATIONS".into(), "2".into()),
            (
                "EWE_SAFE_OP".into(),
                self.bin.join("op").display().to_string(),
            ),
            ("WAYLAND_DISPLAY".into(), "wayland-test".into()),
        ]
    }

    fn start(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("daemon.log"))
            .expect("log");
        let child = Command::new(cli_exe().with_file_name("ewe-safed"))
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("ewe-safed (run cargo test from the workspace)");
        self.daemons.push(child);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.cli(&["ping"])["ok"] == true {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon didn't answer");
    }

    fn stop(&mut self) {
        for mut c in self.daemons.drain(..) {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
    }

    fn raw(&self, args: &[&str], stdin: Option<&str>) -> (String, i32) {
        let mut c = Command::new(cli_exe());
        c.args(args)
            .env_clear()
            .envs(self.env())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = c.spawn().expect("ewe-safe");
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().expect("wait");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }

    fn cli_in(&self, args: &[&str], stdin: &str) -> Value {
        let (out, code) = self.raw(args, Some(stdin));
        assert_eq!(code, 0, "{args:?} exits 0");
        serde_json::from_str(&out).unwrap_or_else(|_| panic!("{args:?} printed {out:?}"))
    }

    fn cli(&self, args: &[&str]) -> Value {
        let (out, code) = self.raw(args, None);
        assert_eq!(code, 0, "{args:?} exits 0");
        serde_json::from_str(&out).unwrap_or_else(|_| panic!("{args:?} printed {out:?}"))
    }

    fn ok(&self, args: &[&str]) -> Value {
        let v = self.cli(args);
        assert_eq!(v["ok"], true, "{args:?}: {v}");
        v
    }

    fn ok_in(&self, args: &[&str], stdin: &str) -> Value {
        let v = self.cli_in(args, stdin);
        assert_eq!(v["ok"], true, "{args:?}: {v}");
        v
    }

    fn init(&self) {
        let v = self.cli_in(
            &["init", "--place", "local"],
            &format!("{MASTER}\n{MASTER}\n"),
        );
        assert_eq!(v["ok"], true, "init: {v}");
    }

    /// One request on the socket (`fields` is socket only).
    fn socket(&self, verb: &str, args: Value) -> Value {
        let sock = UnixStream::connect(self.run.join("ewe-safe.sock")).expect("connect");
        let mut rd = BufReader::new(sock.try_clone().unwrap());
        let mut wr = sock;
        let req = json!({"v": 1, "id": 9, "verb": verb, "args": args});
        wr.write_all(format!("{req}\n").as_bytes()).unwrap();
        let mut reply = String::new();
        rd.read_line(&mut reply).unwrap();
        serde_json::from_str(&reply).expect("a JSON reply")
    }

    fn settled(&self) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.ok(&["status"])["sync"]["pending"] == false {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the edit never reached the place");
    }

    fn reveal(&self, id: &str, field: &str) -> Value {
        self.ok(&["reveal", id, "--field", field, "--json"])["value"].clone()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.run);
        if std::env::var_os("SAFE_E2E_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

/// No secret of the card in a reply that isn't a reveal.
fn no_secrets(what: &str, v: &Value) {
    let shown = v.to_string();
    for s in [NUMBER, "4242 4242", &format!("\"{CODE}\""), PIN] {
        assert!(!shown.contains(s), "{what} shows {s}: {shown}");
    }
}

fn add_card(s: &Sandbox) -> String {
    let v = s.ok_in(
        &[
            "add",
            "--kind",
            "card",
            "--holder",
            "Sam Moe",
            "--expiry",
            "8/29",
            "--tag",
            "money",
            "--card-stdin",
            "--notes-stdin",
        ],
        &format!("4242 4242 4242 4242\n{CODE}\n{PIN}\nfor travel\n"),
    );
    assert!(v.get("warning").is_none(), "a good number: {v}");
    no_secrets("add", &v);
    v["item_id"].as_str().unwrap().to_string()
}

fn add_address(s: &Sandbox) -> String {
    s.ok(&[
        "add",
        "--kind",
        "address",
        "--full-name",
        "Sam Moe",
        "--line1",
        "12 Main St",
        "--city",
        "Tbilisi",
        "--postal-code",
        "0105",
        "--country",
        "ge",
        "--phone",
        "+995 555 00 00 00",
        "--email",
        "sam@example.org",
    ])["item_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn cards_and_addresses_from_the_cli_and_the_socket() {
    let mut s = Sandbox::new("cli");
    s.start();
    s.init();
    let card = add_card(&s);
    let home = add_address(&s);
    s.ok(&[
        "add",
        "--title",
        "Bank",
        "--username",
        "sam",
        "--password-stdin",
    ]);

    // lists: a kind each, and never a secret
    let cards = s.ok(&["list", "--kind", "card"]);
    no_secrets("list --kind card", &cards);
    let items = cards["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let c = &items[0];
    assert_eq!(c["id"], card.as_str());
    assert_eq!(c["kind"], "card");
    assert_eq!(c["title"], "Visa •• 4242", "the default title");
    assert_eq!(
        c["card"],
        json!({"brand": "visa", "last4": "4242", "expiry": "08/2029", "holder": "Sam Moe",
               "has_number": true, "has_security_code": true, "has_pin": true})
    );
    assert_eq!(
        (c["has_password"].clone(), c["address"].clone()),
        (json!(false), Value::Null)
    );
    let addrs = s.ok(&["list", "--kind", "address"])["items"].clone();
    assert_eq!(addrs.as_array().unwrap().len(), 1);
    assert_eq!(addrs[0]["title"], "Home");
    assert_eq!(
        addrs[0]["address"],
        json!({"name": "Sam Moe", "line1": "12 Main St", "city": "Tbilisi", "country": "GE"})
    );
    let all = s.ok(&["list"]);
    no_secrets("list", &all);
    assert_eq!(all["items"].as_array().unwrap().len(), 3);
    assert_eq!(
        s.ok(&["list", "--kind", "login"])["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(s.cli(&["list", "--kind", "cards"])["error"], "bad-request");
    no_secrets("search", &s.ok(&["search", "visa"]));
    assert_eq!(s.ok(&["search", "4242"])["items"][0]["id"], card.as_str());
    assert!(
        s.ok(&["search", NUMBER])["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.ok(&["search", "tbilisi"])["items"][0]["id"],
        home.as_str()
    );
    let m = s.ok(&["match", "--query", "visa"]);
    assert!(
        m["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["kind"] == "login"),
        "the fill picker offers logins only: {m}"
    );
    no_secrets("status", &s.ok(&["status"]));

    // show: no secret; an address's every part
    let shown = s.ok(&["show", &card]);
    no_secrets("show", &shown);
    assert!(
        shown["item"].get("notes").is_none(),
        "a card's notes are protected"
    );
    assert_eq!(
        s.ok(&["show", &card, "--reveal-notes"])["item"]["notes"],
        "for travel\n"
    );
    let a = s.ok(&["show", &home])["item"]["address"].clone();
    assert_eq!(a["postal_code"], "0105");
    assert_eq!(a["phone"], "+995 555 00 00 00");
    assert_eq!(a["line2"], "");

    // reveal: the protocol's names and the KDBX names
    assert_eq!(s.reveal(&card, "number"), NUMBER);
    assert_eq!(s.reveal(&card, "security_code"), CODE);
    assert_eq!(s.reveal(&card, "Security code"), CODE);
    assert_eq!(s.reveal(&card, "pin"), PIN);
    assert_eq!(s.reveal(&card, "Cardholder"), "Sam Moe");
    assert_eq!(s.reveal(&home, "city"), "Tbilisi");
    assert_eq!(
        s.raw(&["reveal", &card, "--field", "number"], None),
        (format!("{NUMBER}\n"), 0)
    );
    let copied = s.ok(&["copy", &card, "--field", "number", "--clear-after", "0"]);
    assert_eq!(copied["copied"], "number");
    assert_eq!(
        std::fs::read_to_string(s.root.join("clip")).unwrap(),
        NUMBER
    );

    // edit: only what is sent changes; "" clears; a blank stdin line keeps
    // its value and "-" clears it
    let e = s.ok_in(
        &["edit", &card, "--holder", "S MOE", "--card-stdin"],
        "\n\n-\n",
    );
    no_secrets("edit", &e);
    assert_eq!(s.reveal(&card, "number"), NUMBER);
    assert_eq!(s.reveal(&card, "security_code"), CODE);
    assert_eq!(
        s.cli(&["reveal", &card, "--field", "pin", "--json"])["error"],
        "not-found"
    );
    let c = s.ok(&["show", &card])["item"]["card"].clone();
    assert_eq!(
        (c["holder"].clone(), c["has_pin"].clone()),
        (json!("S MOE"), json!(false))
    );
    // a new number: the brand and a default title follow it; a typo warns
    let e = s.ok_in(
        &["edit", &card, "--card-stdin"],
        "5555 5555 5555 4445\n\n\n",
    );
    assert!(e["warning"].as_str().unwrap().contains("card check"), "{e}");
    let c = s.ok(&["show", &card])["item"].clone();
    assert_eq!(c["title"], "Mastercard •• 4445");
    assert_eq!(c["card"]["brand"], "mastercard");
    // an edit that changes nothing saves nothing
    assert!(s.ok(&["edit", &card, "--holder", "S MOE"])["sync"].is_object());
    s.ok(&["edit", &home, "--line2", "Flat 3", "--country", "Georgia"]);
    let a = s.ok(&["show", &home])["item"]["address"].clone();
    assert_eq!(
        (a["line2"].clone(), a["country"].clone()),
        (json!("Flat 3"), json!("Georgia"))
    );

    // mistakes are bad requests, and say why
    for (args, stdin) in [
        (vec!["edit", card.as_str(), "--expiry", "13/29"], ""),
        (vec!["edit", card.as_str(), "--brand", "laser"], ""),
        (vec!["edit", card.as_str(), "--card-stdin"], "42x\n\n\n"),
        (vec!["edit", home.as_str(), "--holder", "x"], ""),
        (vec!["edit", card.as_str(), "--city", "x"], ""),
        (
            vec!["add", "--kind", "login", "--title", "x", "--holder", "y"],
            "",
        ),
        (vec!["add", "--kind", "planet"], ""),
    ] {
        let v = s.cli_in(&args, stdin);
        assert_eq!(v["error"], "bad-request", "{args:?}: {v}");
        no_secrets("an error", &v);
    }

    // the browser's fields: the gate is on by default and nothing was
    // confirmed (`confirm` is stream L's verb)
    let f = s.socket("fields", json!({"item_id": card}));
    assert_eq!(f["error"], "confirm-needed", "{f}");
    assert_eq!(f["hint"], "ewe-safe confirm --ask");
    assert!(f["message"].as_str().unwrap().ends_with('.'));
    no_secrets("confirm-needed", &f);
    let f = s.socket("fields", json!({"item_id": home}));
    assert_eq!(f["ok"], true, "{f}");
    assert_eq!(f["kind"], "address");
    assert_eq!(
        (
            f["fields"]["given_name"].clone(),
            f["fields"]["family_name"].clone()
        ),
        (json!("Sam"), json!("Moe"))
    );
    assert_eq!(f["fields"]["line2"], "Flat 3");
    let login = s.ok(&["list", "--kind", "login"])["items"][0]["id"].clone();
    assert_eq!(
        s.socket("fields", json!({"item_id": login}))["error"],
        "bad-request"
    );
    s.ok(&["lock"]);
    assert_eq!(
        s.socket("fields", json!({"item_id": card}))["error"],
        "locked"
    );
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));

    // the file itself: open it again (another computer's view)
    s.settled();
    s.stop();
    let file = s.root.join("data/ewe/safe/passwords.kdbx");
    let back = safe_core::Safe::open_file(&file, &safe_core::safe::key(MASTER, None).unwrap())
        .expect("the saved safe opens");
    let e = back
        .database()
        .iter_all_entries()
        .find(|e| e.id().to_string() == card)
        .expect("the card");
    assert_eq!(e.get("Number"), Some("5555555555554445"));
    assert!(e.fields["Number"].is_protected() && e.fields["Security code"].is_protected());
    assert_eq!(e.get("Brand"), Some("mastercard"));
    assert!(e.get("PIN").is_none());
    let sum = back.summary(&home).unwrap();
    assert_eq!(sum.address.unwrap().city, "Tbilisi");
    // nothing in the sandbox holds the number in plain text
    let mut stack = vec![s.root.clone()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n != "clip")
                && let Ok(bytes) = std::fs::read(&p)
            {
                for secret in ["5555555555554445", NUMBER, "Sam Moe", "Tbilisi"] {
                    assert!(
                        !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                        "{} holds {secret} in plain text",
                        p.display()
                    );
                }
            }
        }
    }
    let log = std::fs::read_to_string(s.root.join("daemon.log")).unwrap_or_default();
    for t in ["Sam", "Visa", "Tbilisi", "4242"] {
        assert!(!log.contains(t), "the log names {t}");
    }
}

#[test]
fn with_the_gate_off_the_browser_gets_the_card_but_never_its_pin() {
    let mut s = Sandbox::new("gate-off");
    s.conf(json!({"confirm_cards": false}));
    s.start();
    s.init();
    let card = add_card(&s);
    let f = s.socket("fields", json!({"item_id": card}));
    assert_eq!(f["ok"], true, "{f}");
    assert_eq!(
        f["fields"],
        json!({"holder": "Sam Moe", "number": NUMBER, "expiry_month": "08",
               "expiry_year": "2029", "security_code": CODE, "brand": "visa"})
    );
    assert!(!f.to_string().contains(PIN), "never the PIN");
    // the recycle bin's items are never filled
    s.ok(&["rm", &card]);
    assert_eq!(
        s.socket("fields", json!({"item_id": card}))["error"],
        "not-found"
    );
}

#[test]
fn convert_turns_an_earlier_imports_notes_into_cards_and_addresses() {
    use safe_core::import::{Batch, Field, Imported, Options};
    use safe_core::{Draft, Kind, Safe};
    use zeroize::Zeroizing;

    let mut s = Sandbox::new("convert");
    // a safe as 0.2's import left it: a Credit Card and an Identity as Notes
    let note = |title: &str, text: &str, fields: Vec<(&str, &str)>| Imported {
        folder: "Personal".into(),
        draft: Draft {
            kind: Kind::Note,
            title: title.into(),
            notes: Zeroizing::new(text.into()),
            ..Draft::default()
        },
        fields: fields
            .into_iter()
            .map(|(n, v)| Field {
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
    let mut safe = Safe::create("Safe", safe_core::kdf::argon2id(2));
    safe.import(
        &Batch {
            items: vec![
                note(
                    "Visa",
                    "Credit card\ncardholder name: Sam Shepherd\ntype: visa\nnumber: 4111111111111111\nverification number: 123\nexpiry date: 2027-04\n\nDaily card",
                    vec![("number", "4111111111111111"), ("verification number", "123")],
                ),
                note(
                    "Sam",
                    "Identity\nIdentification\nfirst name: Sam\nlast name: Shepherd\n\nAddress\naddress:\n  1 Hill Rd\n  Ewetown, 9012\n  nz",
                    vec![],
                ),
                note("Store card", "Credit card\nshop: Wool & Co", vec![]),
            ],
            skipped: Vec::new(),
        },
        &Options::default(),
    )
    .expect("import");
    let file = s.root.join("data").join("old.kdbx");
    safe.write_file(&file, &safe_core::safe::key(MASTER, None).unwrap())
        .expect("write");
    s.start();
    let o = s.cli_in(
        &[
            "open",
            "--place",
            "local",
            "--location",
            file.to_str().unwrap(),
        ],
        &format!("{MASTER}\n"),
    );
    assert_eq!(o["ok"], true, "{o}");
    assert_eq!(
        s.cli(&["convert"])["error"],
        "bad-request",
        "the source is named"
    );

    let dry = s.ok(&["convert", "--from-1password", "--dry-run"]);
    assert_eq!(dry["dry_run"], true);
    let kinds: Vec<(String, String)> = dry["converted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["title"].as_str().unwrap().into(),
                c["kind"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("Sam".into(), "address".into()),
            ("Visa".into(), "card".into())
        ]
    );
    assert_eq!(
        dry["skipped"],
        json!([{"title": "Store card", "reason": "Safe found no card number in it"}])
    );
    assert_eq!(
        s.ok(&["list", "--kind", "note"])["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let done = s.ok(&["convert", "--from-1password"]);
    no_secrets("convert", &done);
    assert!(done["sync"].is_object());
    let card = s.ok(&["list", "--kind", "card"])["items"][0].clone();
    assert_eq!(card["title"], "Visa");
    assert_eq!(card["card"]["last4"], "1111");
    assert_eq!(card["card"]["expiry"], "04/2027");
    let id = card["id"].as_str().unwrap();
    assert_eq!(s.reveal(id, "number"), "4111111111111111");
    assert_eq!(s.reveal(id, "notes"), "Daily card");
    let a = s.ok(&["list", "--kind", "address"])["items"][0]["address"].clone();
    assert_eq!(
        a,
        json!({"name": "Sam Shepherd", "line1": "1 Hill Rd", "city": "Ewetown", "country": "NZ"})
    );
    assert!(
        s.ok(&["convert", "--from-1password"])["converted"]
            .as_array()
            .unwrap()
            .is_empty(),
        "nothing left to convert"
    );
}
