//! `import` and `watch` with the real binaries (docs/PROTOCOL.md,
//! docs/IMPORT.md). Each test gets a sandbox like tests/e2e.rs: its own XDG
//! directories, a fake `ewe-conf`, cheap key derivation, no logind; `op` is
//! tests/import/fake-op answering from the fixtures, named by
//! `EWE_SAFE_OP` so a real op on the PATH is never run. Never a real
//! account, the live keyring or ewe.conf.
//!
//! The written safe is read back with pykeepass (an independent reader):
//! `SAFE_TEST_PYTHON` names a Python that has it (CI installs it into
//! `python3`); without one that check is skipped, loudly.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const MASTER: &str = "correct horse battery";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/import");
/// Every secret the fixtures hold.
const SECRETS: &[&str] = &[
    "Disc-pw-Zq9!",
    "old-disc-1",
    "4242",
    "JBSWY3DPEHPK3PXP",
    "router-pw-55",
    "4111111111111111",
    "baa-baa-77",
    "forum-pw",
    "OPENSSH PRIVATE",
    "gh-pw-X7",
    "bank-pw-1",
    "BACKUP-CODES",
];

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
        let root = std::env::temp_dir().join(format!("safe-imp-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // the socket path must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/si-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let bin = root.join("bin");
        for d in [&root, &run, &bin] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        for d in ["state", "config", "data", "home/Downloads"] {
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
        Sandbox {
            root,
            run,
            bin,
            daemons: Vec::new(),
        }
    }

    /// `op` on the PATH: the fake, answering from the fixtures.
    fn with_op(&self) {
        std::fs::copy(format!("{FIXTURES}/fake-op"), self.bin.join("op")).expect("op");
        std::fs::set_permissions(self.bin.join("op"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
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
            // the real op (this machine may have one) is never run: this
            // path is the fake once `with_op` puts it there, nothing before
            (
                "EWE_SAFE_OP".into(),
                self.bin.join("op").display().to_string(),
            ),
            (
                "FAKE_OP_FIXTURE".into(),
                format!("{FIXTURES}/fixtures/op.json"),
            ),
            ("FAKE_OP_LOG".into(), p("op.argv")),
        ]
    }

    fn start(&mut self) {
        self.start_with(&[]);
    }

    fn start_with(&mut self, extra: &[(&str, &str)]) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("daemon.log"))
            .expect("log");
        let child = Command::new(cli_exe().with_file_name("ewe-safed"))
            .env_clear()
            .envs(self.env())
            .envs(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())))
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
        let mut child = Command::new(cli_exe())
            .args(args)
            .env_clear()
            .envs(self.env())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("ewe-safe");
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

    fn init(&self) {
        let v = self.cli_in(
            &["init", "--place", "local"],
            &format!("{MASTER}\n{MASTER}\n"),
        );
        assert_eq!(v["ok"], true, "init: {v}");
    }

    fn titles(&self) -> Vec<String> {
        let mut t: Vec<String> = self.ok(&["list"])["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["title"].as_str().unwrap().to_string())
            .collect();
        t.sort();
        t
    }

    fn id_of(&self, title: &str) -> String {
        self.ok(&["list"])["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["title"] == title)
            .unwrap_or_else(|| panic!("no {title}"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Wait until the last edit has reached the place (the cache has it
    /// when the answer comes; the place a moment later).
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

    fn safe_file(&self) -> PathBuf {
        self.root.join("data/ewe/safe/passwords.kdbx")
    }

    /// The export where a user's browser puts it.
    fn download(&self, name: &str) -> String {
        let to = self.root.join("home/Downloads").join(name);
        std::fs::copy(format!("{FIXTURES}/fixtures/{name}"), &to).expect("copy");
        to.display().to_string()
    }

    /// No file in the sandbox but the exports holds a secret in plain text.
    fn assert_no_plaintext(&self) {
        let mut stack = vec![self.root.clone(), self.run.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let p = e.path();
                if p.starts_with(self.root.join("home/Downloads")) || p.starts_with(&self.bin) {
                    continue;
                }
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(bytes) = std::fs::read(&p) {
                    for s in SECRETS {
                        assert!(
                            !bytes.windows(s.len()).any(|w| w == s.as_bytes()),
                            "{} holds {s} in plain text",
                            p.display()
                        );
                    }
                }
            }
        }
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

const READ_BACK: &str = r#"
import json, sys
from pykeepass import PyKeePass
kp = PyKeePass(sys.argv[1], password=sys.argv[2])
out = {}
for e in kp.entries:
    if e.group.name == "Recycle Bin":
        continue
    out[e.title] = {
        "group": "/".join(e.group.path) if e.group.path else "",
        "username": e.username, "password": e.password, "url": e.url,
        "notes": e.notes, "otp": e.otp, "tags": e.tags or [],
        "custom": e.custom_properties,
        "history": [h.password for h in e.history],
        "attachments": {a.filename: a.data.decode("latin-1") for a in e.attachments},
    }
print(json.dumps(out))
"#;

/// The safe file as pykeepass reads it, or None (and a note) without it.
fn read_back(file: &Path) -> Option<Value> {
    let python = std::env::var("SAFE_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    let has = Command::new(&python)
        .args(["-c", "import pykeepass"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !has {
        eprintln!("NOTE: no pykeepass in {python}: the independent read-back is skipped");
        return None;
    }
    let out = Command::new(&python)
        .args(["-I", "-c", READ_BACK])
        .arg(file)
        .arg(MASTER)
        .output()
        .expect("python");
    assert!(
        out.status.success(),
        "pykeepass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(serde_json::from_slice(&out.stdout).expect("json"))
}

#[test]
fn a_1pux_export_comes_in_whole_and_nothing_lies_around() {
    let mut s = Sandbox::new("1pux");
    s.start();
    s.init();
    let file = s.download("sample.1pux");

    // locked: nothing is read
    s.ok(&["lock"]);
    assert_eq!(s.cli(&["import", "1pux", &file])["error"], "locked");
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));

    // already here: the same site and username as the export's Discord
    let a = s.cli_in(
        &[
            "add",
            "--title",
            "My Discord",
            "--username",
            "SAM",
            "--url",
            "https://www.discord.com",
            "--password-stdin",
        ],
        "already-here\n",
    );
    assert_eq!(a["ok"], true, "{a}");

    // a dry run changes nothing (once the add has reached the place)
    s.settled();
    let before = std::fs::metadata(s.safe_file())
        .unwrap()
        .modified()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let dry = s.ok(&["import", "1pux", &file, "--dry-run"]);
    assert_eq!(dry["dry_run"], true);
    let r = &dry["report"];
    assert_eq!(
        (
            r["logins"].clone(),
            r["notes"].clone(),
            r["duplicates"].clone()
        ),
        (json!(4), json!(3), json!(1))
    );
    // 1Password's Credit Card and Identity (docs/IMPORT.md)
    assert_eq!(
        (r["cards"].clone(), r["addresses"].clone()),
        (json!(1), json!(1))
    );
    assert_eq!(s.titles(), ["My Discord"]);
    assert_eq!(
        std::fs::metadata(s.safe_file())
            .unwrap()
            .modified()
            .unwrap(),
        before,
        "nothing saved"
    );

    // the import: one save, the hint to delete the export
    let v = s.ok(&["import", "1pux", &file]);
    let r = &v["report"];
    assert_eq!(
        (
            r["logins"].clone(),
            r["notes"].clone(),
            r["otps"].clone(),
            r["attachments"].clone(),
            r["duplicates"].clone()
        ),
        (json!(4), json!(3), json!(2), json!(2), json!(1))
    );
    assert_eq!(
        (r["cards"].clone(), r["addresses"].clone()),
        (json!(1), json!(1))
    );
    assert_eq!(r["folders"], json!(["Archive", "Personal", "Work"]));
    assert!(v["hint"].as_str().unwrap().contains("Delete the export"));
    // the cache has it when the answer comes, the place a moment later
    assert!(
        matches!(v["sync"]["state"].as_str(), Some("pending" | "local")),
        "{}",
        v["sync"]
    );
    let skipped: Vec<&str> = r["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["title"].as_str().unwrap())
        .collect();
    assert!(skipped.contains(&"Thrown away"));
    assert!(skipped.contains(&"GitHub — missing.txt"));
    let shown = v.to_string();
    for secret in SECRETS {
        assert!(!shown.contains(secret), "the reply shows {secret}");
    }
    assert_eq!(s.titles().len(), 10);

    let discord = s.id_of("Discord");
    assert_eq!(
        s.raw(&["reveal", &discord, "--field", "password"], None),
        ("Disc-pw-Zq9!\n".to_string(), 0)
    );
    let shown = s.ok(&["show", &discord])["item"].clone();
    assert_eq!(shown["folder"], "Personal");
    assert_eq!(shown["urls"].as_array().unwrap().len(), 3);
    assert_eq!(shown["has_otp"], true);

    // the independent reader sees every field
    if let Some(kp) = read_back(&s.safe_file()) {
        let d = &kp["Discord"];
        assert_eq!(d["group"], "Personal");
        assert_eq!(d["username"], "sam");
        assert_eq!(d["password"], "Disc-pw-Zq9!");
        assert_eq!(d["url"], "https://discord.com/login");
        assert_eq!(d["custom"]["KP2A_URL_1"], "https://discordapp.com");
        assert_eq!(d["custom"]["KP2A_URL_2"], "https://canary.discord.com");
        assert_eq!(d["custom"]["Security: PIN"], "4242");
        assert!(
            d["otp"]
                .as_str()
                .unwrap()
                .starts_with("otpauth://totp/Discord")
        );
        assert_eq!(d["history"], json!(["old-disc-1", "old-disc-2"]));
        assert_eq!(
            d["attachments"]["backup-codes.txt"],
            "BACKUP-CODES 1111 2222\n"
        );
        assert_eq!(d["tags"], json!(["chat", "Favorite"]));
        assert_eq!(kp["Visa"]["notes"], "Daily card");
        assert_eq!(kp["Visa"]["custom"]["Number"], "4111111111111111");
        assert_eq!(kp["Visa"]["custom"]["Expiry"], "04/2027");
        assert_eq!(kp["Sam Shepherd"]["custom"]["City"], "Ewetown");
        assert_eq!(kp["Old forum"]["group"], "Archive");
        assert_eq!(
            kp["Passport scan"]["attachments"]["passport.pdf"],
            "%PDF-1.4 fake\n"
        );
        assert_eq!(kp["GitHub"]["group"], "Work");
    }

    // again, skipping duplicates: what is already here stays out
    let again = s.ok(&["import", "1pux", &file, "--skip-duplicates"]);
    let r = &again["report"];
    assert!(r["duplicates"].as_u64().unwrap() >= 3, "{r}");
    assert!(
        r["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["title"] == "Discord")
    );

    s.assert_no_plaintext();
    let log = std::fs::read_to_string(s.root.join("daemon.log")).unwrap_or_default();
    assert!(
        log.contains("imported 4 logins and 3 notes, 1 cards, 1 addresses (1pux)"),
        "{log}"
    );
    for t in ["Discord", "Visa", "sam"] {
        assert!(!log.contains(t), "the log names {t}");
    }
}

#[test]
fn a_csv_export_and_the_1password_app_through_op() {
    let mut s = Sandbox::new("csv-op");
    s.start();
    s.init();
    let file = s.download("1password.csv");
    let v = s.ok(&["import", "1password-csv", &file]);
    assert_eq!(v["report"]["logins"], 2);
    assert_eq!(v["report"]["folders"], json!(["Archive"]));
    let bank = s.id_of("Bank");
    assert_eq!(
        s.ok(&["reveal", &bank, "--field", "password", "--json"])["value"],
        "bank-pw-1"
    );
    assert_eq!(
        s.cli(&["import", "1password-csv", &s.download("sample.1pux")])["error"],
        "source-error",
        "a zip is no CSV"
    );

    // no op installed: a hint to install it
    let e = s.cli(&["import", "op", "--dry-run"]);
    assert_eq!(e["error"], "source-error");
    assert!(e["hint"].as_str().unwrap().contains("1password-cli"));

    s.with_op();
    let one = s.ok(&["import", "op", "--vault", "Work", "--dry-run"]);
    assert_eq!(
        (
            one["report"]["logins"].clone(),
            one["report"]["notes"].clone(),
            one["report"]["cards"].clone(),
            one["report"]["addresses"].clone()
        ),
        (json!(0), json!(0), json!(1), json!(1))
    );
    assert!(one.get("hint").is_none(), "no export file to delete");
    let all = s.ok(&["import", "op"]);
    let r = &all["report"];
    assert_eq!(
        (
            r["logins"].clone(),
            r["notes"].clone(),
            r["attachments"].clone()
        ),
        (json!(2), json!(1), json!(2))
    );
    assert_eq!(r["folders"], json!(["Archive", "Personal", "Work"]));
    let discord = s.id_of("Discord");
    assert_eq!(
        s.ok(&["reveal", &discord, "--field", "Security: PIN", "--json"])["value"],
        "4242"
    );
    assert_eq!(
        s.ok(&["show", &s.id_of("Old forum")])["item"]["folder"],
        "Archive"
    );
    // op is asked by id, never handed a value
    let argv = std::fs::read_to_string(s.root.join("op.argv")).unwrap();
    assert!(argv.contains("item get i3 --vault v1 --format json --include-archive"));
    assert!(argv.contains("document get i2 --vault v1"));
    assert!(argv.contains("read --no-newline op://v1/i1/f1"));
    for secret in SECRETS {
        assert!(!argv.contains(secret));
    }
    assert_eq!(
        s.cli(&["import", "op", "--vault", "Nope"])["error"],
        "bad-request"
    );

    // op's own words when it fails
    s.stop();
    s.start_with(&[("FAKE_OP_FAIL", "1")]);
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));
    let e = s.cli(&["import", "op"]);
    assert_eq!(e["error"], "source-error");
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("authorization prompt dismissed")
    );
    s.assert_no_plaintext();
}

/// Lines from a child's stdout, as they come.
fn lines_of(child: &mut Child) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for l in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                return;
            }
        }
    });
    rx
}

/// The next line whose event is `want`, skipping others.
fn wait_event(rx: &mpsc::Receiver<String>, want: &str) -> Value {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if let Ok(l) = rx.recv_timeout(Duration::from_millis(200)) {
            let v: Value = serde_json::from_str(&l).unwrap_or_else(|_| panic!("not JSON: {l}"));
            assert_eq!(v["v"], 1, "every line is protocol 1: {l}");
            if v["event"] == want {
                return v;
            }
        }
    }
    panic!("no {want} event");
}

#[test]
fn watch_prints_status_then_events_then_daemon_gone() {
    let mut s = Sandbox::new("watch");
    // no daemon: one line, and done
    let (out, code) = s.raw(&["watch"], None);
    assert_eq!(code, 0);
    assert_eq!(
        serde_json::from_str::<Value>(out.trim()).unwrap(),
        json!({"v": 1, "event": "daemon-gone"})
    );

    s.start();
    s.init();
    let mut w = Command::new(cli_exe())
        .arg("watch")
        .env_clear()
        .envs(s.env())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("watch");
    let rx = lines_of(&mut w);
    let first: Value =
        serde_json::from_str(&rx.recv_timeout(Duration::from_secs(10)).expect("a line")).unwrap();
    assert_eq!(first["v"], 1);
    assert_eq!(first["event"], "status", "the first line: {first}");
    assert_eq!(first["status"]["ok"], true);
    assert_eq!(first["status"]["set_up"], true);
    assert_eq!(first["status"]["locked"], false);

    s.ok(&["lock"]);
    assert_eq!(wait_event(&rx, "locked")["reason"], "user");
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));
    wait_event(&rx, "unlocked");
    let a = s.cli_in(&["add", "--title", "Bank", "--password-stdin"], "pw\n");
    assert_eq!(a["ok"], true);
    let changed = wait_event(&rx, "changed");
    assert!(
        !changed.to_string().contains("Bank"),
        "no title in an event"
    );

    s.stop();
    wait_event(&rx, "daemon-gone");
    let start = Instant::now();
    loop {
        if let Some(st) = w.try_wait().expect("wait") {
            assert!(st.success(), "watch exits 0");
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "watch didn't exit"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
