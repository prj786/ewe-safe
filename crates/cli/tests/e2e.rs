//! The real binaries end to end (docs/PROTOCOL.md). Each test gets a
//! sandbox: its own XDG directories, a fake `ewe-conf` (a JSON file), a
//! fake `ewe-cloud` and clipboard, cheap key derivation, no logind. The
//! mock WebDAV server stands in for Nextcloud. Nothing touches the live
//! keyring, ewe.conf, session or account.
//!
//! Run from the workspace (`cargo test`), which builds both binaries.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use safe_testkit::{Mock, PASS, Proxy, USER};
use serde_json::{Value, json};

const MASTER: &str = "correct horse battery";
const DISCORD_PW: &str = "hunter2-discord-Zq9";
const NOTE_TEXT: &str = "recovery-code-7781";

static N: AtomicUsize = AtomicUsize::new(0);

fn cli_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ewe-safe"))
}

fn daemon_exe() -> PathBuf {
    let p = cli_exe().with_file_name("ewe-safed");
    assert!(
        p.exists(),
        "{} is missing: run `cargo test` from the workspace, which builds it",
        p.display()
    );
    p
}

struct Sandbox {
    root: PathBuf,
    run: PathBuf,
    bin: PathBuf,
    extra: Vec<(String, String)>,
    daemons: Vec<Child>,
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).expect("script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("safe-e2e-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // the socket path must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/se-{}-{n}", std::process::id()));
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
with open(p + ".argv", "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
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
                "#!/bin/sh\necho \"$*\" >> {r}/wl-copy.argv\necho \"$WAYLAND_DISPLAY\" > {r}/wl-copy.display\nif [ \"$1\" = --clear ]; then rm -f {r}/clip; else cat > {r}/clip; fi\n"
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
            extra: Vec::new(),
            daemons: Vec::new(),
        }
    }

    /// Nextcloud through `ewe-cloud`, at this base URL.
    fn cloud(&self, base: &str) {
        write_exec(
            &self.bin.join("ewe-cloud"),
            &format!(
                "#!/bin/sh\ncase \"$1\" in\n  webdav-url) echo '{base}' ;;\n  token) echo '{{\"ok\": true, \"token\": \"{PASS}\", \"user\": \"{USER}\"}}' ;;\nesac\n"
            ),
        );
    }

    fn env(&self) -> Vec<(String, String)> {
        let p = |d: &str| self.root.join(d).display().to_string();
        let mut env = vec![
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
            ("EWE_SAFE_INSECURE_LOOPBACK".into(), "1".into()),
            ("WAYLAND_DISPLAY".into(), "wayland-test".into()),
        ];
        env.extend(self.extra.iter().cloned());
        env
    }

    fn log(&self) -> std::fs::File {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("daemon.log"))
            .expect("log")
    }

    fn start(&mut self) {
        let child = Command::new(daemon_exe())
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(self.log())
            .spawn()
            .expect("ewe-safed");
        self.daemons.push(child);
        self.wait_ready();
    }

    fn wait_ready(&self) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.cli(&["ping"])["ok"] == true {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon didn't answer: {}", self.daemon_log());
    }

    fn stop(&mut self) {
        for mut c in self.daemons.drain(..) {
            term(c.id());
            let _ = c.wait();
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(cli_exe());
        c.args(args).env_clear().envs(self.env());
        c
    }

    /// stdout and the exit code.
    fn raw(&self, args: &[&str], stdin: Option<&str>) -> (String, i32) {
        let mut c = self.command(args);
        c.stdin(if stdin.is_some() {
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

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.root.join("daemon.log")).unwrap_or_default()
    }

    fn init(&self, place: &[&str]) -> Value {
        let mut args = vec!["init"];
        args.extend_from_slice(place);
        let v = self.cli_in(&args, &format!("{MASTER}\n{MASTER}\n"));
        assert_eq!(v["ok"], true, "init: {v}");
        v
    }
}

/// SIGTERM, as systemd stops the service at logout.
fn term(pid: u32) {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
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

fn wait_until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn without_a_daemon_the_cli_says_so_and_generate_still_works() {
    let s = Sandbox::new("no-daemon");
    let v = s.cli(&["status"]);
    assert_eq!(v["error"], "daemon-unavailable");
    let g = s.ok(&["generate", "--length", "24", "--no-symbols"]);
    let pw = g["value"].as_str().unwrap();
    assert_eq!(pw.len(), 24);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    let g = s.ok(&["generate", "--words", "6"]);
    assert_eq!(g["value"].as_str().unwrap().split('-').count(), 6);
    assert_eq!(s.cli(&["frobnicate"])["error"], "bad-request");
}

#[test]
fn a_safe_on_this_computer_from_init_to_restart() {
    let mut s = Sandbox::new("local");
    s.start();
    let st = s.ok(&["status"]);
    assert_eq!(st["set_up"], false);
    assert_eq!(s.cli(&["list"])["error"], "not-set-up");

    let v = s.init(&["--place", "local"]);
    assert_eq!(v["place"]["kind"], "local");
    let file = s.root.join("data/ewe/safe/passwords.kdbx");
    assert!(file.exists(), "the safe is at the default path");
    let st = s.ok(&["status"]);
    assert_eq!(
        (
            st["set_up"].clone(),
            st["locked"].clone(),
            st["items"].clone()
        ),
        (json!(true), json!(false), json!(0))
    );
    assert_eq!(st["sync"]["state"], "local");

    // three items: a login, a note, a generated login pinned to an app
    let a = s.cli_in(
        &[
            "add",
            "--title",
            "Discord",
            "--username",
            "sam",
            "--url",
            "https://discord.com/login",
            "--password-stdin",
        ],
        &format!("{DISCORD_PW}\n"),
    );
    assert_eq!(a["ok"], true, "{a}");
    let new_id = a["item_id"]
        .as_str()
        .expect("add answers item_id")
        .to_string();
    assert_eq!(s.ok(&["show", &new_id])["item"]["title"], "Discord");
    let n = s.cli_in(
        &[
            "add",
            "--kind",
            "note",
            "--title",
            "Recovery codes",
            "--notes-stdin",
        ],
        NOTE_TEXT,
    );
    assert_eq!(n["ok"], true, "{n}");
    s.ok(&[
        "add",
        "--title",
        "Mail",
        "--username",
        "me@example.org",
        "--generate",
        "--words",
        "4",
        "--app",
        "thunderbird",
        "--folder",
        "Work",
    ]);
    assert_eq!(s.titles(), ["Discord", "Mail", "Recovery codes"]);
    assert_eq!(
        s.ok(&["list", "--kind", "note"])["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // the picker's verb
    let m = s.ok(&[
        "match",
        "--class",
        "discord",
        "--title",
        "Discord - General",
    ]);
    assert_eq!(m["items"][0]["title"], "Discord");
    assert_eq!(m["items"][0]["reason"], "site matches the app");
    let m = s.ok(&["match", "--class", "thunderbird"]);
    assert_eq!(m["items"][0]["title"], "Mail");
    assert_eq!(m["items"][0]["score"], 50);
    assert_eq!(m["items"].as_array().unwrap().len(), 2, "logins only");
    assert_eq!(
        s.ok(&["match", "--class", "x", "--limit", "1"])["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(s.ok(&["search", "mail"])["items"][0]["title"], "Mail");

    let discord = s.id_of("Discord");
    let note = s.id_of("Recovery codes");
    let mail = s.id_of("Mail");
    assert_eq!(s.ok(&["show", &mail])["item"]["folder"], "Work");
    assert!(
        s.ok(&["show", &note])["item"].get("notes").is_none(),
        "a note's text needs --reveal-notes"
    );
    assert_eq!(
        s.ok(&["show", &note, "--reveal-notes"])["item"]["notes"],
        NOTE_TEXT
    );

    // reveal: bare for scripts, --json for programs
    assert_eq!(
        s.raw(&["reveal", &discord, "--field", "password"], None),
        (format!("{DISCORD_PW}\n"), 0)
    );
    assert_eq!(
        s.ok(&["reveal", &discord, "--field", "username", "--json"])["value"],
        "sam"
    );
    assert_eq!(
        s.cli(&["reveal", "nope", "--field", "password", "--json"])["error"],
        "not-found"
    );

    // edits; an edit that changes nothing saves nothing
    s.ok(&["edit", &discord, "--username", "sam2", "--app", "discord"]);
    let shown = s.ok(&["show", &discord])["item"].clone();
    assert_eq!(
        (shown["username"].clone(), shown["apps"].clone()),
        (json!("sam2"), json!(["discord"]))
    );
    // the edit is in the cache when it answers; the file (the place) gets it
    // moments later, so wait for that write before measuring — reading the
    // time at once raced it on a slow builder (the 0.2.0-beta package build)
    wait_until(
        "the edit to reach the file",
        Duration::from_secs(10),
        || s.ok(&["status"])["sync"]["pending"] == json!(false),
    );
    let mut before = std::fs::metadata(&file).unwrap().modified().unwrap();
    wait_until("the file to settle", Duration::from_secs(10), || {
        std::thread::sleep(Duration::from_millis(300));
        let now = std::fs::metadata(&file).unwrap().modified().unwrap();
        std::mem::replace(&mut before, now) == now
    });
    std::thread::sleep(Duration::from_millis(1100));
    s.ok(&["edit", &discord, "--app", "Discord"]);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        std::fs::metadata(&file).unwrap().modified().unwrap(),
        before,
        "nothing to save"
    );
    s.ok(&["edit", &discord, "--remove-app", "discord"]);
    assert_eq!(s.ok(&["show", &discord])["item"]["apps"], json!([]));

    // the recycle bin
    s.ok(&["rm", &note]);
    assert_eq!(s.titles(), ["Discord", "Mail"]);
    assert_eq!(
        s.ok(&["list", "--deleted"])["items"][0]["title"],
        "Recovery codes"
    );
    s.ok(&["restore", &note]);
    assert_eq!(s.titles(), ["Discord", "Mail", "Recovery codes"]);

    // copy, then the clipboard clears itself (only while it's still ours)
    let c = s.ok(&["copy", &discord, "--clear-after", "1"]);
    assert_eq!(c["cleared_after"], 1);
    assert_eq!(
        std::fs::read_to_string(s.root.join("clip")).unwrap(),
        DISCORD_PW
    );
    assert_eq!(
        std::fs::read_to_string(s.root.join("wl-copy.display"))
            .unwrap()
            .trim(),
        "wayland-test"
    );
    assert!(
        s.run.join("ewe-clip-skip").exists(),
        "the history gate's marker"
    );
    wait_until("the clipboard to clear", Duration::from_secs(5), || {
        !s.root.join("clip").exists()
    });
    s.ok(&["copy", &discord, "--clear-after", "1"]);
    std::fs::write(s.root.join("clip"), "something the user copied since").unwrap();
    std::thread::sleep(Duration::from_millis(1800));
    assert!(s.root.join("clip").exists(), "a newer copy is left alone");

    // lock: nothing readable, the bare reveal prints nothing and exits 1
    assert_eq!(s.ok(&["lock"])["locked"], true);
    let st = s.ok(&["status"]);
    assert_eq!(
        (st["locked"].clone(), st["items"].clone()),
        (json!(true), Value::Null)
    );
    for verb in [
        &["list"][..],
        &["match", "--class", "x"],
        &["search", "x"],
        &["show", &discord],
    ] {
        assert_eq!(s.cli(verb)["error"], "locked", "{verb:?}");
    }
    assert_eq!(
        s.raw(&["reveal", &discord, "--field", "password"], None),
        (String::new(), 1)
    );
    assert_eq!(
        s.cli_in(&["unlock"], "wrong password\n")["error"],
        "wrong-key"
    );
    assert_eq!(s.cli_in(&["unlock"], &format!("{MASTER}\n"))["items"], 3);

    // a new master password
    let p = s.cli_in(&["passwd"], "new master 2\nnew master 2\n");
    assert_eq!(p["ok"], true, "{p}");
    s.ok(&["lock"]);
    assert_eq!(
        s.cli_in(&["unlock"], &format!("{MASTER}\n"))["error"],
        "wrong-key"
    );
    assert_eq!(s.cli_in(&["unlock"], "new master 2\n")["ok"], true);

    // a restart keeps the safe, locked
    s.stop();
    s.start();
    let st = s.ok(&["status"]);
    assert_eq!(
        (st["set_up"].clone(), st["locked"].clone()),
        (json!(true), json!(true))
    );
    s.cli_in(&["unlock"], "new master 2\n");
    assert_eq!(s.titles(), ["Discord", "Mail", "Recovery codes"]);
    assert_eq!(
        s.raw(&["reveal", &discord, "--field", "password"], None)
            .0
            .trim(),
        DISCORD_PW
    );

    // the other machines learn where the safe lives, through ewe-conf
    let conf = std::fs::read_to_string(s.root.join("config/fake-ewe-conf.json")).unwrap();
    assert!(conf.contains("\"place\": \"local\""), "{conf}");

    // nothing secret, and no title or username, outside the encrypted files
    s.stop();
    let mut seen = String::new();
    for f in walk(&s.root) {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "kdbx" || f.starts_with(s.root.join("bin")) || f.ends_with("clip") {
            continue;
        }
        seen.push_str(&String::from_utf8_lossy(&std::fs::read(&f).unwrap()));
    }
    for secret in [
        MASTER,
        "new master 2",
        DISCORD_PW,
        NOTE_TEXT,
        "Discord",
        "Recovery codes",
        "sam2",
        "me@example.org",
    ] {
        assert!(
            !seen.contains(secret),
            "{secret:?} leaked into the sandbox's plain files"
        );
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Two machines on one Nextcloud: each edits offline, both edits survive.
#[test]
fn two_machines_on_one_nextcloud() {
    let mock = Mock::start();
    let (pa, pb) = (Proxy::start(mock.port()), Proxy::start(mock.port()));
    let mut a = Sandbox::new("nc-a");
    let mut b = Sandbox::new("nc-b");
    a.cloud(&pa.base());
    b.cloud(&pb.base());
    a.start();
    b.start();

    let v = a.init(&["--place", "nextcloud"]);
    assert_eq!(v["place"]["kind"], "nextcloud");
    assert_eq!(v["place"]["location"], "ewe/safe/passwords.kdbx");
    assert_eq!(v["place"]["guarded"], true, "the mock refuses a stale save");
    assert_eq!(v["sync"]["state"], "in-sync");
    assert_eq!(
        a.cli_in(
            &["init", "--place", "nextcloud"],
            &format!("{MASTER}\n{MASTER}\n")
        )["error"],
        "place-error",
        "one safe per machine"
    );
    a.ok(&[
        "add",
        "--title",
        "Shared",
        "--username",
        "both",
        "--generate",
    ]);
    a.ok(&["sync"]);
    assert_eq!(a.ok(&["status"])["sync"]["state"], "in-sync");

    // the second machine opens it (a wrong password leaves nothing behind)
    assert_eq!(
        b.cli_in(&["open", "--place", "nextcloud"], "not it\n")["error"],
        "wrong-key"
    );
    assert_eq!(b.ok(&["status"])["set_up"], false);
    let o = b.cli_in(&["open", "--place", "nextcloud"], &format!("{MASTER}\n"));
    assert_eq!(o["items"], 1, "{o}");

    // both offline, both edit
    pa.offline();
    pb.offline();
    a.ok(&["add", "--title", "FromA", "--username", "a", "--generate"]);
    b.ok(&["add", "--title", "FromB", "--username", "b", "--generate"]);
    let shared = b.id_of("Shared");
    b.ok(&["edit", &shared, "--username", "changed-on-b"]);
    a.ok(&["sync"]);
    let st = a.ok(&["status"])["sync"].clone();
    assert_eq!(
        (st["state"].clone(), st["pending"].clone()),
        (json!("offline"), json!(true)),
        "{st}"
    );

    // back online: both edits survive on both machines
    pa.online();
    pb.online();
    a.ok(&["sync"]);
    b.ok(&["sync"]);
    a.ok(&["sync"]);
    let want = ["FromA", "FromB", "Shared"];
    assert_eq!(a.titles(), want);
    assert_eq!(b.titles(), want);
    for m in [&a, &b] {
        let shared = m.id_of("Shared");
        assert_eq!(m.ok(&["show", &shared])["item"]["username"], "changed-on-b");
        let st = m.ok(&["status"])["sync"].clone();
        assert_eq!(
            (st["state"].clone(), st["pending"].clone()),
            (json!("in-sync"), json!(false)),
            "{st}"
        );
    }
    assert_eq!(
        a.ok(&["status"])["sync"]["by_machine"],
        b.ok(&["status"])["sync"]["by_machine"]
    );
}

/// `status`, `summary`, `match` and `list` answer from memory while the
/// place hangs; `lock` doesn't wait for it either.
#[test]
fn the_fast_path_answers_while_the_place_hangs() {
    let mock = Mock::start();
    let mut s = Sandbox::new("hang");
    s.cloud(&mock.base());
    s.start();
    s.init(&["--place", "nextcloud"]);
    s.ok(&[
        "add",
        "--title",
        "GitHub",
        "--username",
        "sam",
        "--generate",
    ]);
    s.ok(&["sync"]);

    mock.set(|i| i.hang = true);
    let env = s.env();
    let hung = std::thread::spawn(move || {
        Command::new(cli_exe())
            .arg("sync")
            .env_clear()
            .envs(env)
            .output()
            .expect("sync")
    });
    std::thread::sleep(Duration::from_millis(300));
    for verb in [
        &["status"][..],
        &["summary"],
        &["match", "--class", "github"],
        &["list"],
    ] {
        let t = Instant::now();
        s.ok(verb);
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "{verb:?} took {:?}",
            t.elapsed()
        );
    }
    let t = Instant::now();
    s.ok(&["lock"]);
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "lock took {:?}",
        t.elapsed()
    );
    assert_eq!(s.ok(&["summary"])["locked"], true);
    mock.set(|i| i.hang = false);
    let out = hung.join().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "the sync that waited still answers: {v}");
}

#[test]
fn a_second_daemon_is_refused() {
    let mut s = Sandbox::new("twice");
    s.start();
    let out = Command::new(daemon_exe())
        .env_clear()
        .envs(s.env())
        .output()
        .expect("second daemon");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already answers"));
    s.ok(&["ping"]);
}

#[test]
fn socket_activation() {
    let activate = Path::new("/usr/bin/systemd-socket-activate");
    if !activate.exists() {
        eprintln!("systemd-socket-activate isn't here: skipped");
        return;
    }
    let mut s = Sandbox::new("activated");
    let mut c = Command::new(activate);
    c.arg("-l").arg(s.run.join("ewe-safe.sock"));
    for (k, _) in s.env() {
        c.arg("-E").arg(k);
    }
    c.arg(daemon_exe())
        .env_clear()
        .envs(s.env())
        .stdout(Stdio::null())
        .stderr(s.log());
    s.daemons.push(c.spawn().expect("systemd-socket-activate"));
    wait_until("the activated socket", Duration::from_secs(5), || {
        s.run.join("ewe-safe.sock").exists()
    });
    s.wait_ready();
    s.ok(&["status"]);
    assert!(
        s.daemon_log().contains("socket activation"),
        "{}",
        s.daemon_log()
    );
}

#[test]
fn the_socket_speaks_protocol_one() {
    let mut s = Sandbox::new("protocol");
    s.start();
    let sock = UnixStream::connect(s.run.join("ewe-safe.sock")).expect("connect");
    let mut rd = BufReader::new(sock.try_clone().unwrap());
    let mut wr = sock;
    let mut ask = |line: &str| -> Value {
        wr.write_all(line.as_bytes()).unwrap();
        wr.write_all(b"\n").unwrap();
        let mut reply = String::new();
        rd.read_line(&mut reply).unwrap();
        serde_json::from_str(&reply).unwrap()
    };
    let v = ask(r#"{"v":1,"id":7,"verb":"version"}"#);
    assert_eq!(
        (v["id"].clone(), v["v"].clone(), v["protocol"].clone()),
        (json!(7), json!(1), json!(1))
    );
    assert_eq!(
        ask(r#"{"v":2,"id":8,"verb":"ping"}"#)["error"],
        "bad-request"
    );
    let v = ask("this is not json");
    assert_eq!(
        (v["error"].clone(), v["id"].clone()),
        (json!("bad-request"), Value::Null)
    );
    assert_eq!(
        ask(r#"{"v":1,"id":9,"verb":"nope"}"#)["error"],
        "bad-request"
    );
    assert_eq!(
        ask(r#"{"v":1,"id":10,"verb":"unlock","args":{"ask":true}}"#)["error"],
        "bad-request"
    );
    // several requests on one connection
    assert_eq!(ask(r#"{"v":1,"id":11,"verb":"ping"}"#)["pong"], true);

    // a subscriber hears what happens, never a title
    let sub = UnixStream::connect(s.run.join("ewe-safe.sock")).expect("connect");
    let mut sub_rd = BufReader::new(sub.try_clone().unwrap());
    let mut sub_wr = sub;
    sub_wr
        .write_all(b"{\"v\":1,\"id\":1,\"verb\":\"subscribe\"}\n")
        .unwrap();
    let mut first = String::new();
    sub_rd.read_line(&mut first).unwrap();
    assert!(first.contains("subscribed"));
    s.init(&["--place", "local"]);
    s.ok(&["add", "--title", "Secret Title", "--username", "u"]);
    s.ok(&["lock"]);
    let mut events = Vec::new();
    sub_wr.set_read_timeout(Some(Duration::from_secs(5))).ok();
    while events.len() < 5 {
        let mut l = String::new();
        if sub_rd.read_line(&mut l).unwrap_or(0) == 0 {
            break;
        }
        assert!(!l.contains("Secret Title"), "an event carried a title: {l}");
        events.push(serde_json::from_str::<Value>(&l).unwrap());
        if events.last().unwrap()["event"] == "locked" {
            break;
        }
    }
    let names: Vec<&str> = events.iter().filter_map(|e| e["event"].as_str()).collect();
    assert!(
        names.contains(&"unlocked") && names.contains(&"changed"),
        "{names:?}"
    );
    let locked = events
        .iter()
        .find(|e| e["event"] == "locked")
        .expect("locked");
    assert_eq!(locked["reason"], "user");
}

/// The Passwords plugin's Enter: a prompt opens, the user unlocks there.
#[test]
fn unlock_ask_waits_for_the_prompt() {
    let mut s = Sandbox::new("ask");
    s.start();
    s.init(&["--place", "local"]);
    s.ok(&["lock"]);
    let me = cli_exe().display().to_string();
    s.extra.push((
        "EWE_SAFE_ASK_CMD".into(),
        format!("sleep 0.5; printf '{MASTER}\\n' | {me} unlock"),
    ));
    let v = s.ok(&["unlock", "--ask"]);
    assert_eq!(v["items"], 0);
    s.ok(&["lock"]);
    s.extra = vec![("EWE_SAFE_ASK_CMD".into(), "true".into())];
    assert_eq!(s.cli(&["unlock", "--ask"])["error"], "cancelled");
    // already unlocked: no prompt at all
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));
    s.extra = vec![("EWE_SAFE_ASK_CMD".into(), "exit 1".into())];
    assert_eq!(s.ok(&["unlock", "--ask"])["items"], 0);
}

#[test]
fn an_unused_safe_locks_itself() {
    let mut s = Sandbox::new("idle");
    s.extra = vec![
        ("EWE_SAFE_IDLE_SECONDS".into(), "2".into()),
        ("EWE_SAFE_SYNC_SECONDS".into(), "1".into()),
    ];
    s.start();
    s.init(&["--place", "local"]);
    assert_eq!(s.ok(&["status"])["locked"], false);
    wait_until("the idle lock", Duration::from_secs(8), || {
        s.ok(&["status"])["locked"] == true
    });
    // the daemon drops the key first and logs after clearing the clipboard,
    // so on a slow runner the line can trail the status by a moment
    wait_until("the idle lock in the log", Duration::from_secs(5), || {
        s.daemon_log().contains("locked (idle)")
    });
}

// ── login unlock (docs/SYSTEM.md §2) ───────────────────────────────────────

const LOGIN_PW: &str = "login-pw-7781";

/// A sandbox set up for login unlock: a cheap login KDF, and a fake
/// `unix_chkpwd` that accepts `EWE_FAKE_LOGIN_PW` (the daemon's own
/// NoNewPrivileges blocks the real setuid helper; the CLI runs it).
fn login_sandbox(name: &str) -> Sandbox {
    let mut s = Sandbox::new(name);
    let chk = s.bin.join("chkpwd");
    write_exec(
        &chk,
        "#!/bin/sh\n# unix_chkpwd stand-in: the password is all of stdin, no newline\n[ \"$(cat)\" = \"$EWE_FAKE_LOGIN_PW\" ] && exit 0 || exit 7\n",
    );
    s.extra = vec![
        ("EWE_SAFE_LOGIN_KDF".into(), "64,1,1".into()),
        ("EWE_SAFE_CHKPWD".into(), chk.display().to_string()),
        ("EWE_FAKE_LOGIN_PW".into(), LOGIN_PW.into()),
    ];
    s.start();
    s
}

fn safe_state(s: &Sandbox) -> PathBuf {
    s.root.join("state/ewe/safe")
}

#[test]
fn login_unlock_enable_unlock_disable() {
    let s = login_sandbox("login-roundtrip");
    s.init(&["--place", "local"]);
    // off to start with
    let st = s.ok(&["login", "status"]);
    assert_eq!(st["enabled"], false);
    assert_eq!(s.ok(&["status"])["unlock_methods"], json!(["password"]));

    // enable: the safe is unlocked, so only the login password is needed
    let en = s.cli_in(&["login", "enable"], &format!("{LOGIN_PW}\n"));
    assert_eq!(en["ok"], true, "enable: {en}");
    assert_eq!(en["enabled"], true);
    assert!(
        safe_state(&s).join("login.key").exists(),
        "login.key written"
    );
    assert!(
        safe_state(&s).join("master.wrap").exists(),
        "master.wrap written"
    );

    // status now shows the method
    let st = s.ok(&["status"]);
    assert_eq!(st["unlock_methods"], json!(["password", "login"]));
    assert_eq!(st["login"]["enabled"], true);
    assert_eq!(st["login"]["session_open"], true);

    // the wrong login password is refused; it isn't the master password either
    s.cli(&["lock"]);
    assert_eq!(
        s.cli_in(&["unlock", "--login"], &format!("{MASTER}\n"))["error"],
        "wrong-key"
    );
    // the right login password opens the safe with no master password
    let u = s.cli_in(&["unlock", "--login"], &format!("{LOGIN_PW}\n"));
    assert_eq!(u["ok"], true, "login unlock: {u}");
    assert_eq!(s.ok(&["status"])["locked"], false);

    // disable: master.wrap goes, the method with it
    let di = s.ok(&["login", "disable"]);
    assert_eq!(di["enabled"], false);
    assert!(
        !safe_state(&s).join("master.wrap").exists(),
        "master.wrap removed"
    );
    assert_eq!(s.ok(&["status"])["unlock_methods"], json!(["password"]));
    assert_eq!(s.ok(&["login", "status"])["enabled"], false);
}

#[test]
fn enable_refuses_a_wrong_login_password() {
    let s = login_sandbox("login-chkpwd");
    s.init(&["--place", "local"]);
    // the fake chkpwd rejects anything but LOGIN_PW, so enable never reaches
    // the daemon and nothing is written
    let en = s.cli_in(&["login", "enable"], "not-my-login\n");
    assert_eq!(en["error"], "wrong-key", "{en}");
    assert!(!safe_state(&s).join("master.wrap").exists());
    assert_eq!(s.ok(&["login", "status"])["enabled"], false);
}

#[test]
fn five_wrong_login_tries_lock_until_the_master_password() {
    let s = login_sandbox("login-tries");
    s.init(&["--place", "local"]);
    s.cli_in(&["login", "enable"], &format!("{LOGIN_PW}\n"));
    s.cli(&["lock"]);
    for n in 1..=4 {
        assert_eq!(
            s.cli_in(&["unlock", "--login"], "wrong\n")["error"],
            "wrong-key",
            "try {n}"
        );
    }
    // the fifth wrong try trips the limit, and it stays tripped
    assert_eq!(
        s.cli_in(&["unlock", "--login"], "wrong\n")["error"],
        "too-many-tries"
    );
    assert_eq!(
        s.cli_in(&["unlock", "--login"], &format!("{LOGIN_PW}\n"))["error"],
        "too-many-tries",
        "a correct login password is still refused while tripped"
    );
    // the master password clears it
    assert_eq!(s.cli_in(&["unlock"], &format!("{MASTER}\n"))["ok"], true);
    s.cli(&["lock"]);
    assert_eq!(
        s.cli_in(&["unlock", "--login"], &format!("{LOGIN_PW}\n"))["ok"],
        true,
        "login unlock works again after the master password"
    );
}

#[test]
fn a_changed_master_password_is_re_sealed_and_login_still_opens() {
    let s = login_sandbox("login-reseal");
    s.init(&["--place", "local"]);
    s.cli_in(&["login", "enable"], &format!("{LOGIN_PW}\n"));
    // change the master password here: master.wrap is re-sealed with it
    let new_master = "a-new-master-9Qx";
    let p = s.cli_in(&["passwd"], &format!("{new_master}\n{new_master}\n"));
    assert_eq!(p["ok"], true, "passwd: {p}");
    s.cli(&["lock"]);
    // login unlock opens the safe at the new master password, no prompt for it
    let u = s.cli_in(&["unlock", "--login"], &format!("{LOGIN_PW}\n"));
    assert_eq!(u["ok"], true, "login unlock after master change: {u}");
}

#[test]
fn a_stale_master_wrap_gives_key_changed_and_is_dropped() {
    let s = login_sandbox("login-keychanged");
    s.init(&["--place", "local"]);
    s.cli_in(&["login", "enable"], &format!("{LOGIN_PW}\n"));
    s.cli(&["lock"]);
    // stand in for "the master changed on another machine": re-seal
    // master.wrap under the real W but a master that no longer opens the safe
    let dir = safe_state(&s);
    let w = safe_login::open_key(&dir.join(safe_login::LOGIN_KEY), LOGIN_PW.as_bytes())
        .expect("open login.key");
    safe_login::seal_master(&dir.join(safe_login::MASTER_WRAP), &w, "stale-master").unwrap();
    let u = s.cli_in(&["unlock", "--login"], &format!("{LOGIN_PW}\n"));
    assert_eq!(u["error"], "key-changed", "{u}");
    assert!(
        !dir.join(safe_login::MASTER_WRAP).exists(),
        "a stale master.wrap is deleted"
    );
    // the master password still opens it
    assert_eq!(s.cli_in(&["unlock"], &format!("{MASTER}\n"))["ok"], true);
}

#[test]
fn confirm_takes_the_master_or_the_login_password() {
    let s = login_sandbox("login-confirm");
    s.init(&["--place", "local"]);
    // unlocked: the master password confirms
    let c = s.cli_in(&["confirm"], &format!("{MASTER}\n"));
    assert_eq!(c["ok"], true, "{c}");
    assert!(c["confirmed_for"].as_u64().unwrap() > 290);
    assert_eq!(
        s.cli_in(&["confirm"], "not-the-master\n")["error"],
        "wrong-key"
    );
    // with login unlock on, the login password confirms too
    s.cli_in(&["login", "enable"], &format!("{LOGIN_PW}\n"));
    assert_eq!(
        s.cli_in(&["confirm", "--login"], &format!("{LOGIN_PW}\n"))["ok"],
        true
    );
    assert_eq!(
        s.cli_in(&["confirm", "--login"], "wrong-login\n")["error"],
        "wrong-key"
    );
    // locked: nothing to confirm
    s.cli(&["lock"]);
    assert_eq!(
        s.cli_in(&["confirm"], &format!("{MASTER}\n"))["error"],
        "locked"
    );
}

#[test]
fn login_unlock_is_off_until_enabled() {
    let s = login_sandbox("login-not-enabled");
    s.init(&["--place", "local"]);
    s.cli(&["lock"]);
    // no master.wrap yet: a login unlock has nothing to open
    assert_eq!(
        s.cli_in(&["unlock", "--login"], &format!("{LOGIN_PW}\n"))["error"],
        "not-enabled"
    );
}
