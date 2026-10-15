//! SSH keys and the agent end to end (TRIO.md S2, docs/PROTOCOL.md "SSH
//! keys"): the real `ewe-safe` and `ewe-safed` in a sandbox (their own XDG
//! directories, a fake `ewe-conf`, cheap key derivation, no logind), and
//! OpenSSH's own `ssh-add` and `ssh-keygen` talking to the sandbox's agent
//! socket. Every OpenSSH tool runs with a cleared environment: the sandbox's
//! HOME and SSH_AUTH_SOCK only, never `~/.ssh` or the session's agent.
//!
//! The approval prompt is `EWE_SAFE_APPROVE_CMD`, a script that answers
//! what the test writes to a file; the unlock prompt is `EWE_SAFE_ASK_CMD`.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const MASTER: &str = "correct horse battery";
const KEY_PASS: &str = "laptop-passphrase-31";

static N: AtomicUsize = AtomicUsize::new(0);

fn cli_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ewe-safe"))
}

fn daemon_exe() -> PathBuf {
    let p = cli_exe().with_file_name("ewe-safed");
    assert!(
        p.exists(),
        "{} is missing: run `cargo build --workspace` first",
        p.display()
    );
    p
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).expect("script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

struct Sandbox {
    root: PathBuf,
    run: PathBuf,
    bin: PathBuf,
    extra: Vec<(String, String)>,
    daemon: Option<Child>,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("safe-ssh-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // the socket paths must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/s2-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let bin = root.join("bin");
        for d in [&root, &run, &bin] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        for d in ["state", "config", "data", "home", "keys", "pub"] {
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
        // the approval prompt: logs who asked for what, answers with the
        // file `answer` ("0" allow, "1" deny, "sleep" never answers)
        let r = root.display();
        write_exec(
            &bin.join("approve"),
            &format!(
                "#!/bin/sh\necho \"$EWE_SAFE_APPROVE_APP|$EWE_SAFE_APPROVE_KEY|$EWE_SAFE_APPROVE_PATH|$EWE_SAFE_APPROVE_SYSTEM\" >> {r}/approvals\na=$(cat {r}/answer 2>/dev/null)\n[ \"$a\" = sleep ] && exec sleep 30\nexit \"${{a:-1}}\"\n"
            ),
        );
        let me = cli_exe().display().to_string();
        let s = Sandbox {
            extra: vec![
                (
                    "EWE_SAFE_APPROVE_CMD".into(),
                    bin.join("approve").display().to_string(),
                ),
                ("EWE_SAFE_PROMPT_SECONDS".into(), "3".into()),
                (
                    "EWE_SAFE_ASK_CMD".into(),
                    format!("printf '{MASTER}\\n' | {me} unlock"),
                ),
            ],
            root,
            run,
            bin,
            daemon: None,
        };
        s.answer("0");
        s
    }

    fn answer(&self, a: &str) {
        std::fs::write(self.root.join("answer"), a).expect("answer");
    }

    fn approvals(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.join("approvals"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn agent(&self) -> PathBuf {
        self.run.join("ewe-safe-ssh.sock")
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
            ("WAYLAND_DISPLAY".into(), "wayland-test".into()),
        ];
        env.extend(self.extra.iter().cloned());
        env
    }

    fn start(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("daemon.log"))
            .expect("log");
        let child = Command::new(daemon_exe())
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("ewe-safed");
        self.daemon = Some(child);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.cli(&["ping"])["ok"] == true && self.agent().exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon didn't answer: {}", self.daemon_log());
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.daemon.take() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
    }

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.root.join("daemon.log")).unwrap_or_default()
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

    /// An OpenSSH tool on the sandbox's agent, nothing of the session's.
    fn openssh(&self, prog: &str, args: &[&str], stdin: Option<&[u8]>) -> (String, String, i32) {
        let mut c = Command::new(prog);
        c.args(args)
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("SSH_AUTH_SOCK", self.agent())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap_or_else(|e| panic!("{prog}: {e}"));
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let out = child.wait_with_output().expect("wait");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }

    /// `ssh-add -L`'s lines (none when the agent has no key).
    fn listed(&self) -> Vec<String> {
        let (out, _, _) = self.openssh("ssh-add", &["-L"], None);
        out.lines()
            .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-"))
            .map(str::to_string)
            .collect()
    }

    /// A key made by ssh-keygen in the sandbox: (private file, public line).
    fn keygen(&self, name: &str, args: &[&str], pass: &str) -> (PathBuf, String) {
        let f = self.root.join("keys").join(name);
        let mut a = vec!["-q", "-N", pass, "-f", f.to_str().unwrap()];
        a.extend_from_slice(args);
        let (_, err, code) = self.openssh("ssh-keygen", &a, None);
        assert_eq!(code, 0, "ssh-keygen: {err}");
        let public = std::fs::read_to_string(f.with_extension("pub")).expect("pub");
        (f, public.trim().to_string())
    }

    /// `ssh-keygen -Y sign` through the agent (only the public key is on
    /// disk where it looks), then `-Y verify`. Whether both worked.
    fn sign_and_verify(&self, public: &str) -> bool {
        self.sign_with("ssh-keygen", public)
    }

    /// The same, signed by `prog` (a copy of ssh-keygen, say).
    fn sign_with(&self, prog: &str, public: &str) -> bool {
        let pubfile = self.root.join("pub").join("key.pub");
        std::fs::write(&pubfile, format!("{public}\n")).unwrap();
        let data = self.root.join("pub").join("data.txt");
        std::fs::write(&data, b"commit 1234\n").unwrap();
        let sig = data.with_extension("txt.sig");
        let _ = std::fs::remove_file(&sig);
        let (_, err, code) = self.openssh(
            prog,
            &[
                "-Y",
                "sign",
                "-f",
                pubfile.to_str().unwrap(),
                "-n",
                "file",
                data.to_str().unwrap(),
            ],
            None,
        );
        if code != 0 {
            eprintln!("sign: {err}");
            return false;
        }
        let signers = self.root.join("pub").join("allowed_signers");
        std::fs::write(&signers, format!("sam {public}\n")).unwrap();
        let (_, err, code) = self.openssh(
            "ssh-keygen",
            &[
                "-Y",
                "verify",
                "-f",
                signers.to_str().unwrap(),
                "-I",
                "sam",
                "-n",
                "file",
                "-s",
                sig.to_str().unwrap(),
            ],
            Some(b"commit 1234\n"),
        );
        assert_eq!(code, 0, "a signature the agent made verifies: {err}");
        true
    }

    fn init(&self) {
        let v = self.cli_in(
            &["init", "--place", "local"],
            &format!("{MASTER}\n{MASTER}\n"),
        );
        assert_eq!(v["ok"], true, "init: {v}");
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

/// The key part of a public line (no comment).
fn bare(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn keys_come_in_and_the_agent_signs_with_them() {
    let mut s = Sandbox::new("agent");
    s.start();
    s.init();

    let st = s.ok(&["ssh", "status"]);
    assert_eq!(
        (st["enabled"].clone(), st["listening"].clone()),
        (json!(false), json!(true))
    );
    assert_eq!(st["confirm"], "first-use");
    let mode = std::fs::metadata(s.agent()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "the agent's socket is private");

    // keys in: a new one, a file, a file with a passphrase
    let made = s.ok(&["ssh", "new", "--title", "GitHub key"]);
    let gh_public = made["ssh"]["public_key"].as_str().unwrap().to_string();
    assert!(gh_public.starts_with("ssh-ed25519 "), "{made}");
    assert!(made["item_id"].is_string());
    let (ec_file, ec_public) = s.keygen("id_ecdsa", &["-t", "ecdsa", "-C", "sam@laptop"], "");
    let ec = s.ok(&["ssh", "add", ec_file.to_str().unwrap()]);
    assert_eq!(ec["ssh"]["key_type"], "ecdsa");
    assert_eq!(
        bare(ec["ssh"]["public_key"].as_str().unwrap()),
        bare(&ec_public)
    );
    let (rsa_file, rsa_public) = s.keygen(
        "id_rsa",
        &["-t", "rsa", "-b", "2048", "-C", "old box"],
        KEY_PASS,
    );
    let wrong = s.cli_in(
        &[
            "ssh",
            "add",
            rsa_file.to_str().unwrap(),
            "--title",
            "Old box",
        ],
        "not it\n",
    );
    assert_eq!(wrong["error"], "bad-request", "{wrong}");
    let rsa = s.cli_in(
        &[
            "ssh",
            "add",
            rsa_file.to_str().unwrap(),
            "--title",
            "Old box",
            "--passphrase-stdin",
        ],
        &format!("{KEY_PASS}\n"),
    );
    assert_eq!(rsa["ok"], true, "{rsa}");
    let again = s.cli(&["ssh", "add", ec_file.to_str().unwrap()]);
    assert_eq!(
        again["error"], "bad-request",
        "a key comes in once: {again}"
    );
    // only the kinds the agent signs with come in
    let (p521, _) = s.keygen("id_p521", &["-t", "ecdsa", "-b", "521"], "");
    let no = s.cli(&["ssh", "add", p521.to_str().unwrap()]);
    assert_eq!(no["error"], "bad-request", "{no}");
    assert!(no["message"].as_str().unwrap().contains("nistp521"), "{no}");
    // a file bigger than a key isn't even read
    let big = s.root.join("keys").join("big");
    std::fs::write(&big, vec![b'a'; 2 * 1024 * 1024]).unwrap();
    let no = s.cli(&["ssh", "add", big.to_str().unwrap()]);
    assert!(no["message"].as_str().unwrap().contains("too big"), "{no}");
    // no public-key list while the agent is off
    let cache = s.root.join("state/ewe/safe/ssh-public.json");
    assert!(!cache.exists());

    let keys = s.ok(&["ssh", "list"]);
    let titles: Vec<&str> = keys["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["GitHub key", "Old box", "sam@laptop"]);
    assert!(keys["items"].as_array().unwrap().iter().all(|i| {
        i["kind"] == "ssh-key"
            && i["ssh"]["fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("SHA256:")
            && i["ssh"]["agent"] == true
    }));
    assert_eq!(
        s.ok(&["list", "--kind", "ssh-key"])["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(
        s.ok(&["list", "--kind", "login"])["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        s.ok(&["match", "--query", "github"])["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // off until enabled
    assert!(s.listed().is_empty(), "the agent is off");
    let en = s.ok(&["ssh", "enable"]);
    assert_eq!(
        (en["enabled"].clone(), en["recorded"].clone()),
        (json!(true), json!(true))
    );
    let env_file = s.root.join("config/environment.d/90-ewe-safe-ssh.conf");
    assert_eq!(en["env_file"], json!(env_file));
    assert!(
        std::fs::read_to_string(&env_file)
            .unwrap()
            .contains("SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/ewe-safe-ssh.sock")
    );
    assert_eq!(
        en["identity_agent"],
        format!("IdentityAgent {}", s.agent().display())
    );
    let listed = s.listed();
    assert_eq!(listed.len(), 3, "{listed:?}");
    for (public, title) in [
        (&gh_public, "GitHub key"),
        (&ec_public, "sam@laptop"),
        (&rsa_public, "Old box"),
    ] {
        assert!(
            listed
                .iter()
                .any(|l| bare(l) == bare(public) && l.ends_with(title)),
            "{title} in {listed:?}"
        );
    }
    let st = s.cli_in(&["ssh", "status"], "");
    assert_eq!(st["keys"], 3);

    // every kind of key signs through the agent; the first use asks
    assert!(s.sign_and_verify(&gh_public), "ed25519");
    assert!(s.sign_and_verify(&ec_public), "ecdsa");
    assert!(
        s.sign_and_verify(&rsa_public),
        "rsa-sha2-512, with the key's passphrase"
    );
    let asked = s.approvals();
    assert_eq!(asked.len(), 3, "{asked:?}");
    let first: Vec<&str> = asked[0].split('|').collect();
    assert!(
        first[0].starts_with("ssh-keygen (from "),
        "the app: {asked:?}"
    );
    assert_eq!(first[1], "GitHub key", "the key");
    assert!(
        first[2].starts_with("/usr/bin/ssh-keygen, started by "),
        "the full path: {asked:?}"
    );
    assert!(
        first[2].ends_with("(not a system program)"),
        "the test's own binary"
    );
    assert_eq!(first[3], "0");

    // first use only: a no now changes nothing until the safe locks
    s.answer("1");
    assert!(s.sign_and_verify(&gh_public), "remembered");
    assert_eq!(s.approvals().len(), 3);
    s.ok(&["lock"]);
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));
    assert!(!s.sign_and_verify(&gh_public), "denied after the lock");
    assert_eq!(s.approvals().len(), 4);

    // no answer in time is a no
    s.answer("sleep");
    let start = Instant::now();
    assert!(!s.sign_and_verify(&ec_public), "timed out");
    assert!(start.elapsed() < Duration::from_secs(20));
    s.answer("0");

    // an approval is for the program's file: a lookalike outside the
    // system's folders is asked about and marked, the same file under
    // another name is remembered, a replaced file is asked about again
    let n = s.approvals().len();
    let copy = s.root.join("keys").join("git");
    std::fs::copy("/usr/bin/ssh-keygen", &copy).unwrap();
    assert!(s.sign_with(copy.to_str().unwrap(), &gh_public));
    let asked = s.approvals();
    assert_eq!(asked.len(), n + 1);
    let last: Vec<&str> = asked[n].split('|').collect();
    assert!(last[0].starts_with("git (from "), "{last:?}");
    assert!(
        last[2].starts_with(&format!("{} (not a system program)", copy.display())),
        "{last:?}"
    );
    let moved = s.root.join("keys").join("git2");
    std::fs::rename(&copy, &moved).unwrap();
    assert!(s.sign_with(moved.to_str().unwrap(), &gh_public));
    assert_eq!(s.approvals().len(), n + 1, "the same file: remembered");
    let fresh = s.root.join("keys").join("git3");
    std::fs::copy("/usr/bin/ssh-keygen", &fresh).unwrap();
    std::fs::rename(&fresh, &moved).unwrap();
    assert!(s.sign_with(moved.to_str().unwrap(), &gh_public));
    assert_eq!(s.approvals().len(), n + 2, "a replaced file asks again");

    // never asking is allowed, with a warning, and logged
    let en = s.ok(&["ssh", "enable", "--confirm", "never"]);
    assert!(
        en["warning"]
            .as_str()
            .unwrap()
            .contains("without a question"),
        "{en}"
    );
    assert!(s.ok(&["ssh", "status"])["warning"].is_string());
    let n = s.approvals().len();
    s.answer("1");
    assert!(s.sign_and_verify(&rsa_public), "never asks");
    assert_eq!(s.approvals().len(), n);
    assert!(
        s.daemon_log()
            .contains("without asking (ssh_confirm = never)")
    );
    let en = s.ok(&["ssh", "enable", "--confirm", "first-use"]);
    assert!(en.get("warning").is_none());
    s.answer("0");

    // locked: the keys are still listed, from the public-key list
    s.ok(&["lock"]);
    let text = std::fs::read_to_string(&cache).expect("the public-key list");
    assert!(!text.contains("PRIVATE"), "public keys only");
    assert_eq!(
        std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(s.listed().len(), 3, "listed while locked");
    // a signature while locked opens the unlock prompt and waits for it
    assert!(s.sign_and_verify(&ec_public), "unlocked through the prompt");
    assert_eq!(s.ok(&["status"])["locked"], false);
    // a prompt closed without unlocking: no signature, still locked
    s.ok(&["lock"]);
    s.extra.retain(|(k, _)| k != "EWE_SAFE_ASK_CMD");
    s.stop();
    let asks = s.root.join("asks");
    s.extra.push((
        "EWE_SAFE_ASK_CMD".into(),
        format!("echo asked >> {}", asks.display()),
    ));
    s.start();
    assert_eq!(
        s.listed().len(),
        3,
        "a restarted daemon lists from the file"
    );
    assert!(!s.sign_and_verify(&ec_public));
    assert_eq!(s.ok(&["status"])["locked"], true);
    // a loop of requests doesn't reopen the prompt: it rests a while
    assert!(!s.sign_and_verify(&ec_public));
    assert!(!s.sign_and_verify(&ec_public));
    let opened = std::fs::read_to_string(&asks).unwrap_or_default();
    assert_eq!(opened.lines().count(), 1, "one prompt: {opened:?}");
    let log = s.daemon_log();
    assert!(log.contains("none again for"), "{log}");
    assert!(
        log.contains("opening the unlock prompt for ssh-keygen"),
        "{log}"
    );

    // keys come from Safe: ssh-add can't put one in or take one out
    let (_, err, code) = s.openssh("ssh-add", &[ec_file.to_str().unwrap()], None);
    assert_ne!(code, 0, "adding is refused: {err}");
    let (_, _, code) = s.openssh("ssh-add", &["-D"], None);
    assert_ne!(code, 0, "removing all is refused");
    let (_, _, code) = s.openssh(
        "ssh-add",
        &["-d", ec_file.with_extension("pub").to_str().unwrap()],
        None,
    );
    assert_ne!(code, 0, "removing one is refused");
    assert_eq!(s.listed().len(), 3);

    let off = s.ok(&["ssh", "disable"]);
    assert_eq!(
        (off["enabled"].clone(), off["env_file_removed"].clone()),
        (json!(false), json!(true))
    );
    assert!(!env_file.exists());
    assert!(s.listed().is_empty());
    assert!(!cache.exists(), "off: no public-key list");

    // ewe-conf can't record it: no SSH_AUTH_SOCK for an agent that stays off
    write_exec(&s.bin.join("ewe-conf"), "#!/bin/sh\nexit 1\n");
    let en = s.ok(&["ssh", "enable"]);
    assert_eq!(
        (en["recorded"].clone(), en["env_file"].clone()),
        (json!(false), Value::Null)
    );
    assert!(!env_file.exists());

    let log = s.daemon_log();
    for never in ["GitHub key", "Old box", "PRIVATE KEY", KEY_PASS, MASTER] {
        assert!(
            !log.contains(never),
            "{never:?} in the daemon's log:\n{log}"
        );
    }
    assert!(log.contains("refused to add or remove keys"));
}

#[test]
fn notes_from_1password_become_ssh_keys() {
    use safe_core::import::{Batch, Field, Imported, Options};
    use safe_core::{Draft, Kind, Safe};
    use zeroize::Zeroizing;

    let mut s = Sandbox::new("adopt");
    // 1Password's form of a key: PKCS#8 (ssh-keygen writes one for ECDSA)
    let (key_file, public) = s.keygen("op_key", &["-t", "ecdsa", "-m", "PKCS8"], "");
    let pem = std::fs::read_to_string(&key_file).unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    // a safe as an earlier `import` left it: the SSH key as a Note
    let listing: String = pem.lines().map(|l| format!("  {l}\n")).collect();
    let note = Imported {
        folder: "Personal".into(),
        draft: Draft {
            kind: Kind::Note,
            title: "Deploy key".into(),
            notes: Zeroizing::new(format!(
                "SSH key\nprivate key:\n{listing}private key (public key): {public}"
            )),
            ..Draft::default()
        },
        fields: vec![Field {
            name: "private key".into(),
            value: Zeroizing::new(pem.clone()),
            protected: true,
        }],
        history: Vec::new(),
        files: Vec::new(),
        created: None,
        modified: None,
        ssh: None,
    };
    let mut safe = Safe::create("Safe", safe_core::kdf::argon2id(2));
    safe.import(
        &Batch {
            items: vec![note],
            skipped: Vec::new(),
        },
        &Options::default(),
    )
    .expect("import");
    let file = s.root.join("data").join("old.kdbx");
    // a public-key list left from another safe goes when the daemon starts
    let stale = s.root.join("state/ewe/safe/ssh-public.json");
    std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
    std::fs::write(&stale, b"{\"v\": 1, \"keys\": []}\n").unwrap();
    safe.write_file(&file, &safe_core::safe::key(MASTER, None).unwrap())
        .expect("write");

    s.start();
    assert!(!stale.exists());
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
    let id = s.ok(&["list", "--kind", "note"])["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let dry = s.ok(&["ssh", "adopt", "--dry-run"]);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(
        dry["adopted"],
        json!([{"item_id": id, "title": "Deploy key"}])
    );
    assert_eq!(
        s.ok(&["list", "--kind", "note"])["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let done = s.ok(&["ssh", "adopt"]);
    assert_eq!(
        done["adopted"][0]["item_id"],
        json!(id),
        "same item, in place"
    );
    let shown = s.ok(&["show", &id, "--reveal-notes"]);
    assert_eq!(shown["item"]["kind"], "ssh-key");
    assert_eq!(
        bare(shown["item"]["ssh"]["public_key"].as_str().unwrap()),
        bare(&public)
    );
    assert!(
        shown["item"]["notes"]
            .as_str()
            .unwrap()
            .starts_with("SSH key\n"),
        "the note text stays"
    );
    let kept = s.cli(&["reveal", &id, "--field", "private key", "--json"]);
    assert_eq!(kept["value"], json!(pem), "the old field stays");
    let openssh = s.cli(&["reveal", &id, "--field", "private_key", "--json"]);
    assert!(
        openssh["value"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );

    s.ok(&["ssh", "enable"]);
    assert_eq!(s.listed().len(), 1);
    assert!(s.sign_and_verify(&public));
    assert!(
        s.ok(&["ssh", "adopt"])["adopted"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_agent_limits_its_connections_and_waits_for_no_one() {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let mut s = Sandbox::new("limits");
    s.start();
    // 32 connections at once are served; the ones above are closed
    let conns: Vec<UnixStream> = (0..40)
        .map(|_| UnixStream::connect(s.agent()).expect("connect"))
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let closed = conns
        .iter()
        .filter(|c| {
            c.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut b = [0u8; 1];
            matches!((&**c).read(&mut b), Ok(0))
        })
        .count();
    assert_eq!(closed, 8, "the ones above 32 are closed");
    drop(conns);
    std::thread::sleep(Duration::from_millis(300));
    let (out, _, _) = s.openssh("ssh-add", &["-L"], None);
    assert!(out.contains("no identities"), "served again: {out}");

    // a request that stops halfway is dropped (10 s for a whole message)
    let mut half = UnixStream::connect(s.agent()).expect("connect");
    half.write_all(&[0, 0, 0, 100, 11]).unwrap();
    half.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let start = Instant::now();
    let mut b = [0u8; 1];
    assert!(matches!(half.read(&mut b), Ok(0)), "closed, no answer");
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_secs(9) && waited < Duration::from_secs(15),
        "{waited:?}"
    );
}

/// Where SSH keys meet the other streams (docs/TRIO.md): a `safe://`
/// reference (S3) reads an SSH key's two parts exactly as `reveal` does,
/// and a passkey (S1) never goes on an SSH key.
#[test]
fn references_and_passkeys_meet_ssh_keys() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let mut s = Sandbox::new("trio");
    s.start();
    s.init();
    let made = s.ok(&["ssh", "new", "--title", "GitHub key"]);
    let id = made["item_id"].as_str().unwrap().to_string();
    let public = made["ssh"]["public_key"].as_str().unwrap().to_string();

    // `read` prints the bare public line; with --json it is `resolve`'s
    // answer, the same value `reveal` gives
    let (out, code) = s.raw(&["read", "safe://GitHub key/public_key"], None);
    assert_eq!((out.trim_end(), code), (public.as_str(), 0));
    let shown = s.ok(&["reveal", &id, "--field", "private_key", "--json"]);
    let read = s.ok(&["read", &format!("safe://{id}/private_key"), "--json"]);
    assert_eq!(read["value"], shown["value"]);
    assert_eq!(read["item_id"], json!(id));
    assert!(
        read["value"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
        "the key file KeeAgent.settings names"
    );

    // a passkey goes on a login only, over the socket as the browser asks
    let mut sock = UnixStream::connect(s.run.join("ewe-safe.sock")).expect("connect");
    let req = json!({"v": 1, "id": 1, "verb": "passkey-create", "args": {
        "rp_id": "github.com", "rp_name": "GitHub", "user_id": "dXNlcg",
        "user_name": "sam", "user_display_name": "Sam",
        "client_data_hash": "A".repeat(43), "algorithms": [-7], "exclude": [],
        "item_id": id, "origin": "https://github.com", "user_verified": true,
    }});
    writeln!(sock, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(&sock).read_line(&mut line).unwrap();
    let v: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(v["error"], "bad-request", "{v}");
    assert_eq!(s.ok(&["passkey", "list"])["passkeys"], json!([]));
    let keys = s.ok(&["ssh", "list"]);
    assert_eq!(keys["items"][0]["passkey"], Value::Null, "{keys}");
    assert_eq!(keys["items"][0]["ssh"]["public_key"], json!(public));
}
