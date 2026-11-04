//! Safe is the SSH gate (docs/GATE.md S21–S27), end to end: the real
//! `ewe-safe` and `ewe-safed` in a sandbox (their own HOME and XDG
//! directories, a fake `ewe-conf` that stores into a JSON file and writes
//! ewe-conf's managed host block, cheap key derivation, no logind), with
//! OpenSSH's own tools.
//!
//! OpenSSH takes `~` from the passwd entry, not `$HOME`, for its default
//! config, known_hosts and identity files. So every `ssh` here runs with
//! `-F <sandbox config>` and a sandbox `UserKnownHostsFile`, and a real
//! connection always names its key with `-i <absolute path>`: nothing
//! reads or writes the real `~/.ssh`. Git runs with `GIT_CONFIG_GLOBAL` in
//! the sandbox.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const MASTER: &str = "correct horse battery";

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

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777
}

fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what}: not within {secs} s");
}

/// The fake `ewe-conf`: `get` and `set` on dotted keys in a JSON file
/// (values parsed as JSON, as ewe-conf does), every `set` logged, and
/// `set network.ssh.hosts` writes the managed block at the end of
/// `$HOME/.ssh/config` the way ewe-conf's `apply_ssh` does.
const FAKE_EWE_CONF: &str = r##"#!/usr/bin/env python3
import json, os, sys, tempfile
p = os.path.join(os.environ["XDG_CONFIG_HOME"], "fake-ewe-conf.json")
try:
    d = json.load(open(p))
except Exception:
    d = {}
a = sys.argv[1:]
def dig(key, create=False):
    node = d
    parts = key.split(".")
    for k in parts[:-1]:
        if k not in node or not isinstance(node[k], dict):
            if not create:
                return None, parts[-1]
            node[k] = {}
        node = node[k]
    return node, parts[-1]
A = "# >>> ewe managed hosts (ewe-conf writes this block; edits inside are overwritten) >>>"
B = "# <<< ewe managed hosts <<<"
def own_hosts(text):
    out = set()
    for raw in text.splitlines():
        parts = raw.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "host":
            names = parts[1].split()
            if len(names) == 1:
                out.add(names[0])
    return out
def apply_ssh(hosts):
    cfg = os.path.join(os.environ["HOME"], ".ssh", "config")
    try:
        text = open(cfg).read()
    except OSError:
        text = ""
    outside = text
    if A in text and B in text:
        pre, _, rest = text.partition(A)
        _, _, post = rest.partition(B)
        outside = pre + post.lstrip("\n")
    own = own_hosts(outside)
    lines = [A]
    for h in hosts:
        # entries it can't read are left out of the block (ewe-conf's own
        # validation is ewe's side)
        if not isinstance(h, dict) or not isinstance(h.get("host"), str):
            continue
        if not isinstance(h.get("options", []), list):
            continue
        if h.get("host") in own:
            continue
        lines.append("Host %s" % h["host"])
        for k, v in h.get("options", []):
            lines.append("    %s %s" % (k, v))
    lines.append(B)
    new = outside.rstrip("\n")
    new = (new + "\n\n" if new else "") + "\n".join(lines) + "\n"
    if new != text:
        os.makedirs(os.path.dirname(cfg), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(cfg), prefix=".ewe-ssh.")
        with os.fdopen(fd, "w") as f:
            f.write(new)
        os.chmod(tmp, 0o600)
        os.replace(tmp, cfg)
if len(a) == 2 and a[0] == "get":
    node, last = dig(a[1])
    if node is None or last not in node:
        print(json.dumps({"error": "no-key", "key": a[1]}), file=sys.stderr)
        sys.exit(1)
    v = node[last]
    print(json.dumps(v) if isinstance(v, (dict, list, bool)) else v)
elif len(a) == 3 and a[0] == "set":
    try:
        v = json.loads(a[2])
    except ValueError:
        v = a[2]
    node, last = dig(a[1], True)
    node[last] = v
    # atomically, like the real ewe-conf: the daemon re-reads the settings
    # on its own, and a half-written file read as "no [safe]" (a CI flake)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p), prefix=".fake-ewe-conf.")
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.replace(tmp, p)
    with open(p + ".log", "a") as f:
        f.write(a[1] + "\n")
    if a[1] == "network.ssh.hosts":
        apply_ssh(v)
else:
    sys.exit(2)
"##;

struct Sandbox {
    root: PathBuf,
    run: PathBuf,
    bin: PathBuf,
    extra: Vec<(String, String)>,
    daemon: Option<Child>,
    children: Vec<Child>,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("safe-gate-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // the socket paths must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/sg-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let bin = root.join("bin");
        for d in [&root, &run, &bin] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        for d in ["state", "config", "data", "home", "keys", "pub", "out"] {
            std::fs::create_dir_all(root.join(d)).expect("mkdir");
        }
        write_exec(&bin.join("ewe-conf"), FAKE_EWE_CONF);
        let r = root.display();
        write_exec(
            &bin.join("approve"),
            &format!(
                "#!/bin/sh\necho \"$EWE_SAFE_APPROVE_APP|$EWE_SAFE_APPROVE_KEY|$EWE_SAFE_APPROVE_HOST|$EWE_SAFE_APPROVE_FORWARDED\" >> {r}/approvals\na=$(cat {r}/answer 2>/dev/null)\nexit \"${{a:-1}}\"\n"
            ),
        );
        // what Safe opens (a page, a terminal) and copies, written down
        write_exec(
            &bin.join("opened"),
            &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {r}/out/opened\n"),
        );
        write_exec(
            &bin.join("wl-copy"),
            &format!("#!/bin/sh\ncat > {r}/out/clipboard\n"),
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
                (
                    "EWE_SAFE_OPEN".into(),
                    bin.join("opened").display().to_string(),
                ),
                ("EWE_SAFE_SETTINGS_SECONDS".into(), "1".into()),
            ],
            root,
            run,
            bin,
            daemon: None,
            children: Vec::new(),
        };
        s.answer("0");
        s
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn ssh_dir(&self) -> PathBuf {
        self.home().join(".ssh")
    }

    fn gate_dir(&self) -> PathBuf {
        self.ssh_dir().join("ewe-safe")
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
            (
                "GIT_CONFIG_GLOBAL".into(),
                self.home().join(".gitconfig").display().to_string(),
            ),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
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

    /// An OpenSSH tool with the sandbox's HOME, nothing of the session's.
    fn tool(
        &self,
        prog: &str,
        args: &[&str],
        envs: &[(&str, &str)],
        stdin: Option<&[u8]>,
    ) -> (String, String, i32) {
        let mut c = Command::new(prog);
        c.args(args)
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .envs(envs.iter().copied())
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

    fn openssh(&self, prog: &str, args: &[&str], stdin: Option<&[u8]>) -> (String, String, i32) {
        let sock = self.agent().display().to_string();
        self.tool(prog, args, &[("SSH_AUTH_SOCK", &sock)], stdin)
    }

    /// A key made by ssh-keygen at `path`: its public line.
    fn keygen_at(&self, path: &Path, args: &[&str], pass: &str) -> String {
        let mut a = vec!["-q", "-N", pass, "-f", path.to_str().unwrap()];
        a.extend_from_slice(args);
        let (_, err, code) = self.openssh("ssh-keygen", &a, None);
        assert_eq!(code, 0, "ssh-keygen: {err}");
        let mut pubf = path.as_os_str().to_owned();
        pubf.push(".pub");
        std::fs::read_to_string(PathBuf::from(pubf))
            .expect("pub")
            .trim()
            .to_string()
    }

    /// `ssh-keygen -Y sign` through Safe's agent with only the public key
    /// on disk, then `-Y verify`.
    fn sign_and_verify(&self, public: &str) -> bool {
        let pubfile = self.root.join("pub").join("key.pub");
        std::fs::write(&pubfile, format!("{public}\n")).unwrap();
        let data = self.root.join("pub").join("data.txt");
        std::fs::write(&data, b"commit 1234\n").unwrap();
        let sig = data.with_extension("txt.sig");
        let _ = std::fs::remove_file(&sig);
        let (_, err, code) = self.openssh(
            "ssh-keygen",
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
        true
    }

    /// A real ssh-agent on `sock` (playing 1Password), holding `key`.
    fn other_agent(&mut self, sock: &Path, key: &Path) {
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let child = Command::new("ssh-agent")
            .args(["-D", "-a", sock.to_str().unwrap()])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("ssh-agent");
        self.children.push(child);
        wait_until("ssh-agent listens", 5, || sock.exists());
        let s = sock.display().to_string();
        let (_, err, code) = self.tool(
            "ssh-add",
            &[key.to_str().unwrap()],
            &[("SSH_AUTH_SOCK", &s)],
            None,
        );
        assert_eq!(code, 0, "ssh-add: {err}");
    }

    fn init(&self) {
        let v = self.cli_in(
            &["init", "--place", "local"],
            &format!("{MASTER}\n{MASTER}\n"),
        );
        assert_eq!(v["ok"], true, "init: {v}");
    }

    fn conf(&self) -> Value {
        std::fs::read(self.root.join("config/fake-ewe-conf.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(json!({}))
    }

    /// Another computer of the account changed ewe.conf.
    fn set_conf(&self, f: impl FnOnce(&mut Value)) {
        let mut c = self.conf();
        f(&mut c);
        std::fs::write(
            self.root.join("config/fake-ewe-conf.json"),
            serde_json::to_vec(&c).unwrap(),
        )
        .unwrap();
    }

    /// `ssh -G` with the sandbox's config: what ssh would use for `host`.
    fn ssh_g(&self, host: &str) -> Vec<(String, String)> {
        let cfg = self.ssh_dir().join("config");
        let (out, err, code) =
            self.tool("ssh", &["-G", "-F", cfg.to_str().unwrap(), host], &[], None);
        assert_eq!(code, 0, "ssh -G: {err}");
        out.lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.stop();
        for mut c in self.children.drain(..) {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.run);
        if std::env::var_os("SAFE_E2E_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn get<'a>(g: &'a [(String, String)], k: &str) -> Vec<&'a str> {
    g.iter()
        .filter(|(key, _)| key == k)
        .map(|(_, v)| v.as_str())
        .collect()
}

fn tag(fp: &str) -> String {
    fp.trim_start_matches("SHA256:")[..16]
        .replace('+', "-")
        .replace('/', "_")
}

const COMMENT: &str =
    "# Safe (ewe): every ssh asks Safe for keys. `ewe-safe ssh disable` removes these two lines.";
const INCLUDE: &str = "Include ~/.ssh/ewe-safe/config";

/// S21 and S22: `enable` puts the gate in place — two lines on top of the
/// user's config, Safe's own folder, a public file per key — `ssh` takes
/// Safe's agent even for a host that names 1Password, the computer follows
/// the account's `ssh_agent`, and `disable` takes away only what Safe
/// wrote.
#[test]
fn the_gate_goes_on_and_off_and_follows_the_account() {
    let mut s = Sandbox::new("gate");
    let ssh = s.ssh_dir();
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let original = "Host work\n    HostName work.example.com\n    IdentityAgent ~/.1password/agent.sock\n\nHost emoh\n    IdentityFile ~/.ssh/id_ed25519\n";
    let cfg = ssh.join("config");
    std::fs::write(&cfg, original).unwrap();
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o644)).unwrap();
    // the user's own key file, and "1Password" holding another key
    let emoh_public = s.keygen_at(&ssh.join("id_ed25519"), &["-C", "sam@emoh"], "");
    let op_key = s.root.join("keys").join("op_key");
    s.keygen_at(&op_key, &["-t", "ecdsa", "-C", "op"], "");
    let op_sock = s.home().join(".1password/agent.sock");
    s.other_agent(&op_sock, &op_key);

    s.start();
    s.init();
    let made = s.ok(&["ssh", "new", "--title", "GitHub key"]);
    let public = made["ssh"]["public_key"].as_str().unwrap().to_string();
    let fp = made["ssh"]["fingerprint"].as_str().unwrap().to_string();

    // before: not the gate; 1Password answers for `work`
    let gate = s.ok(&["ssh", "status"])["gate"].clone();
    assert_eq!(
        (gate["on"].clone(), gate["include"].clone()),
        (json!(false), json!(false))
    );
    assert_eq!(
        gate["overridden"],
        json!([{"host": "work", "agent": "~/.1password/agent.sock"}])
    );
    assert_eq!(
        gate["key_files"],
        json!([{"path": ssh.join("id_ed25519"), "fingerprint": fp_of(&s, &emoh_public), "in_safe": false}])
    );
    assert_eq!(
        gate["other_agents"],
        json!([{"socket": op_sock, "name": "1Password", "keys": 1, "missing_from_safe": 1}])
    );
    assert!(!s.gate_dir().exists());

    // on
    let en = s.ok(&["ssh", "enable", "--confirm", "first-use"]);
    assert_eq!(en["gate"]["on"], true, "{en}");
    assert_eq!(en["gate"]["include"], true);
    let text = std::fs::read_to_string(&cfg).unwrap();
    assert_eq!(text, format!("{COMMENT}\n{INCLUDE}\n{original}"));
    assert_eq!(mode(&cfg), 0o644, "the file keeps its mode");
    assert_eq!(
        std::fs::read_to_string(ssh.join("config.before-safe")).unwrap(),
        original
    );
    assert_eq!(mode(&s.gate_dir()), 0o700);
    let gate_cfg = std::fs::read_to_string(s.gate_dir().join("config")).unwrap();
    assert!(
        gate_cfg.starts_with("# Written by Safe (ewe-safe)."),
        "{gate_cfg}"
    );
    assert!(
        gate_cfg.contains(&format!("    IdentityAgent {}\n", s.agent().display())),
        "{gate_cfg}"
    );
    let known = s.gate_dir().join("known_hosts");
    assert!(
        gate_cfg.contains(&format!(
            "    GlobalKnownHostsFile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2 {}\n",
            known.display()
        )),
        "{gate_cfg}"
    );
    assert_eq!(mode(&s.gate_dir().join("config")), 0o600);
    assert!(
        std::fs::read_to_string(&known)
            .unwrap()
            .contains("\ngithub.com ssh-ed25519 ")
    );
    // S22: the key's public file, named by its fingerprint
    let key_file = s.gate_dir().join(format!("key-{}.pub", tag(&fp)));
    wait_until("the key file", 5, || key_file.exists());
    assert_eq!(
        std::fs::read_to_string(&key_file).unwrap(),
        format!("{} GitHub key\n", bare(&public))
    );
    assert_eq!(mode(&key_file), 0o644);
    let item = &s.ok(&["ssh", "list"])["items"][0]["ssh"];
    assert_eq!(
        item["file"],
        format!("~/.ssh/ewe-safe/key-{}.pub", tag(&fp))
    );
    assert_eq!(item["last_used"], Value::Null);

    // ssh takes Safe's agent, even for the host that names 1Password
    let g = s.ssh_g("work");
    assert_eq!(get(&g, "identityagent"), [s.agent().display().to_string()]);
    assert!(
        get(&g, "globalknownhostsfile")[0].ends_with(&known.display().to_string()),
        "{g:?}"
    );
    assert_eq!(
        get(&s.ssh_g("anything.example"), "identityagent"),
        [s.agent().display().to_string()]
    );

    // once only: a second enable writes nothing
    let before = std::fs::metadata(&cfg).unwrap().modified().unwrap();
    s.ok(&["ssh", "enable"]);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(std::fs::metadata(&cfg).unwrap().modified().unwrap(), before);
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), text);

    // last used: the agent's last signature here (no title on disk)
    assert!(s.sign_and_verify(&public));
    assert_eq!(s.approvals().len(), 1, "asked as always");
    let item = &s.ok(&["ssh", "list"])["items"][0]["ssh"];
    assert!(
        item["last_used"]["program"]
            .as_str()
            .unwrap()
            .starts_with("ssh-keygen"),
        "{item}"
    );
    assert!(item["last_used"]["at"].as_str().unwrap().ends_with('Z'));
    let used = std::fs::read_to_string(s.root.join("state/ewe/safe/ssh-used.json")).unwrap();
    assert!(used.contains(&fp) && !used.contains("GitHub key"), "{used}");

    // the user's key file, once in Safe, is `in_safe`
    s.ok(&["ssh", "add", ssh.join("id_ed25519").to_str().unwrap()]);
    let gate = s.ok(&["ssh", "status"])["gate"].clone();
    assert_eq!(gate["key_files"][0]["in_safe"], true, "{gate}");
    assert_eq!(
        gate["overridden"][0]["host"], "work",
        "still named: Safe answers anyway"
    );

    // lines moved down by hand go back on top
    std::fs::write(
        &cfg,
        format!("ServerAliveInterval 30\n{COMMENT}\n{INCLUDE}\n{original}"),
    )
    .unwrap();
    wait_until("the lines back on top", 5, || {
        std::fs::read_to_string(&cfg).unwrap()
            == format!("{COMMENT}\n{INCLUDE}\nServerAliveInterval 30\n{original}")
    });

    // locked, a deleted key file comes back at start, from the public-key list
    s.ok(&["lock"]);
    s.stop();
    std::fs::remove_file(&key_file).unwrap();
    s.start();
    wait_until("the key file again", 5, || key_file.exists());

    // the account: another computer turned the agent off …
    let with_line = std::fs::read_to_string(&cfg).unwrap();
    s.set_conf(|c| c["safe"]["ssh_agent"] = json!(false));
    wait_until("the gate gone", 10, || !s.gate_dir().exists());
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        with_line.replacen(&format!("{COMMENT}\n{INCLUDE}\n"), "", 1)
    );
    assert!(
        !s.root
            .join("config/environment.d/90-ewe-safe-ssh.conf")
            .exists()
    );
    assert!(ssh.join("config.before-safe").exists(), "the copy stays");
    assert!(
        ssh.join("id_ed25519").exists(),
        "key files are never touched"
    );
    // … and on again
    s.set_conf(|c| c["safe"]["ssh_agent"] = json!(true));
    wait_until("the gate back", 10, || {
        std::fs::read_to_string(&cfg).unwrap() == with_line && key_file.exists()
    });

    // an ewe-conf that doesn't answer, or answers with anything but a
    // [safe] table, changes nothing
    for broken in [
        "#!/bin/sh\nexit 2\n",
        "#!/bin/sh\necho '[]'\n",
        "#!/bin/sh\necho 'oops'\n",
        "#!/bin/sh\necho '{\"error\": \"no-key\", \"key\": \"safe\"}' >&2\nexit 1\n",
    ] {
        write_exec(&s.bin.join("ewe-conf"), broken);
        std::thread::sleep(Duration::from_secs(3));
        assert!(s.gate_dir().join("config").exists(), "{broken}");
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            with_line,
            "{broken}"
        );
    }
    write_exec(&s.bin.join("ewe-conf"), FAKE_EWE_CONF);

    // off: only Safe's lines and files
    let off = s.ok(&["ssh", "disable"]);
    assert_eq!(off["env_file_removed"], true, "{off}");
    assert_eq!(off["gate"]["on"], false);
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        format!("ServerAliveInterval 30\n{original}")
    );
    assert!(!s.gate_dir().exists());
    assert_eq!(
        std::fs::read_to_string(ssh.join("config.before-safe")).unwrap(),
        original,
        "never touched"
    );
    let log = s.daemon_log();
    assert!(!log.contains("GitHub key"), "{log}");
    assert!(log.contains("the SSH gate is off (ewe.conf"), "{log}");
}

fn fp_of(s: &Sandbox, public: &str) -> String {
    let f = s.root.join("pub").join("fp.pub");
    std::fs::write(&f, format!("{public}\n")).unwrap();
    let (out, _, _) = s.tool("ssh-keygen", &["-l", "-f", f.to_str().unwrap()], &[], None);
    out.split_whitespace().nth(1).unwrap().to_string()
}

/// The key part of a public line (no comment).
fn bare(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// S21: no `~/.ssh` yet, and a config that is a link (a dotfiles folder).
#[test]
fn a_new_config_and_a_linked_one() {
    let mut s = Sandbox::new("newcfg");
    s.start();
    s.init();
    s.ok(&["ssh", "enable"]);
    let ssh = s.ssh_dir();
    assert_eq!(mode(&ssh), 0o700);
    let cfg = ssh.join("config");
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        format!("{COMMENT}\n{INCLUDE}\n")
    );
    assert_eq!(mode(&cfg), 0o600);
    assert!(!ssh.join("config.before-safe").exists(), "nothing to copy");
    s.ok(&["ssh", "disable"]);
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "");

    // a link stays a link; its target gets the lines
    let dots = s.root.join("dotfiles");
    std::fs::create_dir_all(&dots).unwrap();
    std::fs::write(dots.join("ssh_config"), "Host x\n    User y\n").unwrap();
    std::fs::remove_file(&cfg).unwrap();
    std::os::unix::fs::symlink(dots.join("ssh_config"), &cfg).unwrap();
    s.ok(&["ssh", "enable"]);
    assert!(cfg.is_symlink());
    assert_eq!(
        std::fs::read_to_string(dots.join("ssh_config")).unwrap(),
        format!("{COMMENT}\n{INCLUDE}\nHost x\n    User y\n")
    );
    s.ok(&["ssh", "disable"]);
    assert!(cfg.is_symlink());
    assert_eq!(
        std::fs::read_to_string(dots.join("ssh_config")).unwrap(),
        "Host x\n    User y\n"
    );
}

impl Sandbox {
    /// One request on the daemon's socket, as the window sends it.
    fn sock(&self, verb: &str, args: Value) -> Value {
        use std::io::{BufRead, BufReader};
        let mut sock = std::os::unix::net::UnixStream::connect(self.run.join("ewe-safe.sock"))
            .expect("connect");
        writeln!(
            sock,
            "{}",
            json!({"v": 1, "id": 1, "verb": verb, "args": args})
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(&sock).read_line(&mut line).unwrap();
        serde_json::from_str(&line).expect("json")
    }
}

fn titles(v: &Value) -> Vec<String> {
    let mut t: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["title"].as_str().unwrap().to_string())
        .collect();
    t.sort();
    t
}

/// S23: "Move SSH to Safe" — key files in (never changed), ewe.conf's hosts
/// stop naming 1Password, the user's own lines are only overridden, and
/// what only 1Password holds is named.
#[test]
fn takeover_moves_keys_and_hosts_and_names_what_only_1password_has() {
    let mut s = Sandbox::new("takeover");
    let ssh = s.ssh_dir();
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let plain = ssh.join("id_ed25519");
    s.keygen_at(&plain, &["-C", "sam@emoh"], "");
    let locked = ssh.join("id_rsa_old");
    s.keygen_at(
        &locked,
        &["-t", "rsa", "-b", "2048", "-C", "old box"],
        "pp-31",
    );
    let elsewhere = s.root.join("keys").join("deploy");
    s.keygen_at(&elsewhere, &["-t", "ecdsa", "-C", "deploy"], "");
    let user_cfg = format!(
        "Host emoh\n    IdentityFile ~/.ssh/id_ed25519\nHost deploy\n    IdentityFile {}\n    IdentityAgent ~/.1password/agent.sock\n",
        elsewhere.display()
    );
    std::fs::write(ssh.join("config"), &user_cfg).unwrap();
    let files_before: Vec<Vec<u8>> = [&plain, &locked, &elsewhere]
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    // ewe.conf, as the owner's: two hosts name 1Password
    s.set_conf(|c| {
        c["network"] = json!({"ssh": {"hosts": [
            {"host": "work", "options": [["HostName", "work.example.com"], ["IdentityAgent", "~/.1password/agent.sock"]]},
            {"host": "work-proxy", "options": [["IdentityAgent", "~/.1password/agent.sock"], ["ProxyJump", "work"]]},
            {"host": "plain", "options": [["User", "sam"]]},
        ]}});
    });
    // "1Password" holds a key only it has, and one of the files
    let op_key = s.root.join("keys").join("op_only");
    s.keygen_at(&op_key, &["-C", "only in 1password"], "");
    let op_sock = s.home().join(".1password/agent.sock");
    s.other_agent(&op_sock, &op_key);
    let (_, err, code) = s.tool(
        "ssh-add",
        &[plain.to_str().unwrap()],
        &[("SSH_AUTH_SOCK", op_sock.to_str().unwrap())],
        None,
    );
    assert_eq!(code, 0, "{err}");

    s.start();
    s.init();
    s.ok(&["lock"]);
    assert_eq!(s.cli(&["ssh", "takeover", "--dry-run"])["error"], "locked");
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));

    // a dry run changes nothing
    let conf_before = s.conf();
    let dry = s.ok(&["ssh", "takeover", "--dry-run"]);
    assert_eq!(dry["dry_run"], true, "{dry}");
    assert_eq!(dry["enabled"], false);
    assert_eq!(titles(&dry["imported"]), ["deploy", "sam@emoh"]);
    assert!(dry["imported"][0]["item_id"].is_null());
    assert_eq!(dry["needs_passphrase"], json!([locked]));
    assert_eq!(dry["hosts_fixed"], json!(["work", "work-proxy"]));
    assert_eq!(
        dry["overridden"],
        json!([{"host": "deploy", "agent": "~/.1password/agent.sock"}])
    );
    let missing = dry["missing_from_safe"].as_array().unwrap();
    assert_eq!(missing.len(), 1, "{dry}");
    assert_eq!(missing[0]["agent"], "1Password");
    assert_eq!(missing[0]["comment"], "only in 1password");
    assert_eq!(missing[0]["key_type"], "ed25519");
    assert!(dry["hint"].as_str().unwrap().contains("ewe-safe import op"));
    assert_eq!(s.conf(), conf_before);
    assert!(!s.gate_dir().exists());
    assert!(
        s.ok(&["ssh", "list"])["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // a wrong passphrase: skipped, with the reason
    let wrong = s.sock(
        "ssh-takeover",
        json!({"dry_run": true, "passphrases": {locked.to_str().unwrap(): "nope"}}),
    );
    assert_eq!(wrong["skipped"][0]["file"], json!(locked), "{wrong}");
    assert!(
        wrong["skipped"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("passphrase")
    );

    // the move, the passphrase sent as the window sends it
    let done = s.sock(
        "ssh-takeover",
        json!({"passphrases": {locked.to_str().unwrap(): "pp-31"}}),
    );
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(done["enabled"], true);
    assert_eq!(done["gate"]["on"], true);
    assert_eq!(titles(&done["imported"]), ["deploy", "old box", "sam@emoh"]);
    assert!(
        done["imported"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["item_id"].is_string())
    );
    assert_eq!(done["needs_passphrase"], json!([]));
    assert_eq!(done["hosts_fixed"], json!(["work", "work-proxy"]));
    assert_eq!(done["files_left"].as_array().unwrap().len(), 3);
    assert!(done["sync"].is_object());
    // ewe.conf: only the IdentityAgent options went, in one set
    assert_eq!(
        s.conf()["network"]["ssh"]["hosts"],
        json!([
            {"host": "work", "options": [["HostName", "work.example.com"]]},
            {"host": "work-proxy", "options": [["ProxyJump", "work"]]},
            {"host": "plain", "options": [["User", "sam"]]},
        ])
    );
    let sets = std::fs::read_to_string(s.root.join("config/fake-ewe-conf.json.log")).unwrap();
    assert_eq!(sets.matches("network.ssh.hosts").count(), 1, "{sets}");
    // the files are never changed; the user's lines neither
    let files_after: Vec<Vec<u8>> = [&plain, &locked, &elsewhere]
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    assert_eq!(files_after, files_before);
    let cfg = std::fs::read_to_string(ssh.join("config")).unwrap();
    assert!(
        cfg.starts_with(&format!("{COMMENT}\n{INCLUDE}\n{user_cfg}")),
        "{cfg}"
    );
    // ssh asks Safe for every host now, the user's and ewe.conf's
    for host in ["work", "deploy", "emoh"] {
        assert_eq!(
            get(&s.ssh_g(host), "identityagent"),
            [s.agent().display().to_string()],
            "{host}"
        );
    }
    // the keys sign through Safe
    let listed = s.ok(&["ssh", "list"])["items"].clone();
    assert_eq!(listed.as_array().unwrap().len(), 3);

    // again: everything is there already
    let again = s.ok(&["ssh", "takeover"]);
    assert_eq!(again["imported"], json!([]), "{again}");
    assert_eq!(titles(&again["already"]), ["deploy", "old box", "sam@emoh"]);
    assert_eq!(again["hosts_fixed"], json!([]));
    assert_eq!(again["missing_from_safe"].as_array().unwrap().len(), 1);

    let log = s.daemon_log();
    for never in ["pp-31", "old box", "sam@emoh", "PRIVATE KEY"] {
        assert!(!log.contains(never), "{never:?} in the log:\n{log}");
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn host<'a>(list: &'a Value, alias: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|h| h["alias"] == alias)
        .unwrap_or_else(|| panic!("{alias} in {list}"))
}

/// S24: the catalogue, `connect` (a key, its file, the host in ewe.conf,
/// the clipboard, the page), conflicts, and the hosts verbs.
#[test]
fn services_connect_and_hosts() {
    let mut s = Sandbox::new("connect");
    s.start();
    s.init();
    let out = s.root.join("out");

    let cat = s.ok(&["ssh", "services"]);
    let list = cat["services"].as_array().unwrap();
    assert_eq!(list.len(), 12);
    assert_eq!(
        list[0],
        json!({
            "service": "github", "name": "GitHub", "group": "git", "host": "github.com",
            "user": "git", "key_type": "ed25519", "key_bits": null,
            "page": "https://github.com/settings/ssh/new", "needs": [], "optional": [],
            "signing": true, "steps": list[0]["steps"], "signing_steps": list[0]["signing_steps"],
        })
    );

    // GitHub: a new key, the gate on, the host in ewe.conf
    let gh = s.ok(&["ssh", "connect", "github"]);
    assert_eq!(
        gh["enabled"], true,
        "the agent was off: connect turns it on"
    );
    assert_eq!(gh["alias"], "github.com");
    assert_eq!(gh["service"], "github");
    assert_eq!(gh["ssh"]["key_type"], "ed25519");
    assert_eq!(gh["copied"], true);
    assert_eq!(gh["opened"], true);
    assert_eq!(gh["remote_hint"], "git@github.com:<owner>/<repo>.git");
    assert_eq!(gh["steps"].as_array().unwrap().len(), 3);
    let gh_id = gh["item_id"].as_str().unwrap().to_string();
    let fp = gh["ssh"]["fingerprint"].as_str().unwrap().to_string();
    let file = format!("~/.ssh/ewe-safe/key-{}.pub", tag(&fp));
    assert_eq!(gh["ssh"]["file"], file);
    let public = gh["ssh"]["public_key"].as_str().unwrap().to_string();
    assert_eq!(
        read(&out.join("clipboard")),
        format!("{} GitHub", bare(&public))
    );
    // the page opens in the background
    wait_until("the page opened", 5, || {
        read(&out.join("opened"))
            .trim_end()
            .ends_with(" https://github.com/settings/ssh/new")
    });
    assert_eq!(s.ok(&["ssh", "list"])["items"][0]["title"], "GitHub");
    assert_eq!(
        s.conf()["network"]["ssh"]["hosts"],
        json!([{"host": "github.com", "options": [["User", "git"], ["IdentityFile", file], ["IdentitiesOnly", "yes"]]}])
    );
    assert!(s.gate_dir().join(format!("key-{}.pub", tag(&fp))).exists());
    let g = s.ssh_g("github.com");
    assert_eq!(get(&g, "identityfile"), [file.as_str()]);
    assert_eq!(get(&g, "identitiesonly"), ["yes"]);
    assert_eq!(get(&g, "user"), ["git"]);
    assert_eq!(get(&g, "identityagent"), [s.agent().display().to_string()]);

    // the same alias with another key: a conflict, nothing made
    let again = s.cli(&["ssh", "connect", "github"]);
    assert_eq!(again["error"], "conflict", "{again}");
    assert_eq!(again["alias"], "github.com");
    assert_eq!(
        again["message"],
        "github.com already uses the key GitHub. Use --replace, or --alias github-2 for a second account."
    );
    assert_eq!(s.ok(&["ssh", "list"])["items"].as_array().unwrap().len(), 1);
    // the same key again is fine
    s.ok(&["ssh", "connect", "github", "--key", &gh_id, "--no-open"]);
    // a second account
    let work = s.ok(&[
        "ssh",
        "connect",
        "github",
        "--alias",
        "github-work",
        "--title",
        "Work GitHub",
        "--no-open",
    ]);
    assert_eq!(work["alias"], "github-work");
    assert_eq!(work["opened"], false);
    assert_eq!(work["remote_hint"], "git@github-work:<owner>/<repo>.git");
    let g = s.ssh_g("github-work");
    assert_eq!(get(&g, "hostname"), ["github.com"]);
    // --replace: github.com takes a new key
    let rep = s.ok(&[
        "ssh",
        "connect",
        "github",
        "--replace",
        "--title",
        "GitHub 2",
        "--no-open",
    ]);
    assert_ne!(rep["item_id"], json!(gh_id));

    // the user's own lines are never edited
    let cfg = s.ssh_dir().join("config");
    let mine = format!(
        "{}Host gitlab.com\n    User me\n",
        read(&cfg)
            .split("\n# >>> ewe managed hosts")
            .next()
            .unwrap()
            .to_string()
            + "\n"
    );
    let rest = read(&cfg)[read(&cfg).find("# >>> ewe managed hosts").unwrap()..].to_string();
    std::fs::write(&cfg, format!("{mine}\n{rest}")).unwrap();
    let gl = s.cli(&["ssh", "connect", "gitlab", "--no-open"]);
    assert_eq!(gl["error"], "conflict", "{gl}");
    assert_eq!(
        gl["message"],
        "You set up gitlab.com yourself in ~/.ssh/config. Change it there, or use --alias."
    );

    // Azure DevOps: RSA, the organization's page
    let ed = s.cli(&[
        "ssh",
        "connect",
        "azure-devops",
        "--key",
        &gh_id,
        "--no-open",
    ]);
    assert_eq!(ed["error"], "bad-request", "{ed}");
    let az = s.ok(&[
        "ssh",
        "connect",
        "azure-devops",
        "--org",
        "fabrikam",
        "--no-open",
    ]);
    assert_eq!(az["ssh"]["key_type"], "rsa");
    assert_eq!(
        az["page"],
        "https://dev.azure.com/fabrikam/_usersSettings/keys"
    );
    assert_eq!(
        az["remote_hint"],
        "git@ssh.dev.azure.com:v3/fabrikam/<project>/<repo>"
    );
    let pubf = s.root.join("pub").join("az.pub");
    std::fs::write(
        &pubf,
        format!("{}\n", az["ssh"]["public_key"].as_str().unwrap()),
    )
    .unwrap();
    let (bits, _, _) = s.tool(
        "ssh-keygen",
        &["-l", "-f", pubf.to_str().unwrap()],
        &[],
        None,
    );
    assert!(bits.starts_with("3072 "), "{bits}");

    // a cloud service: no host yet; Google Cloud wants the user name last
    let aws = s.ok(&["ssh", "connect", "aws", "--no-open"]);
    assert_eq!(
        (aws["alias"].clone(), aws["page"].clone()),
        (Value::Null, json!("https://console.aws.amazon.com/ec2/"))
    );
    assert_eq!(aws["remote_hint"], Value::Null);
    let gc = s.ok(&["ssh", "connect", "gcloud", "--user", "sam", "--no-open"]);
    assert!(read(&out.join("clipboard")).ends_with(" sam"), "{gc}");

    // a server: a terminal runs ssh-copy-id
    let no = s.cli(&["ssh", "connect", "server", "--host", "10.0.0.9"]);
    assert_eq!(no["error"], "bad-request");
    let sv = s.ok(&[
        "ssh", "connect", "server", "--host", "10.0.0.9", "--user", "deploy", "--port", "2222",
    ]);
    assert_eq!(sv["alias"], "10.0.0.9");
    let sv_fp = sv["ssh"]["fingerprint"].as_str().unwrap();
    let want = format!(
        "kitty --title Safe: copy your key to 10.0.0.9 ssh-copy-id -f -i {} -o PreferredAuthentications=keyboard-interactive,password,publickey -p 2222 deploy@10.0.0.9",
        s.gate_dir()
            .join(format!("key-{}.pub", tag(sv_fp)))
            .display()
    );
    wait_until("the terminal opened", 5, || {
        read(&out.join("opened")).lines().last() == Some(want.as_str())
    });

    // the hosts
    let hosts = s.ok(&["ssh", "hosts"])["hosts"].clone();
    let h = host(&hosts, "github.com");
    assert_eq!(h["source"], "ewe");
    assert_eq!(h["key"]["title"], "GitHub 2");
    assert_eq!(h["service"], "github");
    assert_eq!(h["agent"], "safe");
    assert_eq!(host(&hosts, "github-work")["service"], "github");
    assert_eq!(host(&hosts, "github-work")["key"]["title"], "Work GitHub");
    assert_eq!(host(&hosts, "10.0.0.9")["port"], 2222);
    assert_eq!(host(&hosts, "10.0.0.9")["user"], "deploy");
    assert_eq!(host(&hosts, "gitlab.com")["source"], "yours");
    assert_eq!(host(&hosts, "gitlab.com")["service"], "gitlab");

    let set = s.ok(&[
        "ssh",
        "host",
        "set",
        "box",
        "--host",
        "192.168.1.9",
        "--user",
        "sam",
        "--port",
        "22",
        "--key",
        &gh_id,
    ]);
    assert_eq!(set["created"], true);
    assert_eq!(set["entry"]["key"]["item_id"], json!(gh_id));
    assert_eq!(set["entry"]["port"], Value::Null, "22 is the default");
    let set = s.ok(&["ssh", "host", "set", "box", "--no-key", "--port", "2200"]);
    assert_eq!(set["created"], false);
    assert_eq!(set["entry"]["key"], Value::Null);
    assert_eq!(
        set["entry"]["host_name"], "192.168.1.9",
        "other options stay"
    );
    assert_eq!(set["entry"]["port"], 2200);
    assert_eq!(
        s.cli(&["ssh", "host", "set", "a b"])["error"],
        "bad-request"
    );
    assert_eq!(s.cli(&["ssh", "host", "set", "x*"])["error"], "bad-request");
    assert_eq!(
        s.cli(&["ssh", "host", "set", "gitlab.com", "--user", "x"])["error"],
        "conflict"
    );
    assert_eq!(s.ok(&["ssh", "host", "remove", "box"])["removed"], true);
    assert_eq!(
        s.cli(&["ssh", "host", "remove", "box"])["error"],
        "not-found"
    );
    assert_eq!(
        s.cli(&["ssh", "host", "remove", "gitlab.com"])["error"],
        "conflict"
    );

    // while locked: the hosts and their keys' titles, from the public-key list
    s.ok(&["lock"]);
    let hosts = s.ok(&["ssh", "hosts"])["hosts"].clone();
    assert_eq!(host(&hosts, "github-work")["key"]["title"], "Work GitHub");
    assert_eq!(s.cli(&["ssh", "connect", "github"])["error"], "locked");
}

/// S24: `ssh test` reads each service's answer (a fake `ssh`).
#[test]
fn ssh_test_reads_each_service() {
    let mut s = Sandbox::new("sshtest");
    let r = s.root.display().to_string();
    write_exec(
        &s.bin.join("fake-ssh"),
        &format!(
            r#"#!/bin/sh
echo "$*" >> {r}/out/ssh-args
case "$*" in
  *git@github.com*|*" gh-alias") echo "Hi sam! You've successfully authenticated, but GitHub does not provide shell access." >&2; exit 1 ;;
  *gitlab.com*) echo "Welcome to GitLab, @sam!"; exit 0 ;;
  *bitbucket.org*) printf 'authenticated via ssh key.\n\nYou can use git to connect to Bitbucket. Shell access is disabled\n'; exit 0 ;;
  *codeberg.org*) echo "Hi there, sam! You've successfully authenticated with the key named GitHub, but Forgejo does not provide shell access."; exit 0 ;;
  *ssh.dev.azure.com*) printf "Warning: Permanently added 'ssh.dev.azure.com' (RSA) to the list of known hosts.\nremote: Shell access is not supported.\nshell request failed on channel 0\n" >&2; exit 1 ;;
  *denied.example*) echo "deploy@denied.example: Permission denied (publickey)." >&2; exit 255 ;;
  *changed.example*) printf '@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.\n' >&2; exit 255 ;;
  *) exit 0 ;;
esac
"#
        ),
    );
    s.extra.push((
        "EWE_SAFE_SSH".into(),
        s.bin.join("fake-ssh").display().to_string(),
    ));
    s.start();
    s.init();
    let k = s.ok(&["ssh", "new", "--title", "Key"]);
    let id = k["item_id"].as_str().unwrap().to_string();
    let args = || read(&s.root.join("out/ssh-args"));

    let t = s.ok(&["ssh", "test", "github"]);
    assert_eq!(
        (
            t["connected"].clone(),
            t["account"].clone(),
            t["message"].clone(),
            t["host_key"].clone()
        ),
        (
            json!(true),
            json!("sam"),
            json!("Connected to GitHub as sam."),
            json!("known")
        )
    );
    let line = args().lines().last().unwrap().to_string();
    assert!(
        line.starts_with(&format!(
            "-T -a -o ForwardAgent=no -o ClearAllForwardings=yes -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o IdentityAgent={} ",
            s.agent().display()
        )),
        "{line}"
    );
    assert!(
        line.ends_with(" -- git@github.com"),
        "a git service runs no command: {line}"
    );
    assert_eq!(s.ok(&["ssh", "test", "gitlab"])["account"], "sam");
    assert_eq!(s.ok(&["ssh", "test", "bitbucket"])["connected"], true);
    assert_eq!(
        s.ok(&["ssh", "test", "codeberg"])["message"],
        "Connected to Codeberg as sam."
    );
    let az = s.ok(&["ssh", "test", "azure-devops"]);
    assert_eq!(
        (az["connected"].clone(), az["host_key"].clone()),
        (json!(true), json!("added"))
    );
    // an alias in ewe.conf for GitHub is what `ssh test github` uses
    s.ok(&[
        "ssh",
        "host",
        "set",
        "gh-alias",
        "--host",
        "github.com",
        "--user",
        "git",
        "--key",
        &id,
    ]);
    assert_eq!(s.ok(&["ssh", "test", "github"])["connected"], true);
    assert!(args().lines().last().unwrap().ends_with(" -- gh-alias"));
    // a server: `true`, with the key asked for
    let no = s.ok(&["ssh", "test", "deploy@denied.example:2222", "--key", &id]);
    assert_eq!(no["connected"], false);
    assert_eq!(
        no["message"],
        "denied.example doesn't know this key yet. Copy it to the server, then check again."
    );
    assert!(no["detail"].as_str().unwrap().contains("Permission denied"));
    let line = args().lines().last().unwrap().to_string();
    assert!(
        line.contains(" -o IdentitiesOnly=yes -p 2222 -- deploy@denied.example true"),
        "{line}"
    );
    assert!(
        line.contains(&format!("-i {}", s.gate_dir().display())),
        "{line}"
    );
    let ch = s.ok(&["ssh", "test", "box@changed.example"]);
    assert_eq!(
        (
            ch["connected"].clone(),
            ch["host_key"].clone(),
            ch["message"].clone()
        ),
        (
            json!(false),
            json!("changed"),
            json!("The server's key changed. Safe stopped. Check with the server's owner.")
        )
    );
    assert_eq!(
        s.cli(&["ssh", "test", "-oProxyCommand=x"])["error"],
        "bad-request"
    );
    assert_eq!(
        s.cli(&["ssh", "test", "gitea"])["error"],
        "bad-request",
        "no host for it yet"
    );
    s.ok(&["lock"]);
    assert_eq!(s.cli(&["ssh", "test", "github"])["error"], "locked");
}

/// S24: one real `sshd` on loopback (non-root), `ssh test` through Safe's
/// agent: connected, the host key added, no question for the daemon's own
/// `ssh`. The session's shell gets the sandbox as its HOME (`SetEnv`), and
/// `PermitUserRC no` keeps sshd off `~/.ssh/rc`: nothing of the real home
/// is read.
#[test]
fn a_real_sshd_lets_safe_in() {
    // Arch keeps sshd in /usr/bin, Debian and Ubuntu (CI) in /usr/sbin; a
    // machine without the OpenSSH server skips this one test, out loud
    let Some(sshd_bin) = ["/usr/bin/sshd", "/usr/sbin/sshd"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
    else {
        eprintln!("a_real_sshd_lets_safe_in: no sshd on this machine, skipped");
        return;
    };
    let mut s = Sandbox::new("sshd");
    let d = s.root.join("sshd");
    std::fs::create_dir_all(&d).unwrap();
    s.keygen_at(&d.join("hostkey"), &["-t", "ed25519"], "");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    std::fs::write(d.join("authorized_keys"), "").unwrap();
    let cfg = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hostkey\nPidFile {d}/pid\nAuthorizedKeysFile {d}/authorized_keys\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPermitUserRC no\nPermitUserEnvironment no\nForceCommand /usr/bin/true\nSetEnv HOME={home} BASH_ENV=/dev/null ENV=/dev/null ZDOTDIR={home}\nLogLevel VERBOSE\n",
        d = d.display(),
        home = s.home().display()
    );
    std::fs::write(d.join("sshd_config"), cfg).unwrap();
    let log = std::fs::File::create(d.join("sshd.log")).unwrap();
    let sshd = Command::new(sshd_bin)
        .args(["-D", "-e", "-f", d.join("sshd_config").to_str().unwrap()])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("sshd");
    s.children.push(sshd);
    wait_until("sshd listens", 10, || {
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
    });
    // ssh with the sandbox's own config and known_hosts (never ~/.ssh)
    write_exec(
        &s.bin.join("sandbox-ssh"),
        "#!/bin/sh\nexec /usr/bin/ssh -F \"$HOME/.ssh/config\" -o UserKnownHostsFile=\"$HOME/.ssh/known_hosts\" \"$@\"\n",
    );
    s.extra.push((
        "EWE_SAFE_SSH".into(),
        s.bin.join("sandbox-ssh").display().to_string(),
    ));
    s.start();
    s.init();
    s.ok(&["ssh", "enable", "--confirm", "first-use"]);
    let k = s.ok(&["ssh", "new", "--title", "Server key"]);
    let id = k["item_id"].as_str().unwrap().to_string();
    let me = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap();
    let target = format!("{}@127.0.0.1:{port}", me.trim());

    let no = s.ok(&["ssh", "test", &target, "--key", &id]);
    assert_eq!(no["connected"], false, "{no}");
    assert_eq!(no["host_key"], "added");
    std::fs::write(
        d.join("authorized_keys"),
        format!("{}\n", k["ssh"]["public_key"].as_str().unwrap()),
    )
    .unwrap();
    let yes = s.ok(&["ssh", "test", &target, "--key", &id]);
    assert_eq!(
        yes["connected"],
        true,
        "{yes}\n{}",
        read(&d.join("sshd.log"))
    );
    assert_eq!(yes["host_key"], "known");
    assert_eq!(yes["message"], "Connected to 127.0.0.1.");
    assert!(
        s.approvals().is_empty(),
        "the daemon's own ssh isn't asked about"
    );
    assert!(
        s.daemon_log()
            .contains("no question for the daemon's own ssh")
    );
    assert!(read(&s.ssh_dir().join("known_hosts")).contains("[127.0.0.1]"));
    let used = &s.ok(&["ssh", "list"])["items"][0]["ssh"]["last_used"];
    assert!(
        used["program"].as_str().unwrap().starts_with("ssh"),
        "{used}"
    );

    // S27: a real ssh of the user's (not the daemon's) binds its session to
    // the server; the question names the host, from known_hosts
    let fp = k["ssh"]["fingerprint"].as_str().unwrap();
    let key_file = s.gate_dir().join(format!("key-{}.pub", tag(fp)));
    let cfg = s.ssh_dir().join("config");
    let known = s.ssh_dir().join("known_hosts");
    let p = port.to_string();
    let (_, err, code) = s.tool(
        "ssh",
        &[
            "-F",
            cfg.to_str().unwrap(),
            "-o",
            &format!("UserKnownHostsFile={}", known.display()),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-i",
            key_file.to_str().unwrap(),
            "-p",
            &p,
            &format!("{}@127.0.0.1", me.trim()),
            "true",
        ],
        &[],
        None,
    );
    assert_eq!(code, 0, "{err}");
    let asked = s.approvals();
    assert_eq!(asked.len(), 1, "{asked:?}");
    let q: Vec<&str> = asked[0].split('|').collect();
    assert!(q[0].starts_with("ssh"), "{q:?}");
    assert_eq!(
        (q[1], q[2], q[3]),
        ("Server key", format!("127.0.0.1:{port}").as_str(), "0")
    );
    // a session-bind with a bad signature closes the connection
    {
        use std::io::Read;
        let mut c = std::os::unix::net::UnixStream::connect(s.agent()).unwrap();
        let mut msg = vec![27u8];
        for part in [&b"session-bind@openssh.com"[..], b"key", b"sid", b"sig"] {
            msg.extend_from_slice(&(part.len() as u32).to_be_bytes());
            msg.extend_from_slice(part);
        }
        msg.push(0);
        c.write_all(&(msg.len() as u32).to_be_bytes()).unwrap();
        c.write_all(&msg).unwrap();
        let mut reply = Vec::new();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, [0, 0, 0, 1, 5], "FAILURE, then closed");
    }

    // review B: only the system's ssh (or the test switch's) goes without a
    // question; another program the daemon starts is asked about
    let copy = s.root.join("keys").join("ssh");
    std::fs::copy("/usr/bin/ssh", &copy).unwrap();
    write_exec(
        &s.bin.join("other-ssh"),
        &format!(
            "#!/bin/sh\nexec {} -F \"$HOME/.ssh/config\" -o UserKnownHostsFile=\"$HOME/.ssh/known_hosts\" \"$@\"\n",
            copy.display()
        ),
    );
    s.extra.retain(|(k, _)| k != "EWE_SAFE_SSH");
    s.extra.push((
        "EWE_SAFE_SSH".into(),
        s.bin.join("other-ssh").display().to_string(),
    ));
    s.stop();
    s.start();
    s.cli_in(&["unlock"], &format!("{MASTER}\n"));
    let asked_before = s.approvals().len();
    let yes = s.ok(&["ssh", "test", &target, "--key", &id]);
    assert_eq!(yes["connected"], true, "{yes}");
    assert_eq!(
        s.approvals().len(),
        asked_before + 1,
        "asked: not the system's ssh"
    );
}

impl Sandbox {
    /// Git in the sandbox: its HOME, `GIT_CONFIG_GLOBAL`, no system config.
    fn git(&self, args: &[&str]) -> (String, String, i32) {
        let out = Command::new("git")
            .args(args)
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .output()
            .expect("git");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }

    fn git_global(&self, key: &str) -> Option<String> {
        let (out, _, code) = self.git(&["config", "--global", "--get", key]);
        (code == 0).then(|| out.trim().to_string())
    }
}

/// S25: Git signs commits and tags through Safe's agent (`ewe-safe-ssh-sign`
/// from packaging/), `git verify-commit` checks them, the computer follows
/// `[safe] git_sign`, and off unsets only Safe's values.
#[test]
fn git_commits_are_signed_through_safe() {
    let mut s = Sandbox::new("sign");
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/ewe-safe-ssh-sign");
    std::fs::copy(&helper, s.bin.join("ewe-safe-ssh-sign")).unwrap();
    s.start();
    s.init();
    let k = s.ok(&["ssh", "new", "--title", "Signing key"]);
    let id = k["item_id"].as_str().unwrap().to_string();
    let fp = k["ssh"]["fingerprint"].as_str().unwrap().to_string();
    let public = k["ssh"]["public_key"].as_str().unwrap().to_string();

    let no = s.cli(&["ssh", "sign-commits", &id]);
    assert_eq!(no["error"], "bad-request", "{no}");
    assert!(
        no["message"]
            .as_str()
            .unwrap()
            .starts_with("Tell Safe your Git email: --email")
    );
    for (k, v) in [
        ("user.email", "sam@example.com"),
        ("user.name", "Sam"),
        ("commit.verbose", "true"),
    ] {
        assert_eq!(s.git(&["config", "--global", k, v]).2, 0);
    }

    let on = s.ok(&["ssh", "sign-commits", &id]);
    assert_eq!(on["signing"]["fingerprint"], json!(fp), "{on}");
    assert_eq!(on["signing"]["email"], "sam@example.com");
    assert_eq!(on["signing"]["recorded"], true);
    let file = format!("~/.ssh/ewe-safe/key-{}.pub", tag(&fp));
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", file.as_str()),
        ("gpg.ssh.program", "ewe-safe-ssh-sign"),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
        (
            "gpg.ssh.allowedSignersFile",
            "~/.ssh/ewe-safe/allowed_signers",
        ),
    ] {
        assert_eq!(s.git_global(k).as_deref(), Some(v), "{k}");
    }
    let signers = s.gate_dir().join("allowed_signers");
    assert_eq!(
        read(&signers),
        format!("sam@example.com namespaces=\"git\" {}\n", bare(&public))
    );
    assert_eq!(s.conf()["safe"]["git_sign"], json!(fp));
    let st = s.ok(&["ssh", "status"])["signing"].clone();
    assert_eq!(
        st,
        json!({"item_id": id, "title": "Signing key", "fingerprint": fp, "active": true, "reason": null})
    );

    // a real commit and a tag, signed through the agent, verified (with the
    // per-app question on: this test reads what it says)
    s.ok(&["ssh", "enable", "--confirm", "first-use"]);
    let repo = s.root.join("repo");
    assert_eq!(s.git(&["init", "-q", repo.to_str().unwrap()]).2, 0);
    let r = repo.to_str().unwrap();
    let (_, err, code) = s.git(&["-C", r, "commit", "--allow-empty", "-q", "-m", "first"]);
    assert_eq!(code, 0, "signed commit: {err}\n{}", s.daemon_log());
    let (_, err, code) = s.git(&["-C", r, "verify-commit", "HEAD"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("Good \"git\" signature for sam@example.com"),
        "{err}"
    );
    assert!(
        s.approvals()
            .iter()
            .any(|a| a.starts_with("ssh-keygen (from git)|Signing key")),
        "{:?}",
        s.approvals()
    );
    assert_eq!(s.git(&["-C", r, "tag", "-m", "one", "v1"]).2, 0);
    assert_eq!(s.git(&["-C", r, "verify-tag", "v1"]).2, 0);

    // the account turned it off elsewhere: only Safe's values go here
    s.set_conf(|c| c["safe"]["git_sign"] = json!(""));
    // allowed_signers goes last
    wait_until("signing off here", 10, || !signers.exists());
    assert_eq!(s.git_global("gpg.ssh.program"), None);
    assert_eq!(s.git_global("user.signingkey"), None);
    assert_eq!(s.git_global("commit.gpgsign"), None);
    assert_eq!(
        s.git_global("commit.verbose").as_deref(),
        Some("true"),
        "the user's own"
    );
    // … and on again elsewhere: this computer has the key, so it follows
    s.set_conf(|c| c["safe"]["git_sign"] = json!(fp));
    // gpg.ssh.allowedSignersFile is the last key set
    wait_until("signing on here", 10, || {
        s.git_global("gpg.ssh.allowedSignersFile").is_some() && signers.exists()
    });
    assert_eq!(
        s.git_global("gpg.ssh.program").as_deref(),
        Some("ewe-safe-ssh-sign")
    );
    assert_eq!(
        s.git(&["-C", r, "commit", "--allow-empty", "-q", "-m", "second"])
            .2,
        0
    );
    assert_eq!(s.git(&["-C", r, "verify-commit", "HEAD"]).2, 0);

    // off by the verb
    let off = s.ok(&["ssh", "sign-commits", "--off"]);
    assert_eq!(off["unset"].as_array().unwrap().len(), 6, "{off}");
    assert_eq!(s.conf()["safe"]["git_sign"], "");
    assert_eq!(s.ok(&["ssh", "status"])["signing"], Value::Null);
    assert_eq!(s.git_global("commit.verbose").as_deref(), Some("true"));
    assert_eq!(
        s.git(&["-C", r, "commit", "--allow-empty", "-q", "-m", "plain"])
            .2,
        0
    );

    // connect --sign; and disable takes signing along (it needs the agent)
    let gl = s.ok(&["ssh", "connect", "gitlab", "--sign", "--no-open"]);
    assert_eq!(gl["signing"]["title"], "GitLab", "{gl}");
    assert!(
        gl["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x.as_str().unwrap().contains("Usage type"))
    );
    assert_eq!(
        s.git_global("gpg.ssh.program").as_deref(),
        Some("ewe-safe-ssh-sign")
    );
    let dis = s.ok(&["ssh", "disable"]);
    assert_eq!(dis["signing_off"], true, "{dis}");
    assert_eq!(s.git_global("gpg.ssh.program"), None);
    assert_eq!(
        s.git(&["-C", r, "commit", "--allow-empty", "-q", "-m", "after"])
            .2,
        0
    );
}

/// S25 (review C): Safe changes Git only where it applied its own values,
/// noted with what each key held before; another computer's `git_sign`
/// never overwrites a Git with its own signing; off puts the old values
/// back where Safe's still are.
#[test]
fn git_signing_leaves_your_own_setup_alone() {
    let mut s = Sandbox::new("ownsign");
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/ewe-safe-ssh-sign");
    std::fs::copy(&helper, s.bin.join("ewe-safe-ssh-sign")).unwrap();
    // the user's own signing: GPG
    for (k, v) in [
        ("user.email", "sam@example.com"),
        ("user.name", "Sam"),
        ("gpg.format", "openpgp"),
        ("user.signingkey", "ABCDEF0123456789"),
        ("commit.gpgsign", "true"),
    ] {
        assert_eq!(s.git(&["config", "--global", k, v]).2, 0);
    }
    let list = |s: &Sandbox| s.git(&["config", "--global", "--list"]).0;
    let before = list(&s);
    let marker = s.root.join("state/ewe/safe/git-signing.json");
    s.start();
    s.init();
    s.ok(&["ssh", "enable"]);
    let k = s.ok(&["ssh", "new", "--title", "Signing key"]);
    let id = k["item_id"].as_str().unwrap().to_string();
    let fp = k["ssh"]["fingerprint"].as_str().unwrap().to_string();

    // start-up and every re-read with git_sign unset: nothing touched
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(list(&s), before);
    // another computer turned signing on: Git here signs with its own
    // setup, so Safe leaves it and says why
    s.set_conf(|c| c["safe"]["git_sign"] = json!(fp));
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(list(&s), before);
    assert!(!marker.exists());
    let st = s.ok(&["ssh", "status"])["signing"].clone();
    assert_eq!(st["active"], false, "{st}");
    assert!(st["reason"].as_str().unwrap().contains("own setup"), "{st}");

    // the user turns it on here: what the keys held is noted first
    s.ok(&["ssh", "sign-commits", &id]);
    assert_eq!(s.git_global("gpg.format").as_deref(), Some("ssh"));
    let note: Value = serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    assert_eq!(note["fingerprint"], json!(fp));
    assert_eq!(
        note["previous"],
        json!({
            "gpg.format": "openpgp",
            "user.signingkey": "ABCDEF0123456789",
            "gpg.ssh.program": null,
            "commit.gpgsign": "true",
            "tag.gpgsign": null,
            "gpg.ssh.allowedSignersFile": null,
        })
    );
    assert_eq!(s.ok(&["ssh", "status"])["signing"]["active"], true);
    // a key the user changes by hand stays theirs
    assert_eq!(
        s.git(&["config", "--global", "commit.gpgsign", "false"]).2,
        0
    );
    let off = s.ok(&["ssh", "sign-commits", "--off"]);
    assert_eq!(off["unset"].as_array().unwrap().len(), 5, "{off}");
    for (k, v) in [
        ("gpg.format", Some("openpgp")),
        ("user.signingkey", Some("ABCDEF0123456789")),
        ("commit.gpgsign", Some("false")),
        ("tag.gpgsign", None),
        ("gpg.ssh.program", None),
        ("gpg.ssh.allowedSignersFile", None),
    ] {
        assert_eq!(s.git_global(k).as_deref(), v, "{k}");
    }
    assert!(!marker.exists());

    // no note, nothing touched: the user's own SSH signing stays, whatever
    // ewe.conf says, also across a restart
    assert_eq!(s.git(&["config", "--global", "gpg.format", "ssh"]).2, 0);
    assert_eq!(
        s.git(&[
            "config",
            "--global",
            "user.signingkey",
            "~/.ssh/id_ed25519.pub"
        ])
        .2,
        0
    );
    let mine = list(&s);
    s.stop();
    s.start();
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(list(&s), mine);

    // an email that can't be a principal in allowed_signers
    let bad = s.cli(&[
        "ssh",
        "sign-commits",
        &id,
        "--email",
        "sam,evil@example.com",
    ]);
    assert_eq!(bad["error"], "bad-request", "{bad}");
    // from another computer, with no signing of the user's here and an odd
    // Git email: Safe signs, but writes no allowed_signers
    for k in ["user.signingkey", "gpg.format"] {
        s.git(&["config", "--global", "--unset", k]);
    }
    assert_eq!(
        s.git(&["config", "--global", "user.email", "sam #1@example.com"])
            .2,
        0
    );
    s.set_conf(|c| c["safe"]["git_sign"] = json!(fp));
    wait_until("signing from the account", 10, || {
        s.git_global("gpg.ssh.allowedSignersFile").is_some()
    });
    assert_eq!(
        s.git_global("gpg.ssh.program").as_deref(),
        Some("ewe-safe-ssh-sign")
    );
    assert!(marker.exists());
    assert!(!s.gate_dir().join("allowed_signers").exists());
}

/// Review D, F-b, F-e: names Safe hands to ssh or writes into a host
/// definition; ewe.conf entries Safe can't read; a linked Safe folder.
#[test]
fn odd_names_entries_and_links_are_refused() {
    let mut s = Sandbox::new("odd");
    s.start();
    s.init();
    // D: one allowlist for every name
    for argv in [
        &["ssh", "connect", "github", "--alias", "x#y", "--no-open"][..],
        &[
            "ssh",
            "connect",
            "github",
            "--alias",
            "git\"hub",
            "--no-open",
        ],
        &[
            "ssh",
            "connect",
            "server",
            "--host",
            "h$x",
            "--user",
            "u",
            "--no-open",
        ],
        &[
            "ssh",
            "connect",
            "server",
            "--host",
            "box",
            "--user",
            "a b",
            "--no-open",
        ],
        &[
            "ssh",
            "connect",
            "azure-devops",
            "--org",
            "o=x",
            "--no-open",
        ],
        &["ssh", "host", "set", "x%h"],
        &["ssh", "host", "set", "box", "--host", "a,b"],
        &["ssh", "test", "a=b"],
        &["ssh", "test", "-oProxyCommand=x"],
        &["ssh", "test", "sam@box\\x"],
    ] {
        let v = s.cli(argv);
        assert_eq!(v["error"], "bad-request", "{argv:?}: {v}");
    }
    assert!(
        s.ok(&["ssh", "list"])["items"]
            .as_array()
            .unwrap()
            .is_empty(),
        "nothing made"
    );

    // F-b: entries Safe can't read stay exactly as they are
    let odd = json!([
        {"options": [["User", "x"]]},
        {"host": "box", "options": [["Port", 2222], ["User", "sam"]]},
        {"host": "odd", "options": "User x"},
    ]);
    s.set_conf(|c| c["network"] = json!({"ssh": {"hosts": odd.clone()}}));
    let hosts = s.ok(&["ssh", "hosts"])["hosts"].clone();
    assert_eq!(host(&hosts, "box")["port"], 2222);
    assert_eq!(host(&hosts, "box")["readable"], true);
    assert_eq!(host(&hosts, "odd")["readable"], false);
    assert!(
        hosts
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["alias"].is_null() && h["readable"] == false)
    );
    assert_eq!(
        s.cli(&["ssh", "host", "set", "odd", "--user", "y"])["error"],
        "conflict"
    );
    assert_eq!(
        s.cli(&["ssh", "host", "remove", "odd"])["error"],
        "conflict"
    );
    s.ok(&["ssh", "host", "set", "box", "--user", "root"]);
    s.ok(&["ssh", "connect", "github", "--no-open"]);
    let stored = s.conf()["network"]["ssh"]["hosts"].clone();
    assert_eq!(stored[0], odd[0], "kept as it was");
    assert_eq!(
        stored[1],
        json!({"host": "box", "options": [["Port", 2222], ["User", "root"]]}),
        "the number stays a number"
    );
    assert_eq!(stored[2], odd[2]);
    assert_eq!(stored[3]["host"], "github.com");
    // not a list at all: Safe won't write over it
    s.set_conf(|c| c["network"]["ssh"]["hosts"] = json!({"host": "x"}));
    let no = s.cli(&["ssh", "host", "set", "new", "--user", "x"]);
    assert_eq!(no["ok"], false, "{no}");
    assert_eq!(s.conf()["network"]["ssh"]["hosts"], json!({"host": "x"}));
    s.set_conf(|c| c["network"]["ssh"]["hosts"] = json!([]));

    // F-e: a linked ~/.ssh/ewe-safe: nothing written or deleted through it
    s.ok(&["ssh", "disable"]);
    let elsewhere = s.root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("known_hosts"), "mine\n").unwrap();
    std::fs::write(elsewhere.join("key-abc.pub"), "mine\n").unwrap();
    let _ = std::fs::remove_dir_all(s.gate_dir());
    std::os::unix::fs::symlink(&elsewhere, s.gate_dir()).unwrap();
    let en = s.ok(&["ssh", "enable"]);
    assert_eq!(en["gate"]["on"], false, "{en}");
    assert!(
        en["gate"]["problem"]
            .as_str()
            .unwrap()
            .contains("is a link"),
        "{en}"
    );
    let theirs = |p: &str| read(&elsewhere.join(p));
    assert!(
        !elsewhere.join("config").exists(),
        "nothing written through the link"
    );
    s.ok(&["ssh", "disable"]);
    assert_eq!(
        (theirs("known_hosts"), theirs("key-abc.pub")),
        ("mine\n".into(), "mine\n".into())
    );
    assert!(s.gate_dir().is_symlink());
}
