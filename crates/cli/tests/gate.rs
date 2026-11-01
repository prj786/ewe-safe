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
    json.dump(d, open(p, "w"))
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
    let en = s.ok(&["ssh", "enable"]);
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

    // an ewe-conf that doesn't answer changes nothing
    write_exec(&s.bin.join("ewe-conf"), "#!/bin/sh\nexit 2\n");
    std::thread::sleep(Duration::from_secs(3));
    assert!(s.gate_dir().join("config").exists());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), with_line);
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
