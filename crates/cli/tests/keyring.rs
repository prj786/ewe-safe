//! The keyring verbs end to end (docs/KEYRING.md): the real `ewe-safe` and
//! `ewe-safed` in a sandbox (their own XDG folders, a fake `ewe-conf` and
//! `unix_chkpwd`), and — when the tools are installed — a real
//! gnome-keyring-daemon on a private `dbus-daemon` (a temp config with no
//! service files, so nothing else can start), shaped like the owner's
//! machine: `login` plus a second keyring that `default` names.
//!
//! Never the session bus: every process gets the private bus's address and
//! a cleared environment. Skipped, with a note, without dbus-daemon,
//! gnome-keyring-daemon, secret-tool or python-gobject.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

static N: AtomicUsize = AtomicUsize::new(0);

const LOGIN: &str = "/org/freedesktop/secrets/collection/login";

/// Shapes and reads the sandbox's gnome-keyring (one connection, the
/// session opened first, as gnome-keyring needs).
const GK: &str = r#"
import os, sys
import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib
bus = Gio.DBusConnection.new_for_address_sync(os.environ["DBUS_SESSION_BUS_ADDRESS"],
    Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
D = "org.freedesktop.secrets"; S = "/org/freedesktop/secrets"
def call(path, iface, method, args):
    return bus.call_sync(D, path, iface, method, args, None, Gio.DBusCallFlags.NONE, 10000, None).unpack()
sess = call(S, "org.freedesktop.Secret.Service", "OpenSession", GLib.Variant("(sv)", ("plain", GLib.Variant("s", ""))))[1]
def sec(v): return (sess, b"", v.encode(), "text/plain")
cmd, a = sys.argv[1], sys.argv[2:]
if cmd == "mkdefault":
    p = call(S, "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface", "CreateWithMasterPassword",
             GLib.Variant("(a{sv}(oayays))", ({"org.freedesktop.Secret.Collection.Label": GLib.Variant("s", a[0])}, sec(a[1]))))[0]
    call(S, "org.freedesktop.Secret.Service", "SetAlias", GLib.Variant("(so)", ("default", p)))
    print(p)
elif cmd == "put":
    props = {"org.freedesktop.Secret.Item.Label": GLib.Variant("s", a[1]),
             "org.freedesktop.Secret.Item.Attributes": GLib.Variant("a{ss}", dict(x.split("=", 1) for x in a[3:]))}
    call(a[0], "org.freedesktop.Secret.Collection", "CreateItem", GLib.Variant("(a{sv}(oayays)b)", (props, sec(a[2]), True)))
elif cmd == "alias":
    print(call(S, "org.freedesktop.Secret.Service", "ReadAlias", GLib.Variant("(s)", ("default",)))[0])
elif cmd == "find":
    items = call(a[0], "org.freedesktop.Secret.Collection", "SearchItems", GLib.Variant("(a{ss})", (dict(x.split("=", 1) for x in a[1:]),)))[0]
    got = call(S, "org.freedesktop.Secret.Service", "GetSecrets", GLib.Variant("(aoo)", (items, sess)))[0]
    print(",".join(sorted(bytes(v[2]).decode() for v in got.values())))
elif cmd == "count":
    print(len(call(a[0], "org.freedesktop.DBus.Properties", "Get", GLib.Variant("(ss)", ("org.freedesktop.Secret.Collection", "Items")))[0]))
"#;

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

fn have(tool: &str) -> bool {
    ["/usr/bin", "/bin"]
        .iter()
        .any(|d| Path::new(d).join(tool).exists())
}

struct Sandbox {
    root: PathBuf,
    run: PathBuf,
    bin: PathBuf,
    bus: Option<(Child, String)>,
    children: Vec<Child>,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        for c in self.children.iter_mut().rev() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
        if let Some((mut b, _)) = self.bus.take() {
            let _ = b.kill();
            let _ = b.wait();
        }
        let _ = std::fs::remove_dir_all(&self.run);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("safe-keyring-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // the socket paths must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/kr-{}-{n}", std::process::id()));
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
            "#!/bin/sh\n[ \"$1\" = get ] && { echo '{\"error\": \"no-key\"}'; exit 1; }\nexit 0\n",
        );
        // unix_chkpwd's protocol: the password NUL-ended on stdin
        write_exec(
            &bin.join("chkpwd"),
            "#!/usr/bin/env python3\nimport sys\nsys.exit(0 if sys.stdin.buffer.read().split(b'\\0')[0] == b'loginpw' else 1)\n",
        );
        std::fs::write(root.join("gk.py"), GK).expect("gk.py");
        Sandbox {
            root,
            run,
            bin,
            bus: None,
            children: Vec::new(),
        }
    }

    /// A private bus with no service files.
    fn bus(&mut self) {
        let conf = self.root.join("bus.conf");
        std::fs::write(
            &conf,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:dir={}</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy>
</busconfig>"#,
                self.run.display()
            ),
        )
        .expect("bus.conf");
        let mut child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", conf.display()))
            .args(["--nofork", "--print-address=1"])
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .expect("its address");
        self.bus = Some((child, line.trim().to_string()));
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
            ("EWE_SAFE_LOGIN_KDF".into(), "64,1,1".into()),
            ("EWE_SAFE_PROMPT_SECONDS".into(), "5".into()),
            (
                "EWE_SAFE_CHKPWD".into(),
                self.bin.join("chkpwd").display().to_string(),
            ),
            (
                "EWE_SAFE_PAM_MODULE".into(),
                self.root.join("no-module.so").display().to_string(),
            ),
        ];
        // without a private bus: an address that leads nowhere, never the
        // session's
        let bus = match &self.bus {
            Some((_, a)) => a.clone(),
            None => format!("unix:path={}/no-bus", self.run.display()),
        };
        env.push(("DBUS_SESSION_BUS_ADDRESS".into(), bus));
        env
    }

    fn spawn(&mut self, program: &str, args: &[&str], stdin: Option<&str>) {
        let mut c = Command::new(program);
        c.args(args)
            .env_clear()
            .envs(self.env())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let mut child = c.spawn().expect(program);
        if let Some(s) = stdin {
            child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        }
        self.children.push(child);
    }

    fn daemon(&mut self) {
        let d = daemon_exe().display().to_string();
        self.spawn(&d, &[], None);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.cli(&["ping"], None)["ok"] == true {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon didn't answer");
    }

    fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> String {
        let mut c = Command::new(program);
        c.args(args)
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = c.spawn().expect(program);
        let mut w = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            w.write_all(s.as_bytes()).unwrap();
        }
        drop(w);
        let out = child.wait_with_output().expect("output");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn cli(&self, args: &[&str], stdin: Option<&str>) -> Value {
        let out = self.run(&cli_exe().display().to_string(), args, stdin);
        serde_json::from_str(&out).unwrap_or_else(|_| panic!("not JSON: {out}"))
    }

    fn gk(&self, args: &[&str]) -> String {
        let script = self.root.join("gk.py").display().to_string();
        let mut a = vec![script.as_str()];
        a.extend_from_slice(args);
        self.run("python3", &a, None)
    }
}

#[test]
fn adopt_waits_for_the_login_module() {
    let mut s = Sandbox::new("adopt");
    s.daemon();
    let v = s.cli(&["keyring", "adopt"], Some("loginpw\n"));
    assert_eq!(v["error"], "needs-login-module", "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("ewe-safe keyring repair")
    );
    // the password is checked before anything else
    let v = s.cli(&["keyring", "adopt"], Some("wrong\n"));
    assert_eq!(v["error"], "wrong-key", "{v}");
    // status says nothing is adopted, and no bus is fine
    let st = s.cli(&["status"], None);
    assert_eq!(st["keyring"]["adopted"], false, "{st}");
    assert_eq!(st["keyring"]["serving"], false);
    assert_eq!(s.cli(&["keyring", "status"], None)["needs_repair"], false);
    // no keyring file appears from asking
    assert!(!s.root.join("state/ewe/safe/keyring.safe").exists());
    assert_eq!(s.cli(&["keyring", "nope"], None)["error"], "bad-request");
}

#[test]
fn repair_moves_a_second_default_keyring_into_login() {
    for tool in [
        "dbus-daemon",
        "gnome-keyring-daemon",
        "secret-tool",
        "python3",
    ] {
        if !have(tool) {
            eprintln!("skipped: no {tool}");
            return;
        }
    }
    let gi = Command::new("python3")
        .args(["-c", "import gi; gi.require_version('Gio', '2.0')"])
        .status()
        .is_ok_and(|s| s.success());
    if !gi {
        eprintln!("skipped: no python-gobject");
        return;
    }
    let mut s = Sandbox::new("repair");
    s.bus();
    s.spawn(
        "gnome-keyring-daemon",
        &["--unlock", "--components=secrets", "--foreground"],
        Some("loginpw"),
    );
    let start = Instant::now();
    while s.gk(&["alias"]).is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "gnome-keyring didn't start"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // the owner's machine: a second keyring that `default` names
    let old = s.gk(&["mkdefault", "Default keyring", "otherpw"]);
    assert!(old.ends_with("Default_5fkeyring"), "{old}");
    s.gk(&[
        "put",
        LOGIN,
        "cloud",
        "old-cloud",
        "service=ewe-cloud",
        "user=sam",
    ]);
    std::thread::sleep(Duration::from_millis(1100));
    let store = |label: &str, secret: &str, attrs: &[&str]| {
        let mut a = vec!["store", "--label", label];
        a.extend_from_slice(attrs);
        s.run("secret-tool", &a, Some(secret));
    };
    store(
        "ewe cloud",
        "new-cloud",
        &["service", "ewe-cloud", "user", "sam"],
    );
    store("ewe mail", "imap", &["service", "ewe-mail", "user", "sam"]);
    assert_eq!(s.gk(&["alias"]), old);
    s.daemon();
    let st = s.cli(&["keyring", "status"], None);
    assert_eq!(st["owner"], "gnome-keyring", "{st}");
    assert_eq!(st["default"], "Default_keyring");
    assert_eq!(st["needs_repair"], true);
    let list = s.cli(&["keyring", "list"], None);
    assert_eq!(list["items"].as_array().unwrap().len(), 3, "{list}");
    assert!(!list.to_string().contains("imap"), "no secret in a list");
    let dry = s.cli(&["keyring", "repair", "--dry-run"], None);
    assert_eq!(
        (dry["moved"].as_u64(), dry["conflicts"].as_u64()),
        (Some(1), Some(1)),
        "{dry}"
    );
    assert_eq!(s.gk(&["alias"]), old, "a dry run changes nothing");
    let r = s.cli(&["keyring", "repair"], None);
    assert_eq!(r["fixed"], true, "{r}");
    assert_eq!(r["default_was"], "Default_keyring");
    assert_eq!(
        (
            r["moved"].as_u64(),
            r["duplicates"].as_u64(),
            r["conflicts"].as_u64(),
            r["replaced"].as_u64()
        ),
        (Some(1), Some(0), Some(1), Some(1))
    );
    assert!(
        r["hint"]
            .as_str()
            .unwrap()
            .contains("Default_keyring.keyring")
    );
    assert_eq!(s.gk(&["alias"]), LOGIN);
    assert_eq!(s.gk(&["find", LOGIN, "service=ewe-cloud"]), "new-cloud");
    assert_eq!(s.gk(&["find", LOGIN, "service=ewe-mail"]), "imap");
    assert_eq!(
        s.gk(&["count", &old]),
        "2",
        "the old keyring stays as it was"
    );
    let lookup = s.run(
        "secret-tool",
        &["lookup", "service", "ewe-mail", "user", "sam"],
        None,
    );
    assert_eq!(lookup, "imap");
    let again = s.cli(&["keyring", "repair"], None);
    assert_eq!(again["already"], true, "{again}");
    assert_eq!(s.cli(&["keyring", "status"], None)["needs_repair"], false);
}
