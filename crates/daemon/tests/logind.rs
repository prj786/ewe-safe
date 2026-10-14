//! Lock with the screen and before sleep, against a stand-in logind on a
//! private bus (never the machine's own): `LockedHint` turning true and
//! `PrepareForSleep(true)` lock the safe, with the reason in the event.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zbus::blocking::connection::Builder;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;

const SESSION: &str = "/org/freedesktop/login1/session/c1";
const USER: &str = "/org/freedesktop/login1/user/_1000";

struct Manager;

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn get_user(&self, _uid: u32) -> OwnedObjectPath {
        OwnedObjectPath::try_from(USER).unwrap()
    }

    fn get_session(&self, _id: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(SESSION).unwrap()
    }

    #[zbus(signal)]
    async fn prepare_for_sleep(emitter: &SignalEmitter<'_>, start: bool) -> zbus::Result<()>;
}

struct User;

#[zbus::interface(name = "org.freedesktop.login1.User")]
impl User {
    #[zbus(property)]
    fn display(&self) -> (String, OwnedObjectPath) {
        (
            "c1".to_string(),
            OwnedObjectPath::try_from(SESSION).unwrap(),
        )
    }
}

struct Session {
    locked: bool,
}

#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl Session {
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.locked
    }
}

struct Bus(Child);

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn call(sock: &Path, verb: &str, args: Value) -> Value {
    let mut s = UnixStream::connect(sock).expect("connect");
    let line = json!({"v": 1, "id": 1, "verb": verb, "args": args}).to_string() + "\n";
    s.write_all(line.as_bytes()).unwrap();
    let mut reply = String::new();
    BufReader::new(&s).read_line(&mut reply).unwrap();
    serde_json::from_str(&reply).unwrap()
}

fn locked(sock: &Path) -> bool {
    call(sock, "status", json!({}))["locked"] == true
}

fn wait(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn the_screen_lock_and_sleep_lock_the_safe() {
    if Command::new("dbus-daemon")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("no dbus-daemon here: skipped");
        return;
    }
    let root = std::env::temp_dir().join(format!("safed-logind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let run = PathBuf::from(format!("/tmp/sl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&run);
    for d in [
        root.join("state"),
        root.join("data"),
        root.join("config"),
        root.join("bin"),
        run.clone(),
    ] {
        std::fs::create_dir_all(&d).unwrap();
    }
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();

    // a private bus, and logind on it
    let mut bus = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .arg(format!("--address=unix:path={}/bus", root.display()))
        .stdout(Stdio::piped())
        .spawn()
        .expect("dbus-daemon");
    let mut addr = String::new();
    BufReader::new(bus.stdout.take().unwrap())
        .read_line(&mut addr)
        .unwrap();
    let addr = addr.trim().to_string();
    let _bus = Bus(bus);
    let logind = Builder::address(addr.as_str())
        .unwrap()
        .name("org.freedesktop.login1")
        .unwrap()
        .serve_at("/org/freedesktop/login1", Manager)
        .unwrap()
        .serve_at(USER, User)
        .unwrap()
        .serve_at(SESSION, Session { locked: false })
        .unwrap()
        .build()
        .expect("logind");

    let sock = run.join("ewe-safe.sock");
    let _daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_ewe-safed"))
            .env_clear()
            .env("HOME", &root)
            .env("PATH", root.join("bin"))
            .env("XDG_RUNTIME_DIR", &run)
            .env("XDG_STATE_HOME", root.join("state"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("EWE_SAFE_KDF_ITERATIONS", "2")
            .env("EWE_SAFE_LOGIND_BUS", &addr)
            .stderr(Stdio::null())
            .spawn()
            .expect("ewe-safed"),
    );
    wait("the daemon", || UnixStream::connect(&sock).is_ok());
    let v = call(&sock, "init", json!({"place": "local", "password": "pw"}));
    assert_eq!(v["ok"], true, "{v}");
    assert!(!locked(&sock));

    // the shell's Lock.qml sets LockedHint
    let session = logind
        .object_server()
        .interface::<_, Session>(SESSION)
        .unwrap();
    session.get_mut().locked = true;
    zbus::block_on(session.get().locked_hint_changed(session.signal_emitter())).unwrap();
    wait("the screen lock", || locked(&sock));

    // unlock; the screen unlocking changes nothing; then the lid closes
    assert_eq!(call(&sock, "unlock", json!({"password": "pw"}))["ok"], true);
    session.get_mut().locked = false;
    zbus::block_on(session.get().locked_hint_changed(session.signal_emitter())).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!locked(&sock), "LockedHint false doesn't lock");
    let manager = logind
        .object_server()
        .interface::<_, Manager>("/org/freedesktop/login1")
        .unwrap();
    zbus::block_on(Manager::prepare_for_sleep(manager.signal_emitter(), false)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!locked(&sock), "waking up doesn't lock");
    zbus::block_on(Manager::prepare_for_sleep(manager.signal_emitter(), true)).unwrap();
    wait("the sleep lock", || locked(&sock));

    let _ = std::fs::remove_dir_all(&run);
    let _ = std::fs::remove_dir_all(&root);
}
