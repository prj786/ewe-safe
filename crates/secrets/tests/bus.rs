//! The keyring on a private `dbus-daemon` of its own (a temp config, no
//! service files: nothing can be activated), driven as a client would:
//! plain and dh sessions, CreateItem through the `default` alias with
//! replace, the locked keyring's search and its prompt, Dismiss, another
//! client's session, and the importer reading it all back. Never the
//! session bus: every connection names the private bus's address. Skipped
//! (with a note) when `dbus-daemon` isn't installed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use safe_login::SessionKey;
use safe_secrets::crypto::{self, KeyPair};
use safe_secrets::{Asking, Files, KeySource, Keyring, Secret};
use zbus::blocking::{Connection, Proxy};
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const DEST: &str = "org.freedesktop.secrets";
const SVC: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
const DEFAULT: &str = "/org/freedesktop/secrets/aliases/default";

struct Bus {
    child: Child,
    address: String,
    _dir: tempfile::TempDir,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bus() -> Option<Bus> {
    let exe = ["/usr/bin/dbus-daemon", "/bin/dbus-daemon"]
        .into_iter()
        .find(|p| Path::new(p).exists())?;
    let dir = tempfile::tempdir().ok()?;
    let conf = dir.path().join("bus.conf");
    std::fs::write(
        &conf,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>"#,
            dir.path().display()
        ),
    )
    .ok()?;
    let mut child = Command::new(exe)
        .arg(format!("--config-file={}", conf.display()))
        .args(["--nofork", "--print-address=1"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut line = String::new();
    BufReader::new(child.stdout.take()?)
        .read_line(&mut line)
        .ok()?;
    Some(Bus {
        child,
        address: line.trim().to_string(),
        _dir: dir,
    })
}

macro_rules! need_bus {
    () => {
        match bus() {
            Some(b) => b,
            None => {
                eprintln!("skipped: no dbus-daemon");
                return;
            }
        }
    };
}

fn connect(b: &Bus) -> Connection {
    zbus::blocking::connection::Builder::address(b.address.as_str())
        .and_then(|x| x.build())
        .expect("the private bus")
}

/// W on demand: `ask` hands it over shortly after (as the window does),
/// unless `refuse`.
#[derive(Default)]
struct Keys {
    w: Mutex<Option<SessionKey>>,
    cv: Condvar,
    give: Mutex<Option<SessionKey>>,
    asked: AtomicUsize,
}

impl Keys {
    fn set(&self, w: SessionKey) {
        *self.w.lock().unwrap() = Some(w);
        self.cv.notify_all();
    }
}

struct Window(Arc<Keys>, std::time::Instant);

impl Asking for Window {
    fn finished(&mut self) -> bool {
        self.0.w.lock().unwrap().is_some() || self.1.elapsed() > Duration::from_millis(400)
    }
    fn stop(&mut self) {}
}

struct Source(Arc<Keys>);

impl KeySource for Source {
    fn key(&self) -> Option<SessionKey> {
        self.0.w.lock().unwrap().clone()
    }
    fn wait(&self, timeout: Duration) -> Option<SessionKey> {
        let g = self.0.w.lock().unwrap();
        let (g, _) = self
            .0
            .cv
            .wait_timeout_while(g, timeout, |w| w.is_none())
            .unwrap();
        g.clone()
    }
    fn ask(&self) -> Option<Box<dyn Asking>> {
        self.0.asked.fetch_add(1, Ordering::SeqCst);
        if let Some(w) = self.0.give.lock().unwrap().clone() {
            let k = self.0.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                k.set(w);
            });
        }
        Some(Box::new(Window(self.0.clone(), std::time::Instant::now())))
    }
    fn log(&self, _msg: &str) {}
}

fn files(dir: &Path) -> Files {
    Files {
        sealed: dir.join("keyring.safe"),
        index: dir.join("keyring.index"),
    }
}

fn proxy<'a>(c: &Connection, path: &'a str, iface: &'a str) -> Proxy<'a> {
    zbus::blocking::proxy::Builder::new(c)
        .destination(DEST)
        .unwrap()
        .path(path)
        .unwrap()
        .interface(iface)
        .unwrap()
        .cache_properties(CacheProperties::No)
        .build()
        .unwrap()
}

fn plain(c: &Connection) -> OwnedObjectPath {
    let (_, s): (OwnedValue, OwnedObjectPath) = proxy(c, SVC, SERVICE)
        .call("OpenSession", &("plain", Value::from("")))
        .unwrap();
    s
}

fn store(
    c: &Connection,
    session: &OwnedObjectPath,
    label: &str,
    attrs: &[(&str, &str)],
    secret: &[u8],
) -> OwnedObjectPath {
    let attrs: HashMap<String, String> = attrs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
    props.insert("org.freedesktop.Secret.Item.Attributes", Value::from(attrs));
    let s = Secret {
        session: session.clone(),
        parameters: Vec::new(),
        value: secret.to_vec(),
        content_type: "text/plain".into(),
    };
    let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = proxy(c, DEFAULT, COLLECTION)
        .call("CreateItem", &(props, s, true))
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    item
}

fn search(c: &Connection, attrs: &[(&str, &str)]) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
    let attrs: HashMap<&str, &str> = attrs.iter().copied().collect();
    proxy(c, SVC, SERVICE)
        .call("SearchItems", &(attrs,))
        .unwrap()
}

fn secret_of(c: &Connection, item: &OwnedObjectPath, session: &OwnedObjectPath) -> Vec<u8> {
    let (s,): (Secret,) = proxy(c, item.as_str(), ITEM)
        .call("GetSecret", &(session,))
        .unwrap();
    s.value.clone()
}

fn serve(b: &Bus, dir: &Path, keys: Arc<Keys>) -> (Keyring, Connection) {
    let conn = connect(b);
    let k = Keyring::new(files(dir), Arc::new(Source(keys)));
    assert!(k.serve(&conn).unwrap(), "we own the name");
    (k, conn)
}

#[test]
fn an_app_stores_finds_and_replaces_a_secret() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let (k, _server) = serve(&b, dir.path(), keys);
    let app = connect(&b);
    let s = plain(&app);
    let a = [("service", "ewe-cloud"), ("user", "sam")];
    let item = store(&app, &s, "ewe cloud", &a, b"app-password-1");
    assert_eq!(item.as_str(), "/org/freedesktop/secrets/collection/login/1");
    let (unlocked, locked) = search(&app, &[("service", "ewe-cloud")]);
    assert_eq!((unlocked, locked.len()), (vec![item.clone()], 0));
    assert_eq!(secret_of(&app, &item, &s), b"app-password-1");
    // replace: the same attributes are the same item
    let again = store(&app, &s, "ewe cloud", &a, b"app-password-2");
    assert_eq!(again, item);
    assert_eq!(secret_of(&app, &item, &s), b"app-password-2");
    assert_eq!(k.count(), 1);
    // the properties libsecret reads
    let i = proxy(&app, item.as_str(), ITEM);
    assert_eq!(i.get_property::<String>("Label").unwrap(), "ewe cloud");
    assert!(!i.get_property::<bool>("Locked").unwrap());
    let attrs: HashMap<String, String> = i.get_property("Attributes").unwrap();
    assert_eq!(attrs.get("user").map(String::as_str), Some("sam"));
    let svc = proxy(&app, SVC, SERVICE);
    let alias: OwnedObjectPath = svc.call("ReadAlias", &("default",)).unwrap();
    assert_eq!(alias.as_str(), "/org/freedesktop/secrets/collection/login");
    let cols: Vec<OwnedObjectPath> = svc.get_property("Collections").unwrap();
    assert_eq!(cols, vec![alias.clone()]);
    let coll = proxy(&app, alias.as_str(), COLLECTION);
    assert!(!coll.get_property::<bool>("Locked").unwrap());
    assert_eq!(
        coll.get_property::<Vec<OwnedObjectPath>>("Items").unwrap(),
        vec![item.clone()]
    );
    // another client can't use this client's session
    let other = connect(&b);
    let e = proxy(&other, item.as_str(), ITEM)
        .call::<_, _, (Secret,)>("GetSecret", &(&s,))
        .unwrap_err();
    assert!(e.to_string().contains("NoSession"), "{e}");
    // delete
    let p: OwnedObjectPath = i.call("Delete", &()).unwrap();
    assert_eq!(p.as_str(), "/");
    assert_eq!(search(&app, &[]).0.len(), 0);
    assert_eq!(k.count(), 0);
}

#[test]
fn the_dh_session_encrypts_both_ways() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let (_k, _server) = serve(&b, dir.path(), keys);
    let app = connect(&b);
    let pair = KeyPair::generate();
    let (out, session): (OwnedValue, OwnedObjectPath) = proxy(&app, SVC, SERVICE)
        .call(
            "OpenSession",
            &(crypto::DH, Value::from(pair.public.clone())),
        )
        .unwrap();
    let theirs = Vec::<u8>::try_from(out).unwrap();
    let key = pair.aes_key(&theirs).expect("their public value");
    let ps = plain(&app);
    let item = store(
        &app,
        &ps,
        "mail",
        &[("service", "ewe-mail")],
        b"imap-secret",
    );
    let (s,): (Secret,) = proxy(&app, item.as_str(), ITEM)
        .call("GetSecret", &(&session,))
        .unwrap();
    assert_eq!(s.parameters.len(), 16);
    assert_ne!(s.value, b"imap-secret");
    assert_eq!(
        &crypto::decrypt(&key, &s.parameters, &s.value).unwrap()[..],
        b"imap-secret"
    );
    // SetSecret, encrypted for the session
    let (iv, ct) = crypto::encrypt(&key, b"new-imap-secret");
    let new = Secret {
        session: session.clone(),
        parameters: iv,
        value: ct,
        content_type: "text/plain".into(),
    };
    let () = proxy(&app, item.as_str(), ITEM)
        .call("SetSecret", &(new,))
        .unwrap();
    assert_eq!(secret_of(&app, &item, &ps), b"new-imap-secret");
    // an algorithm Safe doesn't speak: NotSupported (libsecret falls back)
    let e = proxy(&app, SVC, SERVICE)
        .call::<_, _, (OwnedValue, OwnedObjectPath)>("OpenSession", &("rot13", Value::from("")))
        .unwrap_err();
    assert!(e.to_string().contains("NotSupported"), "{e}");
}

fn wait_completed(c: &Connection, prompt: &OwnedObjectPath, dismiss: bool) -> (bool, OwnedValue) {
    let p = proxy(c, prompt.as_str(), PROMPT);
    let mut done = p.receive_signal("Completed").unwrap();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        if let Some(m) = done.next() {
            let _ = tx.send(m.body().deserialize::<(bool, OwnedValue)>().unwrap());
        }
    });
    if dismiss {
        let () = p.call("Dismiss", &()).unwrap();
    } else {
        let () = p.call("Prompt", &("",)).unwrap();
    }
    rx.recv_timeout(Duration::from_secs(10)).expect("Completed")
}

#[test]
fn a_locked_keyring_finds_items_and_opens_through_its_prompt() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let w = SessionKey::generate();
    // first run: an item, saved under W
    {
        let keys = Arc::new(Keys::default());
        keys.set(w.clone());
        let (k, server) = serve(&b, dir.path(), keys);
        let app = connect(&b);
        let s = plain(&app);
        store(&app, &s, "a", &[("service", "ewe-cloud")], b"one");
        store(&app, &s, "b", &[("service", "other")], b"two");
        k.release().unwrap();
        drop(server);
    }
    // a restart: no W yet
    let keys = Arc::new(Keys::default());
    let (k, _server) = serve(&b, dir.path(), keys.clone());
    assert!(!k.is_open());
    assert_eq!(k.count(), 2, "known from the index while locked");
    let app = connect(&b);
    let (unlocked, locked) = search(&app, &[("service", "ewe-cloud")]);
    assert!(unlocked.is_empty());
    assert_eq!(
        locked,
        vec![OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login/1").unwrap()]
    );
    let coll = proxy(&app, DEFAULT, COLLECTION);
    assert!(coll.get_property::<bool>("Locked").unwrap());
    // Dismiss: nothing opens
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = proxy(&app, SVC, SERVICE)
        .call("Unlock", &(locked.clone(),))
        .unwrap();
    assert_ne!(prompt.as_str(), "/");
    let (dismissed, _) = wait_completed(&app, &prompt, true);
    assert!(dismissed);
    assert!(!k.is_open());
    // the window brings W
    *keys.give.lock().unwrap() = Some(w.clone());
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = proxy(&app, SVC, SERVICE)
        .call("Unlock", &(locked.clone(),))
        .unwrap();
    let (dismissed, result) = wait_completed(&app, &prompt, false);
    assert!(!dismissed);
    let opened = Vec::<OwnedObjectPath>::try_from(result).unwrap();
    assert_eq!(opened, locked);
    assert!(k.is_open());
    assert_eq!(keys.asked.load(Ordering::SeqCst), 1, "one window");
    let s = plain(&app);
    assert_eq!(secret_of(&app, &locked[0], &s), b"one");
    assert!(!coll.get_property::<bool>("Locked").unwrap());
}

#[test]
fn create_item_while_locked_waits_for_the_key() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    *keys.give.lock().unwrap() = Some(SessionKey::generate());
    let (k, _server) = serve(&b, dir.path(), keys);
    let app = connect(&b);
    let s = plain(&app);
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Value::from("later"));
    let secret = Secret {
        session: s.clone(),
        parameters: Vec::new(),
        value: b"pw".to_vec(),
        content_type: "text/plain".into(),
    };
    let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = proxy(&app, DEFAULT, COLLECTION)
        .call("CreateItem", &(props, secret, true))
        .unwrap();
    assert_eq!(item.as_str(), "/");
    let (dismissed, result) = wait_completed(&app, &prompt, false);
    assert!(!dismissed);
    let made = OwnedObjectPath::try_from(result).unwrap();
    assert_eq!(secret_of(&app, &made, &s), b"pw");
    assert_eq!(k.count(), 1);
}

#[test]
fn the_importer_reads_a_keyring_through_its_api() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let (_k, server) = serve(&b, dir.path(), keys);
    let app = connect(&b);
    let s = plain(&app);
    store(
        &app,
        &s,
        "cloud",
        &[("service", "ewe-cloud"), ("user", "sam")],
        b"one",
    );
    // a second collection, named by an alias
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work"),
    );
    let (work, _): (OwnedObjectPath, OwnedObjectPath) = proxy(&app, SVC, SERVICE)
        .call("CreateCollection", &(props, "work"))
        .unwrap();
    assert_eq!(work.as_str(), "/org/freedesktop/secrets/collection/work");
    let mut iprops: HashMap<&str, Value<'_>> = HashMap::new();
    iprops.insert("org.freedesktop.Secret.Item.Label", Value::from("vpn"));
    let sec = Secret {
        session: s.clone(),
        parameters: Vec::new(),
        value: b"two".to_vec(),
        content_type: "text/plain".into(),
    };
    let (_item, _): (OwnedObjectPath, OwnedObjectPath) = proxy(&app, work.as_str(), COLLECTION)
        .call("CreateItem", &(iprops, sec, false))
        .unwrap();
    let reader = connect(&b);
    let read = safe_secrets::client::read_all(&reader, Duration::from_secs(5)).unwrap();
    assert_eq!(read.locked, 0);
    let names: Vec<(&str, bool, usize)> = read
        .collections
        .iter()
        .map(|c| (c.name.as_str(), c.default, c.items.len()))
        .collect();
    assert_eq!(names, vec![("login", true, 1), ("work", false, 1)]);
    let one = &read.collections[0].items[0];
    assert_eq!(&one.secret[..], b"one");
    assert_eq!(one.label, "cloud");
    assert_eq!(one.attributes.get("user").map(String::as_str), Some("sam"));
    assert!(one.created > 0 && one.modified >= one.created);
    let (owner, pid) = safe_secrets::client::owner(&reader).unwrap();
    assert_eq!(
        Some(owner.as_str()),
        server.unique_name().map(|n| n.as_str())
    );
    assert_eq!(pid, Some(std::process::id()));
}

fn new_collection(c: &Connection, label: &str) -> OwnedObjectPath {
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert(
        "org.freedesktop.Secret.Collection.Label",
        Value::from(label),
    );
    let (path, _): (OwnedObjectPath, OwnedObjectPath) = proxy(c, SVC, SERVICE)
        .call("CreateCollection", &(props, ""))
        .unwrap();
    path
}

fn lookup(c: &Connection, s: &OwnedObjectPath, coll: &str, attrs: &[(&str, &str)]) -> Vec<Vec<u8>> {
    let attrs: HashMap<&str, &str> = attrs.iter().copied().collect();
    let found: Vec<OwnedObjectPath> = proxy(c, coll, COLLECTION)
        .call("SearchItems", &(attrs,))
        .unwrap();
    found.iter().map(|p| secret_of(c, p, s)).collect()
}

/// The owner's machine: `login`, and a second keyring that `default` names
/// (where apps wrote). The repair moves everything into `login`.
#[test]
fn repair_moves_the_second_keyring_into_login() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let (_k, _server) = serve(&b, dir.path(), keys.clone());
    let app = connect(&b);
    let s = plain(&app);
    let login = "/org/freedesktop/secrets/collection/login";
    let old = new_collection(&app, "Default keyring");
    // in login already: one the same, one that will be older
    let put = |coll: &str, label: &str, attrs: &[(&str, &str)], secret: &[u8]| {
        let attrs: HashMap<String, String> = attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut props: HashMap<&str, Value<'_>> = HashMap::new();
        props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        props.insert("org.freedesktop.Secret.Item.Attributes", Value::from(attrs));
        let sec = Secret {
            session: s.clone(),
            parameters: Vec::new(),
            value: secret.to_vec(),
            content_type: "text/plain".into(),
        };
        let _: (OwnedObjectPath, OwnedObjectPath) = proxy(&app, coll, COLLECTION)
            .call("CreateItem", &(props, sec, true))
            .unwrap();
    };
    put(login, "same", &[("service", "same")], b"s1");
    put(login, "cloud", &[("service", "ewe-cloud")], b"old-cloud");
    std::thread::sleep(Duration::from_millis(1100));
    put(old.as_str(), "same", &[("service", "same")], b"s1");
    put(
        old.as_str(),
        "cloud",
        &[("service", "ewe-cloud")],
        b"new-cloud",
    );
    put(old.as_str(), "mail", &[("service", "ewe-mail")], b"imap");
    let () = proxy(&app, SVC, SERVICE)
        .call("SetAlias", &("default", &old))
        .unwrap();
    let reader = connect(&b);
    // a dry run changes nothing
    let dry = safe_secrets::repair::repair(&reader, true, Duration::from_secs(5)).unwrap();
    assert_eq!(dry.default_was.as_deref(), Some("default_keyring"));
    assert_eq!(
        (dry.moved, dry.duplicates, dry.conflicts, dry.replaced),
        (1, 1, 1, 1)
    );
    assert!(lookup(&app, &s, login, &[("service", "ewe-mail")]).is_empty());
    let r = safe_secrets::repair::repair(&reader, false, Duration::from_secs(5)).unwrap();
    assert_eq!(
        (r.moved, r.duplicates, r.conflicts, r.replaced, r.skipped),
        (1, 1, 1, 1, 0)
    );
    assert_eq!(r.sources, vec!["default_keyring".to_string()]);
    let alias: OwnedObjectPath = proxy(&app, SVC, SERVICE)
        .call("ReadAlias", &("default",))
        .unwrap();
    assert_eq!(alias.as_str(), login);
    assert_eq!(
        lookup(&app, &s, login, &[("service", "ewe-mail")]),
        vec![b"imap".to_vec()]
    );
    assert_eq!(
        lookup(&app, &s, login, &[("service", "ewe-cloud")]),
        vec![b"new-cloud".to_vec()]
    );
    assert_eq!(lookup(&app, &s, login, &[("service", "same")]).len(), 1);
    // the old keyring is untouched
    assert_eq!(lookup(&app, &s, old.as_str(), &[]).len(), 3);
    // a second run: nothing to do
    let again = safe_secrets::repair::repair(&reader, false, Duration::from_secs(5)).unwrap();
    assert!(again.already);
    assert_eq!(again.default_was.as_deref(), Some("login"));
}

#[test]
fn repair_refuses_without_a_login_collection() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let (_k, _server) = serve(&b, dir.path(), keys);
    let app = connect(&b);
    let other = new_collection(&app, "Other");
    let () = proxy(&app, SVC, SERVICE)
        .call("SetAlias", &("default", &other))
        .unwrap();
    let () = proxy(
        &app,
        "/org/freedesktop/secrets/collection/login",
        COLLECTION,
    )
    .call::<_, _, OwnedObjectPath>("Delete", &())
    .map(|_| ())
    .unwrap();
    let e = safe_secrets::repair::repair(&connect(&b), false, Duration::from_secs(5)).unwrap_err();
    assert_eq!(e, safe_secrets::repair::Error::NoLogin);
}

#[test]
fn the_carrier_keeps_w_in_login_and_never_prompts() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let w = SessionKey::generate();
    {
        let keys = Arc::new(Keys::default());
        keys.set(SessionKey::generate());
        let (k, server) = serve(&b, dir.path(), keys);
        let c = connect(&b);
        safe_secrets::carrier::store_on(&c, &w, "m1").unwrap();
        // again: replaced, not a second item
        safe_secrets::carrier::store_on(&c, &w, "m1").unwrap();
        assert_eq!(k.count(), 1);
        assert_eq!(safe_secrets::carrier::fetch_on(&c, "m1"), Some(w.clone()));
        assert_eq!(safe_secrets::carrier::fetch_on(&c, "m2"), None);
        let s = plain(&c);
        let (found, _) = search(&c, &[("application", "ewe-safe"), ("machine", "m1")]);
        let i = proxy(&c, found[0].as_str(), ITEM);
        assert_eq!(
            i.get_property::<String>("Label").unwrap(),
            safe_secrets::carrier::LABEL
        );
        let _ = s;
        k.release().unwrap();
        drop(server);
    }
    // the keyring locked (another start, no key yet): no item, no prompt
    let keys = Arc::new(Keys::default());
    let (_k, _server) = serve(&b, dir.path(), keys.clone());
    let c = connect(&b);
    let other = SessionKey::generate();
    *keys.give.lock().unwrap() = Some(other);
    assert_eq!(safe_secrets::carrier::fetch_on(&c, "m1"), None);
    assert!(safe_secrets::carrier::store_on(&c, &w, "m1").is_err());
    assert!(safe_secrets::carrier::delete_on(&c, "m1").is_err());
    assert_eq!(keys.asked.load(Ordering::SeqCst), 0, "never a window");
}

#[test]
fn the_carrier_goes_away_with_delete() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let (_k, _server) = serve(&b, dir.path(), keys);
    let c = connect(&b);
    let w = SessionKey::generate();
    safe_secrets::carrier::store_on(&c, &w, "m1").unwrap();
    assert!(safe_secrets::carrier::delete_on(&c, "m1").unwrap());
    assert!(!safe_secrets::carrier::delete_on(&c, "m1").unwrap());
    assert_eq!(safe_secrets::carrier::fetch_on(&c, "m1"), None);
}

#[test]
fn nothing_answers_when_no_keyring_runs() {
    let b = need_bus!();
    let c = connect(&b);
    assert_eq!(safe_secrets::carrier::fetch_on(&c, "m1"), None);
    assert!(safe_secrets::client::owner(&c).is_none());
    assert_eq!(
        safe_secrets::repair::repair(&c, true, Duration::from_secs(1)).unwrap_err(),
        safe_secrets::repair::Error::NoKeyring
    );
    assert!(safe_secrets::client::list(&c).is_err());
}

#[test]
fn list_reads_names_without_secrets_or_prompts() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let (_k, _server) = serve(&b, dir.path(), keys);
    let app = connect(&b);
    let s = plain(&app);
    store(&app, &s, "ewe cloud", &[("service", "ewe-cloud")], b"x");
    let (items, locked) = safe_secrets::client::list(&connect(&b)).unwrap();
    assert!(locked.is_empty());
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].meta.label, "ewe cloud");
    assert_eq!(items[0].collection, "login");
}

/// adopt imports before it takes the name: every object must still be on
/// the bus once it serves (the alias `default` too).
#[test]
fn what_was_merged_before_serving_is_on_the_bus() {
    let b = need_bus!();
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    keys.set(SessionKey::generate());
    let k = Keyring::new(files(dir.path()), Arc::new(Source(keys)));
    assert!(k.wake());
    let m = k
        .merge(vec![safe_secrets::Incoming {
            collection: "login".into(),
            collection_label: "Login".into(),
            label: "imported".into(),
            attributes: [("service".to_string(), "x".to_string())].into(),
            secret: zeroize::Zeroizing::new(b"old".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 1,
        }])
        .unwrap();
    assert_eq!(m.added, 1);
    let conn = connect(&b);
    assert!(k.serve(&conn).unwrap());
    let app = connect(&b);
    let s = plain(&app);
    let item = store(&app, &s, "new", &[("service", "y")], b"new");
    assert_eq!(item.as_str(), "/org/freedesktop/secrets/collection/login/2");
    let (found, _) = search(&app, &[("service", "x")]);
    assert_eq!(secret_of(&app, &found[0], &s), b"old");
}
