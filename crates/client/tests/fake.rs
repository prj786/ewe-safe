//! safe_client against a fake daemon: a UnixListener in a temporary
//! directory that answers the way ewe-safed does (docs/PROTOCOL.md).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use safe_client::{Connection, Next, scrub, subscribe_at};
use serde_json::{Value, json};

static N: AtomicUsize = AtomicUsize::new(0);

/// A short path: sun_path is 108 bytes.
fn sock() -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir = PathBuf::from(format!("/tmp/sc-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("s.sock")
}

/// Serve one connection with `f`, which gets every request line and the
/// stream to answer on; the requests it saw come back on the channel.
fn serve(f: impl Fn(&Value, &mut UnixStream) + Send + 'static) -> (PathBuf, mpsc::Receiver<Value>) {
    let path = sock();
    let l = UnixListener::bind(&path).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        for line in BufReader::new(s).lines() {
            let Ok(line) = line else { return };
            let req: Value = serde_json::from_str(&line).unwrap();
            f(&req, &mut w);
            let _ = tx.send(req);
        }
    });
    (path, rx)
}

fn answer(w: &mut UnixStream, v: Value) {
    let mut line = v.to_string();
    line.push('\n');
    w.write_all(line.as_bytes()).unwrap();
}

#[test]
fn a_missing_socket_is_daemon_unavailable() {
    let path = sock();
    let v = match Connection::open_at(&path) {
        Ok(_) => panic!("connected to nothing"),
        Err(v) => v,
    };
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"], "daemon-unavailable");
    assert!(v["hint"].as_str().unwrap().contains("ewe-safe.socket"));
}

#[test]
fn a_reply_comes_back_without_v_and_id() {
    let (path, rx) = serve(|req, w| {
        answer(
            w,
            json!({"v": 1, "id": req["id"], "ok": true, "pong": true}),
        );
    });
    let mut c = Connection::open_at(&path).unwrap();
    let v = c.call("ping", json!({}), Duration::from_secs(5));
    assert_eq!(v, json!({"ok": true, "pong": true}));
    let req = rx.recv().unwrap();
    assert_eq!(req["v"], 1);
    assert_eq!(req["verb"], "ping");
    assert_eq!(req["args"], json!({}));
}

#[test]
fn ids_count_up_and_other_ids_are_skipped() {
    let (path, rx) = serve(|req, w| {
        // a stray line first: a reply to someone else's id
        answer(w, json!({"v": 1, "id": 999, "ok": true, "stray": true}));
        answer(
            w,
            json!({"v": 1, "id": req["id"], "ok": true, "verb": req["verb"]}),
        );
    });
    let mut c = Connection::open_at(&path).unwrap();
    let a = c.call("status", json!({}), Duration::from_secs(5));
    let b = c.call("list", json!({"kind": "login"}), Duration::from_secs(5));
    assert_eq!(a["verb"], "status");
    assert_eq!(b["verb"], "list");
    assert!(a.get("stray").is_none() && b.get("stray").is_none());
    assert_eq!(rx.recv().unwrap()["id"], 1);
    let second = rx.recv().unwrap();
    assert_eq!(second["id"], 2);
    assert_eq!(second["args"], json!({"kind": "login"}));
}

#[test]
fn silence_is_a_timeout_not_a_hang() {
    let (path, _rx) = serve(|_req, _w| {});
    let mut c = Connection::open_at(&path).unwrap();
    let v = c.call("status", json!({}), Duration::from_millis(200));
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"], "internal");
}

#[test]
fn a_hang_up_is_daemon_unavailable() {
    let path = sock();
    let l = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut line = String::new();
        let _ = BufReader::new(&s).read_line(&mut line);
        drop(s);
    });
    let mut c = Connection::open_at(&path).unwrap();
    let v = c.call("status", json!({}), Duration::from_secs(5));
    assert_eq!(v["error"], "daemon-unavailable");
}

#[test]
fn secrets_travel_in_args_and_are_wiped_from_the_request() {
    let (path, rx) = serve(|req, w| {
        answer(w, json!({"v": 1, "id": req["id"], "ok": true, "items": 0}));
    });
    let mut c = Connection::open_at(&path).unwrap();
    let v = c.call(
        "unlock",
        json!({"password": "correct horse battery"}),
        Duration::from_secs(5),
    );
    assert_eq!(v["ok"], true);
    // the daemon got it, once, inside args
    let req = rx.recv().unwrap();
    assert_eq!(req["args"]["password"], "correct horse battery");
}

#[test]
fn scrub_empties_every_secret_key_and_nothing_else() {
    let mut a = json!({
        "password": "p1",
        "new_password": "p2",
        "password_value": "p3",
        "notes": "n",
        "title": "Discord",
    });
    scrub(&mut a);
    for k in ["password", "new_password", "password_value", "notes"] {
        assert_eq!(a[k], "", "{k} not wiped");
    }
    assert_eq!(a["title"], "Discord");
}

#[test]
fn events_stream_until_the_daemon_goes_away() {
    let path = sock();
    let l = UnixListener::bind(&path).unwrap();
    let (go, wait) = mpsc::channel::<()>();
    thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).unwrap();
        let req: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["verb"], "subscribe");
        answer(
            &mut w,
            json!({"v": 1, "id": req["id"], "ok": true, "subscribed": true}),
        );
        answer(&mut w, json!({"v": 1, "event": "unlocked"}));
        answer(
            &mut w,
            json!({"v": 1, "event": "locked", "reason": "screen"}),
        );
        wait.recv().unwrap();
        drop(w);
        drop(s);
    });
    let mut ev = subscribe_at(&path).unwrap();
    let wait = Duration::from_secs(5);
    match ev.next(wait) {
        Next::Event(v) => assert_eq!(v, json!({"event": "unlocked"})),
        _ => panic!("no unlocked event"),
    }
    match ev.next(wait) {
        Next::Event(v) => assert_eq!(v, json!({"event": "locked", "reason": "screen"})),
        _ => panic!("no locked event"),
    }
    assert!(matches!(ev.next(Duration::from_millis(150)), Next::Quiet));
    go.send(()).unwrap();
    assert!(matches!(ev.next(wait), Next::Closed));
}

#[test]
fn a_refused_subscription_is_its_error() {
    let (path, _rx) = serve(|req, w| {
        answer(
            w,
            json!({"v": 1, "id": req["id"], "ok": false, "error": "bad-request", "message": "no"}),
        );
    });
    match subscribe_at(&path) {
        Ok(_) => panic!("subscribed"),
        Err(v) => assert_eq!(v["error"], "bad-request"),
    }
}
