//! The SSH agent (TRIO.md S2; the ssh-agent protocol,
//! draft-miller-ssh-agent): `ssh` and `git` use the keys in the safe
//! through `$XDG_RUNTIME_DIR/ewe-safe-ssh.sock` (0600, `SO_PEERCRED`: same
//! uid or no answer). The socket is activated with the main one (a second
//! `ListenStream` in `ewe-safe.socket`), or bound here.
//!
//! - `REQUEST_IDENTITIES`: every SSH key item an agent may use. While the
//!   safe is locked the list comes from `ssh-public.json` (public keys and
//!   their names only), written whenever the unlocked safe changes.
//! - `SIGN_REQUEST`: ed25519, ecdsa-sha2-nistp256/384, rsa-sha2-256/512.
//!   Locked: the unlock prompt opens (`ewe-safe unlock --ask`) and the
//!   request waits for it.
//! - Approval: the first use of a key by an app in each unlock asks "Allow
//!   ssh (from git) to use GitHub key?" (`[safe] ssh_confirm`). No answer
//!   in time is a no.
//! - Every other request (adding or removing keys, locking the agent, …)
//!   is refused: the keys come from Safe.
//!
//! Nothing here logs a title or a value.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use safe_core::Kind;
use safe_core::ssh as keys;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config::{self, Paths};
use crate::daemon::{Daemon, Fail, lk, rd};
use crate::log;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
/// Requests that would put keys in or take them out (SSH2 and the old
/// SSH1 ones, smartcards, lock/unlock): all refused.
const KEY_CHANGES: [u8; 12] = [1, 7, 8, 9, 17, 18, 19, 20, 21, 22, 23, 25];
/// OpenSSH's own limit on a message.
const MAX_MESSAGE: usize = 256 * 1024;
/// How long the unlock prompt and the approval prompt wait for the user.
const PROMPT_WAIT: Duration = Duration::from_secs(60);

/// The agent's socket from systemd, when the unit passed one.
static ACTIVATED: Mutex<Option<RawFd>> = Mutex::new(None);
/// The agent's socket when bound here: removed at exit.
static BOUND: Mutex<Option<PathBuf>> = Mutex::new(None);
/// The running agent, for the `ssh-*` verbs.
static AGENT: OnceLock<Arc<Agent>> = OnceLock::new();

pub fn get() -> Option<&'static Arc<Agent>> {
    AGENT.get()
}

/// `EWE_SAFE_PROMPT_SECONDS` is a test switch: a shorter wait.
fn prompt_wait() -> Duration {
    std::env::var("EWE_SAFE_PROMPT_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(PROMPT_WAIT)
}

/// The path a listening unix socket is bound to.
fn bound_path(fd: RawFd) -> Option<Vec<u8>> {
    // SAFETY: getsockname fills at most `len` bytes of a zeroed sockaddr_un
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let r =
        unsafe { libc::getsockname(fd, (&mut addr as *mut libc::sockaddr_un).cast(), &mut len) };
    if r != 0 || i32::from(addr.sun_family) != libc::AF_UNIX {
        return None;
    }
    Some(
        addr.sun_path
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect(),
    )
}

/// A socket systemd passed: the agent's when it is bound to
/// `…/ewe-safe-ssh.sock` (server.rs asks for each one).
pub fn claim(fd: RawFd) -> bool {
    let ours =
        bound_path(fd).is_some_and(|p| p.ends_with(format!("/{}", config::SSH_SOCKET).as_bytes()));
    if ours {
        *lk(&ACTIVATED) = Some(fd);
    }
    ours
}

/// The agent's listening socket: systemd's, or bound here (0600). Another
/// process answering on the path keeps it.
fn listen(paths: &Paths) -> Result<UnixListener, String> {
    if let Some(fd) = lk(&ACTIVATED).take() {
        // SAFETY: systemd passed this fd, and claim() took it for us alone
        return Ok(unsafe { UnixListener::from_raw_fd(fd) });
    }
    let path = paths.ssh_socket();
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            return Err(format!("something already answers on {}", path.display()));
        }
        let _ = std::fs::remove_file(&path);
    }
    // SAFETY: umask only changes this process's file-mode mask
    let old = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(&path);
    unsafe { libc::umask(old) };
    let l = bound.map_err(|e| format!("can't listen on {}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("can't make {} private: {e}", path.display()))?;
    *lk(&BOUND) = Some(path);
    Ok(l)
}

/// At exit: the socket goes when it was bound here.
pub fn cleanup() {
    if let Some(p) = lk(&BOUND).take() {
        let _ = std::fs::remove_file(p);
    }
}

pub struct Agent {
    d: Arc<Daemon>,
    /// (app, public key) pairs allowed since the safe was unlocked.
    allowed: Mutex<HashSet<(String, String)>>,
    /// One approval prompt at a time.
    asking: Mutex<()>,
    /// One unlock prompt at a time.
    unlocking: Mutex<()>,
    /// What `ssh-public.json` holds now.
    cached: Mutex<String>,
    listening: Mutex<bool>,
}

/// One key the agent offers.
struct Identity {
    blob: Vec<u8>,
    comment: String,
}

/// Start the agent: its socket, and the watcher that keeps the public-key
/// list and forgets approvals when the safe locks.
pub fn spawn(d: Arc<Daemon>) -> Arc<Agent> {
    let a = Arc::new(Agent {
        d: d.clone(),
        allowed: Mutex::new(HashSet::new()),
        asking: Mutex::new(()),
        unlocking: Mutex::new(()),
        cached: Mutex::new(String::new()),
        listening: Mutex::new(false),
    });
    let rx = d.subscribe();
    let w = a.clone();
    std::thread::spawn(move || {
        while let Ok(line) = rx.recv() {
            let event = serde_json::from_str::<Value>(&line)
                .ok()
                .and_then(|v| v.get("event").and_then(Value::as_str).map(str::to_string));
            match event.as_deref() {
                Some("locked") => lk(&w.allowed).clear(),
                Some("unlocked" | "changed") => w.write_cache(),
                _ => {}
            }
        }
    });
    match listen(&d.paths) {
        Ok(l) => {
            *lk(&a.listening) = true;
            let srv = a.clone();
            std::thread::spawn(move || {
                for conn in l.incoming() {
                    match conn {
                        Ok(s) => {
                            let a = srv.clone();
                            std::thread::spawn(move || a.serve(s));
                        }
                        Err(e) => log(&format!("ssh agent: accept: {e}")),
                    }
                }
            });
        }
        Err(e) => log(&format!("no SSH agent: {e}")),
    }
    let _ = AGENT.set(a.clone());
    a
}

impl Agent {
    pub fn listening(&self) -> bool {
        *lk(&self.listening)
    }

    /// The keys an agent may use, from the unlocked safe.
    fn unlocked_keys(&self) -> Option<Vec<(String, String, String)>> {
        let snap = rd(&self.d.snap);
        if snap.locked {
            return None;
        }
        Some(
            snap.items
                .iter()
                .filter(|s| s.kind == Kind::SshKey)
                .filter_map(|s| {
                    let info = s.ssh.as_ref().filter(|i| i.agent)?;
                    (!info.public_key.is_empty())
                        .then(|| (s.id.clone(), s.title.clone(), info.public_key.clone()))
                })
                .collect(),
        )
    }

    /// `ssh-public.json` from the unlocked safe, when it changed.
    pub fn write_cache(&self) {
        let Some(found) = self.unlocked_keys() else {
            return;
        };
        let keys: Vec<Value> = found
            .iter()
            .filter_map(|(_, title, line)| {
                Some(json!({"public_key": keys::public_line(&keys::public_blob(line)?)?, "comment": title}))
            })
            .collect();
        let text = format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({"v": 1, "keys": keys})).unwrap_or_default()
        );
        let mut cached = lk(&self.cached);
        let path = self.d.paths.ssh_public();
        // no key, and never one: no file
        if *cached == text || (keys.is_empty() && cached.is_empty() && !path.exists()) {
            return;
        }
        let written = path
            .parent()
            .map_or(Ok(()), |dir| {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
            })
            .and_then(|()| safe_core::atomic::write(&path, text.as_bytes()));
        match written {
            Ok(()) => *cached = text,
            Err(e) => log(&format!("ssh agent: can't write the public-key list: {e}")),
        }
    }

    /// The keys from `ssh-public.json` (the safe is locked).
    fn cached_keys(&self) -> Vec<Identity> {
        let Ok(bytes) = std::fs::read(self.d.paths.ssh_public()) else {
            return Vec::new();
        };
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        v.get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|k| {
                Some(Identity {
                    blob: keys::public_blob(k.get("public_key")?.as_str()?)?,
                    comment: k
                        .get("comment")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                })
            })
            .collect()
    }

    /// What `REQUEST_IDENTITIES` answers: nothing while the agent is off.
    fn identities(&self) -> Vec<Identity> {
        if !self.d.settings().ssh_agent {
            return Vec::new();
        }
        let mut out: Vec<Identity> = match self.unlocked_keys() {
            Some(found) => found
                .into_iter()
                .filter_map(|(_, title, line)| {
                    Some(Identity {
                        blob: keys::public_blob(&line)?,
                        comment: title,
                    })
                })
                .collect(),
            None => self.cached_keys(),
        };
        // the same key in two items is offered once
        let mut seen = HashSet::new();
        out.retain(|i| seen.insert(i.blob.clone()));
        out
    }

    /// How many keys the agent offers now (`ssh-status`).
    pub fn key_count(&self) -> usize {
        self.unlocked_keys()
            .map(|k| k.len())
            .unwrap_or_else(|| self.cached_keys().len())
    }

    fn serve(&self, mut s: UnixStream) {
        // SAFETY: getuid has no failure mode
        let me = unsafe { libc::getuid() };
        let Some((uid, pid)) = peer_cred(&s) else {
            return;
        };
        if uid != me {
            return;
        }
        let peer = Peer::of(pid);
        loop {
            let mut len = [0u8; 4];
            if s.read_exact(&mut len).is_err() {
                return;
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > MAX_MESSAGE {
                return;
            }
            let mut body = Zeroizing::new(vec![0u8; n]);
            if s.read_exact(&mut body).is_err() {
                return;
            }
            let reply = self.answer(&peer, &body);
            let mut out = Vec::with_capacity(reply.len() + 4);
            out.extend_from_slice(&(reply.len() as u32).to_be_bytes());
            out.extend_from_slice(&reply);
            if s.write_all(&out).and_then(|()| s.flush()).is_err() {
                return;
            }
        }
    }

    fn answer(&self, peer: &Peer, body: &[u8]) -> Vec<u8> {
        match body[0] {
            REQUEST_IDENTITIES => {
                let ids = self.identities();
                let mut out = vec![IDENTITIES_ANSWER];
                out.extend_from_slice(&(ids.len() as u32).to_be_bytes());
                for i in ids {
                    put_string(&mut out, &i.blob);
                    put_string(&mut out, i.comment.as_bytes());
                }
                out
            }
            SIGN_REQUEST => {
                let mut rest = &body[1..];
                let parsed = (|| {
                    let blob = take_string(&mut rest)?;
                    let data = take_string(&mut rest)?;
                    let flags = take_u32(&mut rest)?;
                    Some((blob, data, flags))
                })();
                match parsed.and_then(|(blob, data, flags)| self.sign(peer, blob, data, flags)) {
                    Some(sig) => {
                        let mut out = vec![SIGN_RESPONSE];
                        put_string(&mut out, &sig);
                        out
                    }
                    None => vec![FAILURE],
                }
            }
            t if KEY_CHANGES.contains(&t) => {
                log("ssh agent: refused to add or remove keys (they come from Safe)");
                vec![FAILURE]
            }
            // extensions (session-bind@openssh.com, query) and the rest
            _ => vec![FAILURE],
        }
    }

    fn sign(&self, peer: &Peer, blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>> {
        if !self.d.settings().ssh_agent || !self.identities().iter().any(|i| i.blob == blob) {
            return None;
        }
        if rd(&self.d.snap).locked && !self.wait_unlocked() {
            log(&format!(
                "ssh agent: still locked, no signature for {}",
                peer.label
            ));
            return None;
        }
        // the safe is open: which item holds the key now
        let (id, title, _) = self
            .unlocked_keys()?
            .into_iter()
            .find(|(_, _, line)| keys::public_blob(line).as_deref() == Some(blob))?;
        let key = keys::public_line(blob).unwrap_or_default();
        if !self.approved(peer, &key, &title) {
            log(&format!("ssh agent: {} was not allowed", peer.label));
            return None;
        }
        let private = self
            .d
            .with_held(|h| h.safe.ssh_private(&id).map_err(Fail::from));
        let (text, pass) = match private {
            Ok(x) => x,
            Err(f) => {
                log(&format!("ssh agent: the key can't be read ({})", f.code));
                return None;
            }
        };
        match keys::sign(&text, &pass, data, flags) {
            Ok(sig) => {
                log(&format!("ssh agent: signed for {}", peer.label));
                Some(sig)
            }
            Err(e) => {
                log(&format!("ssh agent: {e}"));
                None
            }
        }
    }

    /// Open the unlock prompt (`ewe-safe unlock --ask`, the same prompt the
    /// picker opens) and wait for the safe to open.
    fn wait_unlocked(&self) -> bool {
        let _one = lk(&self.unlocking);
        let snap_ok = |d: &Daemon| {
            let s = rd(&d.snap);
            (s.set_up, s.locked)
        };
        match snap_ok(&self.d) {
            (false, _) => return false,
            (true, false) => return true,
            _ => {}
        }
        // the prompt the CLI opens, and the test switches it honours
        let mut env = display_env(&self.d.paths);
        for k in ["EWE_SAFE_ASK_CMD", "EWE_SAFE_SOCKET"] {
            if let Ok(v) = std::env::var(k) {
                env.push((k.to_string(), v));
            }
        }
        let mut child = match prompt(cli().as_os_str(), &["unlock", "--ask"], &env)
            .stdout(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                log(&format!("ssh agent: can't open the unlock prompt ({e})"));
                return false;
            }
        };
        let start = Instant::now();
        let wait = prompt_wait();
        loop {
            std::thread::sleep(Duration::from_millis(150));
            if !snap_ok(&self.d).1 {
                let _ = child.try_wait();
                return true;
            }
            if let Ok(Some(_)) = child.try_wait() {
                return !snap_ok(&self.d).1;
            }
            if start.elapsed() > wait {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }

    /// `[safe] ssh_confirm`: `never` asks nothing, `every-time` asks every
    /// time, `first-use` once per app and key until the safe locks.
    fn approved(&self, peer: &Peer, key: &str, title: &str) -> bool {
        let mode = self.d.settings().ssh_confirm;
        if mode == "never" {
            return true;
        }
        let pair = (peer.identity.clone(), key.to_string());
        let first_use = mode == config::CONFIRM_FIRST_USE;
        if first_use && lk(&self.allowed).contains(&pair) {
            return true;
        }
        let _one = lk(&self.asking);
        // allowed while this request waited for the other prompt
        if first_use && lk(&self.allowed).contains(&pair) {
            return true;
        }
        let yes = ask(&self.d.paths, &peer.label, title);
        if yes && first_use {
            lk(&self.allowed).insert(pair);
        }
        yes
    }
}

// ── the wire ────────────────────────────────────────────────────────────

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn take_u32(rest: &mut &[u8]) -> Option<u32> {
    let (n, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    Some(u32::from_be_bytes(*n))
}

fn take_string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = take_u32(rest)? as usize;
    if rest.len() < n {
        return None;
    }
    let (s, tail) = rest.split_at(n);
    *rest = tail;
    Some(s)
}

fn peer_cred(s: &UnixStream) -> Option<(u32, i32)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a ucred of exactly `len` bytes on a valid fd
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (r == 0).then_some((cred.uid, cred.pid))
}

// ── who is asking ───────────────────────────────────────────────────────

/// The app on the other end, from `SO_PEERCRED`'s pid: "ssh (from git)".
struct Peer {
    label: String,
    /// What an approval is remembered by: the program and its parent's.
    identity: String,
}

/// (the program's path, its short name), or None for a pid that is gone.
fn program(pid: i32) -> Option<(String, String)> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        });
    match exe {
        Some(path) => {
            let name = Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| comm.clone());
            Some((path, name))
        }
        None => Some((comm.clone(), comm)),
    }
}

fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // "pid (comm) state ppid …": comm may hold spaces and parentheses
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

impl Peer {
    fn of(pid: i32) -> Peer {
        let Some((path, name)) = (pid > 0).then(|| program(pid)).flatten() else {
            return Peer {
                label: "an app".to_string(),
                identity: "?".to_string(),
            };
        };
        let parent = parent_of(pid).filter(|p| *p > 1).and_then(program);
        match parent {
            Some((ppath, pname)) if pname != name => Peer {
                label: format!("{name} (from {pname})"),
                identity: format!("{path}\n{ppath}"),
            },
            Some((ppath, _)) => Peer {
                label: name,
                identity: format!("{path}\n{ppath}"),
            },
            None => Peer {
                label: name,
                identity: path,
            },
        }
    }
}

// ── prompts ─────────────────────────────────────────────────────────────

/// `ewe-safe` next to this binary, or on the PATH.
fn cli() -> PathBuf {
    std::env::current_exe()
        .ok()
        .map(|p| p.with_file_name("ewe-safe"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("ewe-safe"))
}

fn on_path(name: &str) -> Option<PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .map(|p| p.with_file_name(name))
        .filter(|p| p.is_file());
    beside.or_else(|| {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}

/// A prompt needs the session's display: the daemon's own when the session
/// passed it on (ewe's autostart imports it into the user manager),
/// otherwise the Wayland socket in `$XDG_RUNTIME_DIR`.
fn display_env(paths: &Paths) -> Vec<(String, String)> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return Vec::new();
    }
    let found = std::fs::read_dir(&paths.runtime).ok().and_then(|dir| {
        let mut names: Vec<String> = dir
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("wayland-") && !n.ends_with(".lock"))
            .collect();
        names.sort();
        names.into_iter().next()
    });
    found
        .map(|n| vec![("WAYLAND_DISPLAY".to_string(), n)])
        .unwrap_or_default()
}

/// A prompt's command, `env` added. Under systemd (`INVOCATION_ID`) the
/// daemon runs in ewe-safe.service's sandbox (no memory both writable and
/// executable, a private /tmp, …) and a child inherits it: a window's
/// JavaScript engine may not run so. There the prompt runs as a transient
/// user unit of its own, `systemd-run --user --wait --pipe`, whose exit
/// status is the prompt's; `--setenv=NAME` hands it `env` from systemd-run's
/// own environment, so no value is on a command line.
fn prompt(program: &OsStr, args: &[&str], env: &[(String, String)]) -> Command {
    let run = on_path("systemd-run").filter(|_| std::env::var_os("INVOCATION_ID").is_some());
    prompt_in(run, program, args, env)
}

fn prompt_in(
    run: Option<PathBuf>,
    program: &OsStr,
    args: &[&str],
    env: &[(String, String)],
) -> Command {
    let mut c = match run {
        Some(run) => {
            let mut c = Command::new(run);
            c.args(["--user", "--quiet", "--collect", "--wait", "--pipe"]);
            for (k, _) in env {
                c.arg(format!("--setenv={k}"));
            }
            c.arg("--").arg(program).args(args);
            c
        }
        None => {
            let mut c = Command::new(program);
            c.args(args);
            c
        }
    };
    c.envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    c
}

/// Wait for a prompt; a prompt still open when the time is up is closed.
fn finish(mut child: Child, wait: Duration) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) if start.elapsed() < wait => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// "Allow `app` to use `key`?" — yes only on an explicit allow.
///
/// - `EWE_SAFE_APPROVE_CMD` (tests, or a user's own prompt): `sh -c`;
///   exit 0 is Allow.
/// - the Safe window's prompt, `ewe-safe-app --approve`: exit 0 is Allow.
/// - else a notification with an Allow action (`notify-send --wait`):
///   ewe's notification server runs the default action on a click; closing
///   it, or no click in time, is Deny.
///
/// The app and the key's name travel in `EWE_SAFE_APPROVE_APP` and
/// `EWE_SAFE_APPROVE_KEY`, never on a command line (the notification's
/// text excepted).
fn ask(paths: &Paths, app: &str, key: &str) -> bool {
    let wait = prompt_wait();
    let mut env = display_env(paths);
    env.push(("EWE_SAFE_APPROVE_APP".into(), app.to_string()));
    env.push(("EWE_SAFE_APPROVE_KEY".into(), key.to_string()));
    let answered = |mut c: Command| {
        c.stdout(Stdio::null())
            .spawn()
            .ok()
            .and_then(|ch| finish(ch, wait))
            .is_some_and(|st| st.success())
    };
    if let Some(cmd) = std::env::var("EWE_SAFE_APPROVE_CMD")
        .ok()
        .filter(|c| !c.is_empty())
    {
        return answered(prompt(OsStr::new("sh"), &["-c", &cmd], &env));
    }
    if let Some(app_bin) = on_path("ewe-safe-app") {
        return answered(prompt(app_bin.as_os_str(), &["--approve"], &env));
    }
    if let Some(notify) = on_path("notify-send") {
        let expire = format!("--expire-time={}", wait.as_millis());
        let summary = format!("Allow {app} to use {key}?");
        let mut c = prompt(
            notify.as_os_str(),
            &[
                "--app-name=Safe",
                "--icon=ewe-safe",
                "--urgency=critical",
                &expire,
                "--wait",
                "--action=default=Allow",
                "--action=deny=Deny",
                &summary,
                "Click to allow. Close it to deny.",
            ],
            &env,
        );
        c.stdout(Stdio::piped());
        let Ok(mut ch) = c.spawn() else {
            return false;
        };
        let out = ch.stdout.take();
        return match finish(ch, wait) {
            Some(st) if st.success() => {
                let mut said = String::new();
                if let Some(mut o) = out {
                    let _ = o.read_to_string(&mut said);
                }
                said.trim() == "default"
            }
            _ => false,
        };
    }
    log("ssh agent: no prompt to ask with (no ewe-safe-app, no notify-send): refused");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_and_numbers_read_off_the_wire() {
        let mut msg = Vec::new();
        put_string(&mut msg, b"blob");
        put_string(&mut msg, b"");
        msg.extend_from_slice(&4u32.to_be_bytes());
        let mut rest = &msg[..];
        assert_eq!(take_string(&mut rest), Some(&b"blob"[..]));
        assert_eq!(take_string(&mut rest), Some(&b""[..]));
        assert_eq!(take_u32(&mut rest), Some(4));
        assert!(rest.is_empty());
        let mut short = &[0u8, 0, 0, 9, 1][..];
        assert_eq!(take_string(&mut short), None, "a length past the end");
    }

    #[test]
    fn under_systemd_a_prompt_is_a_unit_of_its_own() {
        let env = vec![("EWE_SAFE_APPROVE_KEY".to_string(), "GitHub key".to_string())];
        let argv = |c: &Command| -> Vec<String> {
            std::iter::once(c.get_program())
                .chain(c.get_args())
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let c = prompt_in(
            Some("/usr/bin/systemd-run".into()),
            OsStr::new("/usr/bin/ewe-safe-app"),
            &["--approve"],
            &env,
        );
        assert_eq!(
            argv(&c),
            [
                "/usr/bin/systemd-run",
                "--user",
                "--quiet",
                "--collect",
                "--wait",
                "--pipe",
                "--setenv=EWE_SAFE_APPROVE_KEY",
                "--",
                "/usr/bin/ewe-safe-app",
                "--approve"
            ],
            "the key's name is not on the command line"
        );
        assert!(
            c.get_envs()
                .any(|(k, v)| k == "EWE_SAFE_APPROVE_KEY" && v == Some(OsStr::new("GitHub key")))
        );
        let c = prompt_in(None, OsStr::new("sh"), &["-c", "exit 0"], &env);
        assert_eq!(argv(&c), ["sh", "-c", "exit 0"]);
    }

    #[test]
    fn this_process_is_described() {
        let p = Peer::of(std::process::id() as i32);
        assert!(!p.label.is_empty() && p.label != "an app");
        assert!(p.identity.contains('/'));
        assert_eq!(Peer::of(0).label, "an app");
        assert!(parent_of(std::process::id() as i32).is_some());
    }
}
