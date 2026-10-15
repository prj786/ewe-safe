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
use std::sync::atomic::{AtomicUsize, Ordering};
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
/// SSH1 ones, smartcards, constrained adds, lock/unlock): all refused.
const KEY_CHANGES: [u8; 14] = [1, 7, 8, 9, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26];
/// OpenSSH's own limit on a message.
const MAX_MESSAGE: usize = 256 * 1024;
/// How long the unlock prompt and the approval prompt wait for the user.
const PROMPT_WAIT: Duration = Duration::from_secs(60);
/// Connections served at once; one more is closed straight away.
const MAX_CONNECTIONS: usize = 32;
/// A connection may wait this long for its next request…
const IDLE: Duration = Duration::from_secs(60);
/// …and a request, once begun, must arrive whole within this.
const MESSAGE: Duration = Duration::from_secs(10);
/// After an unlock prompt went unanswered, no new one for this long, then
/// twice as long each time: a loop of signing requests must not reopen it
/// forever.
const COOLDOWN: Duration = Duration::from_secs(30);
const COOLDOWN_MAX: Duration = Duration::from_secs(600);

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
    /// (app's files, public key) pairs allowed since the safe was unlocked.
    allowed: Mutex<HashSet<(String, String)>>,
    /// One approval prompt at a time.
    asking: Mutex<()>,
    /// One unlock prompt at a time.
    unlocking: Mutex<()>,
    /// No unlock prompt before this; the next pause; said in the log yet.
    cooldown: Mutex<(Option<Instant>, Duration, bool)>,
    /// What `ssh-public.json` holds now.
    cached: Mutex<String>,
    listening: Mutex<bool>,
    connections: AtomicUsize,
    /// When a connection over the limit was last logged.
    crowded: Mutex<Option<Instant>>,
}

/// One served connection, counted while it lives.
struct Counted(Arc<Agent>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
    }
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
        cooldown: Mutex::new((None, COOLDOWN, false)),
        cached: Mutex::new(String::new()),
        listening: Mutex::new(false),
        connections: AtomicUsize::new(0),
        crowded: Mutex::new(None),
    });
    // a list from another safe, or from before the agent was turned off
    // (it is only rewritten unlocked: docs/PROTOCOL.md, "The SSH agent")
    if !d.is_set_up() || !d.settings().ssh_agent {
        a.forget_cache();
    }
    let rx = d.subscribe();
    let w = a.clone();
    std::thread::spawn(move || {
        while let Ok(line) = rx.recv() {
            let event = serde_json::from_str::<Value>(&line)
                .ok()
                .and_then(|v| v.get("event").and_then(Value::as_str).map(str::to_string));
            match event.as_deref() {
                Some("locked") => lk(&w.allowed).clear(),
                Some("unlocked") => {
                    *lk(&w.cooldown) = (None, COOLDOWN, false);
                    w.write_cache();
                }
                Some("changed") => w.write_cache(),
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
                            if srv.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                                srv.connections.fetch_sub(1, Ordering::SeqCst);
                                srv.too_many();
                                continue;
                            }
                            let guard = Counted(srv.clone());
                            std::thread::spawn(move || guard.0.serve(s));
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

    /// A connection over the limit was closed; said at most once a minute.
    fn too_many(&self) {
        let mut last = lk(&self.crowded);
        if last.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
            *last = Some(Instant::now());
            log(&format!(
                "ssh agent: {MAX_CONNECTIONS} connections at once: closing the ones above"
            ));
        }
    }

    /// `ssh-public.json` goes (the agent was turned off, or the list is
    /// from another safe).
    pub fn forget_cache(&self) {
        let mut cached = lk(&self.cached);
        let _ = std::fs::remove_file(self.d.paths.ssh_public());
        cached.clear();
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

    /// `ssh-public.json` from the unlocked safe, when it changed; only while
    /// the agent is on.
    pub fn write_cache(&self) {
        if !self.d.settings().ssh_agent {
            return;
        }
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
                let line = k.get("public_key")?.as_str()?;
                // the agent signs with these kinds of key only
                if !keys::supported_line(line) {
                    return None;
                }
                Some(Identity {
                    blob: keys::public_blob(line)?,
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
            if s.set_read_timeout(Some(IDLE)).is_err() || s.read_exact(&mut len).is_err() {
                return;
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > MAX_MESSAGE {
                return;
            }
            let mut body = Zeroizing::new(vec![0u8; n]);
            if s.set_read_timeout(Some(MESSAGE)).is_err() || s.read_exact(&mut body).is_err() {
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
        if rd(&self.d.snap).locked && !self.wait_unlocked(peer) {
            return None;
        }
        // the safe is open: which item holds the key now
        let (id, title, _) = self
            .unlocked_keys()?
            .into_iter()
            .find(|(_, _, line)| keys::public_blob(line).as_deref() == Some(blob))?;
        let key = keys::public_line(blob).unwrap_or_default();
        let asked = self.d.settings().ssh_confirm != "never";
        if !self.approved(peer, &key, &title) {
            log(&format!(
                "ssh agent: {} was not allowed ({})",
                peer.label, peer.detail
            ));
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
                if asked {
                    log(&format!("ssh agent: signed for {}", peer.label));
                } else {
                    log(&format!(
                        "ssh agent: signed for {} without asking (ssh_confirm = never)",
                        peer.label
                    ));
                }
                Some(sig)
            }
            Err(e) => {
                log(&format!("ssh agent: {e}"));
                None
            }
        }
    }

    /// Open the unlock prompt (`ewe-safe unlock --ask`, the same prompt the
    /// picker opens) and wait for the safe to open. After a prompt went
    /// unanswered, none opens again for a while (`COOLDOWN`, growing).
    fn wait_unlocked(&self, peer: &Peer) -> bool {
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
        {
            let mut cd = lk(&self.cooldown);
            if let Some(until) = cd.0
                && Instant::now() < until
            {
                if !cd.2 {
                    cd.2 = true;
                    log(&format!(
                        "ssh agent: locked, and the last unlock prompt went unanswered: none again for {} s ({} asked: {})",
                        until.saturating_duration_since(Instant::now()).as_secs(),
                        peer.label,
                        peer.detail
                    ));
                }
                return false;
            }
        }
        log(&format!(
            "ssh agent: opening the unlock prompt for {} ({})",
            peer.label, peer.detail
        ));
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
        let opened = loop {
            std::thread::sleep(Duration::from_millis(150));
            if !snap_ok(&self.d).1 {
                let _ = child.try_wait();
                break true;
            }
            if let Ok(Some(_)) = child.try_wait() {
                break !snap_ok(&self.d).1;
            }
            if start.elapsed() > wait {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        };
        let mut cd = lk(&self.cooldown);
        *cd = if opened {
            (None, COOLDOWN, false)
        } else {
            log(&format!(
                "ssh agent: still locked, no signature for {} (no new prompt for {} s)",
                peer.label,
                cd.1.as_secs()
            ));
            (
                Some(Instant::now() + cd.1),
                (cd.1 * 2).min(COOLDOWN_MAX),
                false,
            )
        };
        opened
    }

    /// `[safe] ssh_confirm`: `never` asks nothing, `every-time` asks every
    /// time, `first-use` once per app and key until the safe locks.
    fn approved(&self, peer: &Peer, key: &str, title: &str) -> bool {
        let mode = self.d.settings().ssh_confirm;
        if mode == "never" {
            return true;
        }
        // a program whose file can't be seen is asked every time
        let pair = peer.identity.clone().map(|id| (id, key.to_string()));
        let first_use = mode == config::CONFIRM_FIRST_USE;
        let known = |p: &Option<(String, String)>| {
            first_use && p.as_ref().is_some_and(|p| lk(&self.allowed).contains(p))
        };
        if known(&pair) {
            return true;
        }
        let _one = lk(&self.asking);
        // allowed while this request waited for the other prompt
        if known(&pair) {
            return true;
        }
        let yes = ask(&self.d.paths, peer, title);
        if yes
            && first_use
            && let Some(p) = pair
        {
            lk(&self.allowed).insert(p);
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

/// The app on the other end, from `SO_PEERCRED`'s pid. A same-uid
/// program can call itself anything, so the prompt shows the full
/// resolved paths and marks one outside the system's folders, and an
/// approval is remembered for the program *file* (its device and inode):
/// moving it keeps the approval, a new or replaced file asks again.
struct Peer {
    /// "ssh (from git)": the log line and the prompt's title.
    label: String,
    /// "/usr/bin/ssh, started by /usr/bin/git", each path outside /usr and
    /// /opt marked "(not a system program)".
    detail: String,
    /// Both programs live in /usr or /opt.
    system: bool,
    /// What an approval is remembered by: the program's file and its
    /// parent's. None when the kernel doesn't say: then it always asks.
    identity: Option<String>,
}

/// One running program, from /proc.
struct Program {
    path: String,
    name: String,
    /// (device, inode) of the file it runs.
    file: Option<(u64, u64)>,
    system: bool,
}

/// Where the system's programs live; anything else (a home folder, /tmp)
/// may be a lookalike.
fn system_path(path: &str) -> bool {
    ["/usr/", "/opt/"].iter().any(|d| path.starts_with(d)) && !path.contains("/../")
}

fn program(pid: i32) -> Option<Program> {
    use std::os::unix::fs::MetadataExt;
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())?;
    let link = format!("/proc/{pid}/exe");
    let file = std::fs::metadata(&link).ok().map(|m| (m.dev(), m.ino()));
    match std::fs::read_link(&link) {
        Ok(p) => {
            let path = p.to_string_lossy().into_owned();
            let name = Path::new(path.trim_end_matches(" (deleted)"))
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| comm.clone());
            Some(Program {
                system: system_path(&path),
                path,
                name,
                file,
            })
        }
        // a program that hides its file: a name only, never remembered
        Err(_) => Some(Program {
            path: format!("{comm} (its file can't be seen)"),
            name: comm,
            file: None,
            system: false,
        }),
    }
}

fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // "pid (comm) state ppid …": comm may hold spaces and parentheses
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

fn shown(p: &Program) -> String {
    if p.system {
        p.path.clone()
    } else {
        format!("{} (not a system program)", p.path)
    }
}

impl Peer {
    fn of(pid: i32) -> Peer {
        let Some(me) = (pid > 0).then(|| program(pid)).flatten() else {
            return Peer {
                label: "an app".to_string(),
                detail: "a program Safe can't see".to_string(),
                system: false,
                identity: None,
            };
        };
        let parent = parent_of(pid).filter(|p| *p > 1).and_then(program);
        let file = |p: &Program| p.file.map(|(d, i)| format!("{d}:{i}"));
        match parent {
            Some(up) => Peer {
                label: if up.name != me.name {
                    format!("{} (from {})", me.name, up.name)
                } else {
                    me.name.clone()
                },
                detail: format!("{}, started by {}", shown(&me), shown(&up)),
                system: me.system && up.system,
                identity: file(&me).zip(file(&up)).map(|(a, b)| format!("{a}/{b}")),
            },
            None => Peer {
                label: me.name.clone(),
                detail: shown(&me),
                system: me.system,
                identity: file(&me),
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

/// "Allow `app` to use `key`?" — yes only on an explicit allow. The
/// prompt shows the full paths too, and says when a program is not a
/// system one: a same-uid program can take any name.
///
/// - `EWE_SAFE_APPROVE_CMD` (tests, or a user's own prompt): `sh -c`;
///   exit 0 is Allow.
/// - the Safe window's prompt, `ewe-safe-app --approve`: exit 0 is Allow.
/// - else a notification with an Allow action (`notify-send --wait`):
///   ewe's notification server runs the default action on a click; closing
///   it, or no click in time, is Deny.
///
/// The app, its paths, whether both are system programs (`1` or `0`) and
/// the key's name travel in `EWE_SAFE_APPROVE_APP`, `EWE_SAFE_APPROVE_PATH`,
/// `EWE_SAFE_APPROVE_SYSTEM` and `EWE_SAFE_APPROVE_KEY`, never on a
/// command line (the notification's text excepted).
fn ask(paths: &Paths, peer: &Peer, key: &str) -> bool {
    let wait = prompt_wait();
    let app = peer.label.as_str();
    let mut env = display_env(paths);
    env.push(("EWE_SAFE_APPROVE_APP".into(), app.to_string()));
    env.push(("EWE_SAFE_APPROVE_KEY".into(), key.to_string()));
    env.push(("EWE_SAFE_APPROVE_PATH".into(), peer.detail.clone()));
    env.push((
        "EWE_SAFE_APPROVE_SYSTEM".into(),
        if peer.system { "1" } else { "0" }.to_string(),
    ));
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
        let body = format!("{}. Click to allow. Close it to deny.", peer.detail);
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
                &body,
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
        use std::os::unix::fs::MetadataExt;
        let p = Peer::of(std::process::id() as i32);
        assert!(!p.label.is_empty() && p.label != "an app");
        // the test binary lives in target/, not a system folder
        let exe = std::env::current_exe().unwrap();
        assert!(
            p.detail
                .starts_with(&format!("{} (not a system program)", exe.display())),
            "{}",
            p.detail
        );
        assert!(!p.system);
        // remembered by the file, not its name
        let m = std::fs::metadata(&exe).unwrap();
        let id = p.identity.expect("the file is known");
        assert!(id.starts_with(&format!("{}:{}", m.dev(), m.ino())), "{id}");
        let none = Peer::of(0);
        assert_eq!((none.label.as_str(), none.identity), ("an app", None));
        assert!(parent_of(std::process::id() as i32).is_some());
    }

    #[test]
    fn only_usr_and_opt_are_system_folders() {
        assert!(system_path("/usr/bin/ssh"));
        assert!(system_path("/opt/1Password/op"));
        assert!(!system_path("/home/sam/.local/bin/git"));
        assert!(!system_path("/tmp/ssh"));
        assert!(!system_path("/usr/../home/sam/git"));
    }
}
