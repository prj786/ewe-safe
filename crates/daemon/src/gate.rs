//! Safe is the SSH gate (docs/GATE.md S21, S22, S26): every `ssh` on this
//! computer asks Safe's agent, even where `~/.ssh/config` names another.
//!
//! - Two lines on top of `~/.ssh/config` include `~/.ssh/ewe-safe/config`,
//!   whose `Host *` names Safe's socket (`ssh` takes the first value it
//!   finds, so this one wins) and adds the services' host keys.
//! - `~/.ssh/ewe-safe/key-<tag>.pub`: a public file for every key the agent
//!   offers, for `IdentityFile` lines; written with the public-key list.
//! - `~/.ssh/ewe-safe/known_hosts`: the services' published host keys,
//!   shipped in this binary.
//!
//! Safe changes only its two lines, its own folder and its environment.d
//! file. It follows the account: `[safe] ssh_agent` is shared in ewe.conf,
//! and [`converge`] makes this computer match it.

use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use safe_core::Kind;
use safe_core::ssh as keys;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config;
use crate::daemon::{Daemon, lk, rd};
use crate::hosts::{self, SshConfig};
use crate::log;

/// The services' host keys (S26), checked in the tests below.
pub const KNOWN_HOSTS: &str = include_str!("../data/known_hosts");

pub const INCLUDE_COMMENT: &str =
    "# Safe (ewe): every ssh asks Safe for keys. `ewe-safe ssh disable` removes these two lines.";
pub const INCLUDE_LINE: &str = "Include ~/.ssh/ewe-safe/config";
const CONFIG_MARK: &str = "# Written by Safe (ewe-safe).";
/// The environment.d file `enable` writes (and `disable` removes).
const ENV_FILE: &str = "90-ewe-safe-ssh.conf";
const ENV_MARK: &str = "# Written by `ewe-safe ssh enable`";
/// 1Password's agent, where its app puts it.
const ONE_PASSWORD: &str = ".1password/agent.sock";
/// How long another agent may take to list its keys.
const AGENT_WAIT: Duration = Duration::from_secs(5);

/// One writer of the gate's files at a time (a verb and the worker).
static WRITING: Mutex<()> = Mutex::new(());

/// Held across "read the settings, then act on them" — by the worker's
/// re-read and convergence, and by the verbs that change `ssh_agent` or
/// `git_sign` (enable, disable, takeover, connect, sign-commits). Without
/// it, a re-read made a moment before a verb recorded its change would
/// undo the verb's work.
pub static TURNING: Mutex<()> = Mutex::new(());

pub fn gate_dir() -> PathBuf {
    hosts::ssh_dir().join("ewe-safe")
}

pub fn config_file() -> PathBuf {
    gate_dir().join("config")
}

pub fn known_hosts_file() -> PathBuf {
    gate_dir().join("known_hosts")
}

pub fn allowed_signers_file() -> PathBuf {
    gate_dir().join("allowed_signers")
}

fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| hosts::home().join(".config"))
}

pub fn env_file() -> PathBuf {
    config_home().join("environment.d").join(ENV_FILE)
}

/// `~/.ssh` comes from `$HOME`; without a full path there, Safe writes
/// nothing (it would land in the daemon's working folder).
fn home_ok() -> bool {
    let h = hosts::home();
    h.is_absolute() && h != Path::new("/")
}

// ── key files (S22) ─────────────────────────────────────────────────────

/// `key-<tag>.pub`'s tag: the first 16 characters of the SHA256
/// fingerprint's base64, `+` → `-` and `/` → `_`. The same on every
/// computer with the same safe, whatever the key is called.
pub fn tag(fingerprint: &str) -> Option<String> {
    let b64 = fingerprint.strip_prefix("SHA256:")?;
    if b64.len() < 16 || !b64.is_ascii() {
        return None;
    }
    Some(
        b64[..16]
            .chars()
            .map(|c| match c {
                '+' => '-',
                '/' => '_',
                c => c,
            })
            .collect(),
    )
}

pub fn key_file(fingerprint: &str) -> Option<PathBuf> {
    Some(gate_dir().join(format!("key-{}.pub", tag(fingerprint)?)))
}

/// The same path, `~` form (for ewe.conf: the same on every computer).
pub fn key_file_tilde(fingerprint: &str) -> Option<String> {
    Some(format!("~/.ssh/ewe-safe/key-{}.pub", tag(fingerprint)?))
}

/// A title as a public key's comment: one line, no control characters.
fn comment_of(title: &str) -> String {
    title
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// A public key file's text: the key and its title as the comment.
pub fn key_file_text(line: &str, title: &str) -> Option<String> {
    let bare = keys::public_line(&keys::public_blob(line)?)?;
    let c = comment_of(title);
    Some(if c.is_empty() {
        format!("{bare}\n")
    } else {
        format!("{bare} {c}\n")
    })
}

/// Write one key's public file (S24's `connect` and `host set` need it now,
/// before the agent's list catches up). Its path.
pub fn write_key_file(line: &str, title: &str) -> io::Result<PathBuf> {
    if !home_ok() {
        return Err(io::Error::other("HOME isn't a full path"));
    }
    let fp = keys::fingerprint_of_line(line).ok_or_else(|| io::Error::other("not a public key"))?;
    let path = key_file(&fp).ok_or_else(|| io::Error::other("no fingerprint"))?;
    let text = key_file_text(line, title).ok_or_else(|| io::Error::other("not a public key"))?;
    let _one = lk(&WRITING);
    make_dirs()?;
    write_if_changed(&path, text.as_bytes(), 0o644)?;
    Ok(path)
}

/// Make `key-*.pub` match the agent's keys: (public line, title) pairs.
/// Files for keys that are gone are removed (only `key-*.pub`).
pub fn sync_key_files(list: &[(String, String)]) -> io::Result<bool> {
    if !home_ok() {
        return Err(io::Error::other("HOME isn't a full path"));
    }
    let _one = lk(&WRITING);
    sync_key_files_held(list)
}

/// [`sync_key_files`], with `WRITING` held by the caller.
fn sync_key_files_held(list: &[(String, String)]) -> io::Result<bool> {
    let mut wanted = std::collections::HashSet::new();
    let mut changed = false;
    make_dirs()?;
    for (line, title) in list {
        let Some(fp) = keys::fingerprint_of_line(line) else {
            continue;
        };
        let (Some(path), Some(text)) = (key_file(&fp), key_file_text(line, title)) else {
            continue;
        };
        // the same key in two items: one file, the first title
        if !wanted.insert(path.clone()) {
            continue;
        }
        changed |= write_if_changed(&path, text.as_bytes(), 0o644)?;
    }
    for e in std::fs::read_dir(gate_dir())?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("key-") && name.ends_with(".pub") && !wanted.contains(&e.path()) {
            std::fs::remove_file(e.path())?;
            changed = true;
        }
    }
    Ok(changed)
}

/// One key from the public-key list (`ssh-public.json`).
#[derive(Clone, Debug)]
pub struct Cached {
    pub line: String,
    pub title: String,
    pub item_id: Option<String>,
}

/// The public-key list, or None when there is none.
pub fn cache_keys(d: &Daemon) -> Option<Vec<Cached>> {
    let bytes = std::fs::read(d.paths.ssh_public()).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    Some(
        v.get("keys")?
            .as_array()?
            .iter()
            .filter_map(|k| {
                Some(Cached {
                    line: k.get("public_key")?.as_str()?.to_string(),
                    title: k
                        .get("comment")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    item_id: k.get("item_id").and_then(Value::as_str).map(str::to_string),
                })
            })
            .collect(),
    )
}

/// A key Safe holds: from the unlocked safe, else from the public-key list
/// (no item id in a list written before 0.4).
#[derive(Clone, Debug)]
pub struct SafeKey {
    pub item_id: Option<String>,
    pub title: String,
    /// The public line without its comment.
    pub line: String,
    pub fingerprint: String,
    pub key_type: String,
}

impl SafeKey {
    pub fn json(&self) -> Value {
        json!({"item_id": self.item_id, "title": self.title, "fingerprint": self.fingerprint})
    }
}

pub fn safe_keys(d: &Daemon) -> Vec<SafeKey> {
    let mk = |item_id: Option<String>, title: &str, line: &str| {
        let blob = keys::public_blob(line)?;
        Some(SafeKey {
            item_id,
            title: title.to_string(),
            line: keys::public_line(&blob)?,
            fingerprint: keys::fingerprint_of_blob(&blob)?,
            key_type: keys::key_type_of_line(line)?,
        })
    };
    let snap = rd(&d.snap);
    if !snap.locked {
        return snap
            .items
            .iter()
            .filter(|s| s.kind == Kind::SshKey)
            .filter_map(|s| mk(Some(s.id.clone()), &s.title, &s.ssh.as_ref()?.public_key))
            .collect();
    }
    drop(snap);
    cache_keys(d)
        .unwrap_or_default()
        .iter()
        .filter_map(|c| mk(c.item_id.clone(), &c.title, &c.line))
        .collect()
}

// ── files ───────────────────────────────────────────────────────────────

fn mkdir_private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// `~/.ssh/ewe-safe` is a link (to anywhere): Safe neither writes nor
/// deletes through it.
pub fn dir_is_link() -> bool {
    std::fs::symlink_metadata(gate_dir()).is_ok_and(|m| m.file_type().is_symlink())
}

const LINK_PROBLEM: &str = "~/.ssh/ewe-safe is a link: Safe won't write or delete through it. Remove the link, and Safe makes the folder.";

/// `~/.ssh` (0700 when made here) and `~/.ssh/ewe-safe` (0700), never
/// through a link.
fn make_dirs() -> io::Result<()> {
    mkdir_private(&hosts::ssh_dir())?;
    if dir_is_link() {
        return Err(io::Error::other(LINK_PROBLEM));
    }
    let g = gate_dir();
    mkdir_private(&g)?;
    let mode = std::fs::metadata(&g)?.permissions().mode() & 0o777;
    if mode != 0o700 {
        std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write a file unless it already holds `bytes` with `mode`: whether it
/// wrote.
pub fn write_if_changed(path: &Path, bytes: &[u8], mode: u32) -> io::Result<bool> {
    let same = std::fs::read(path).is_ok_and(|b| b == bytes);
    let mode_ok = std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o777 == mode);
    if same && mode_ok {
        return Ok(false);
    }
    if !same {
        safe_core::atomic::write(path, bytes)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(true)
}

fn quoted(p: &Path) -> String {
    let s = p.to_string_lossy();
    if s.contains(char::is_whitespace) {
        format!("\"{s}\"")
    } else {
        s.into_owned()
    }
}

/// `~/.ssh/ewe-safe/config`: absolute paths, since it is this computer's.
fn config_text(d: &Daemon) -> String {
    format!(
        "{CONFIG_MARK} Every ssh on this computer asks Safe for keys.\n\
         # `ewe-safe ssh disable` removes this file and the Include line.\n\
         Host *\n    IdentityAgent {}\n    GlobalKnownHostsFile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2 {}\n",
        quoted(&d.paths.ssh_socket()),
        quoted(&known_hosts_file()),
    )
}

fn env_text() -> String {
    format!(
        "{ENV_MARK}: ssh and git use the keys in Safe.\n# `ewe-safe ssh disable` removes this file.\nSSH_AUTH_SOCK=${{XDG_RUNTIME_DIR}}/{}\n",
        config::SSH_SOCKET
    )
}

fn ours(path: &Path, mark: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|t| t.starts_with(mark))
}

/// The first line of a config that isn't blank or a comment.
fn first_directive(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
}

fn is_our_line(line: &str) -> bool {
    let l = line.trim_end_matches(['\n', '\r']).trim_end();
    l == INCLUDE_COMMENT || l == INCLUDE_LINE
}

/// The text without Safe's two lines (only those exact lines).
fn without_our_lines(text: &str) -> (String, bool) {
    let mut found = false;
    let kept: String = text
        .split_inclusive('\n')
        .filter(|l| {
            let ours = is_our_line(l);
            found |= ours;
            !ours
        })
        .collect();
    (kept, found)
}

/// The Include line is the first thing `~/.ssh/config` says.
pub fn included() -> bool {
    std::fs::read_to_string(hosts::ssh_config_path())
        .is_ok_and(|t| first_directive(&t) == Some(INCLUDE_LINE))
}

/// The user's `~/.ssh/config` (its target, when it is a link: a link
/// stays a link) and its text now ("" when there is none).
fn user_config() -> io::Result<(PathBuf, String)> {
    let path = hosts::ssh_config_path();
    let real = if path.is_symlink() {
        std::fs::canonicalize(&path)?
    } else {
        path
    };
    let text = match std::fs::read_to_string(&real) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    Ok((real, text))
}

/// Replace `real` with `new`, keeping its mode, unless it no longer holds
/// `expected` (ewe-conf rewrote its managed block meanwhile): the file is
/// read again right before the rename. Whether it was written.
fn replace_if_unchanged(real: &Path, expected: &str, new: &str) -> io::Result<bool> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = real.parent().unwrap_or(Path::new("."));
    let mode = std::fs::metadata(real)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o600);
    let tmp = dir.join(format!(".config.safe-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(new.as_bytes())?;
        f.sync_all()?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        let now = match std::fs::read_to_string(real) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        if now != expected {
            return Ok(false);
        }
        std::fs::rename(&tmp, real)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(true)
    })();
    if !matches!(written, Ok(true)) {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// How often a read-modify-write of `~/.ssh/config` starts again when the
/// file changed under it.
const TRIES: usize = 5;

/// Put the two lines on top of `~/.ssh/config` (S21.2). The file is first
/// copied to `config.before-safe` (once). Nothing is written when they are
/// there already.
fn add_lines() -> io::Result<bool> {
    mkdir_private(&hosts::ssh_dir())?;
    for _ in 0..TRIES {
        let (real, text) = user_config()?;
        if first_directive(&text) == Some(INCLUDE_LINE) {
            return Ok(false);
        }
        let backup = hosts::ssh_dir().join("config.before-safe");
        if real.exists() && !backup.exists() {
            std::fs::copy(&real, &backup)?;
        }
        // lines of ours lower down (moved by hand) go to the top
        let (rest, _) = without_our_lines(&text);
        let new = format!("{INCLUDE_COMMENT}\n{INCLUDE_LINE}\n{rest}");
        if replace_if_unchanged(&real, &text, &new)? {
            return Ok(true);
        }
    }
    Err(io::Error::other(
        "~/.ssh/config kept changing while Safe wrote it",
    ))
}

/// Take Safe's two lines out of `~/.ssh/config`; nothing else changes.
fn remove_lines() -> io::Result<bool> {
    for _ in 0..TRIES {
        let (real, text) = user_config()?;
        let (rest, found) = without_our_lines(&text);
        if !found {
            return Ok(false);
        }
        if replace_if_unchanged(&real, &text, &rest)? {
            return Ok(true);
        }
    }
    Err(io::Error::other(
        "~/.ssh/config kept changing while Safe wrote it",
    ))
}

fn remove_if(path: &Path, cond: bool) -> bool {
    cond && std::fs::remove_file(path).is_ok()
}

/// Everything "on" needs (S21): the environment.d file, Safe's folder and
/// its files, the key files from the public-key list, the two lines.
/// Whether anything was written.
pub fn apply(d: &Daemon) -> io::Result<bool> {
    if !home_ok() {
        return Err(io::Error::other("HOME isn't a full path"));
    }
    let _one = lk(&WRITING);
    let env = env_file();
    if let Some(dir) = env.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut changed = write_if_changed(&env, env_text().as_bytes(), 0o600)?;
    make_dirs()?;
    changed |= write_if_changed(&config_file(), config_text(d).as_bytes(), 0o600)?;
    changed |= write_if_changed(&known_hosts_file(), KNOWN_HOSTS.as_bytes(), 0o644)?;
    if let Some(list) = cache_keys(d) {
        let pairs: Vec<(String, String)> = list.into_iter().map(|c| (c.line, c.title)).collect();
        changed |= sync_key_files_held(&pairs)?;
    }
    changed |= add_lines()?;
    Ok(changed)
}

/// Everything "off" removes, only what Safe wrote: the two lines, the
/// config file, the key files, `known_hosts`, `allowed_signers`, the
/// environment.d file. `config.before-safe` stays. Whether anything went.
pub fn remove() -> bool {
    if !home_ok() {
        return false;
    }
    let _one = lk(&WRITING);
    let mut gone = match remove_lines() {
        Ok(x) => x,
        Err(e) => {
            log(&format!(
                "can't take Safe's lines out of ~/.ssh/config: {e}"
            ));
            false
        }
    };
    let env = env_file();
    gone |= remove_if(&env, ours(&env, ENV_MARK));
    if dir_is_link() {
        log("~/.ssh/ewe-safe is a link: Safe deletes nothing through it");
        return gone;
    }
    let cfg = config_file();
    gone |= remove_if(&cfg, ours(&cfg, CONFIG_MARK));
    let dir = gate_dir();
    if let Ok(list) = std::fs::read_dir(&dir) {
        for e in list.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let safes = (name.starts_with("key-") && name.ends_with(".pub"))
                || name == "known_hosts"
                || name == "allowed_signers";
            gone |= remove_if(&e.path(), safes);
        }
    }
    // the folder last: once it is gone, so is everything else
    let _ = std::fs::remove_dir(&dir);
    gone
}

/// Safe's agent on and the gate in place, for a verb that needs them (a
/// key Safe holds is no use without its agent): `connect`, `sign-commits`.
/// Whether it had to be turned on.
pub fn ensure_on(d: &Daemon) -> Result<bool, crate::daemon::Fail> {
    use crate::daemon::Fail;
    let _turning = lk(&TURNING);
    if d.settings().ssh_agent && is_on() {
        return Ok(false);
    }
    if !d.settings().ssh_agent && !config::conf_store("ssh_agent", "true") {
        return Err(Fail::new(
            "internal",
            "ewe-conf could not store [safe] ssh_agent = true, so Safe's agent stays off",
        )
        .hint("Check that ewe-conf works: ewe-conf get safe"));
    }
    d.reload_settings();
    apply(d).map_err(|e| {
        Fail::new(
            "internal",
            format!("Safe can't put the SSH gate in place: {e}"),
        )
    })?;
    if let Some(ag) = crate::agent::get() {
        ag.write_cache();
    }
    Ok(true)
}

/// The gate is on: the Include line on top, and Safe's config file in
/// Safe's own folder (not through a link).
pub fn is_on() -> bool {
    included() && !dir_is_link() && ours(&config_file(), CONFIG_MARK)
}

/// Make this computer match `[safe] ssh_agent` (at start and on every
/// settings read; the daemon checks that the read got an answer).
pub fn converge(d: &Daemon) {
    let st = d.settings();
    if st.ssh_agent && d.is_set_up() {
        match apply(d) {
            Ok(true) => log("the SSH gate is in place (ewe.conf: ssh_agent = true)"),
            Ok(false) => {}
            Err(e) => log(&format!("can't put the SSH gate in place: {e}")),
        }
    } else if !st.ssh_agent && remove() {
        log("the SSH gate is off (ewe.conf: ssh_agent = false): Safe's lines and files are gone");
    }
}

// ── what ssh-status says (S21) ──────────────────────────────────────────

/// An `IdentityAgent` value names Safe's own socket.
fn is_safe_socket(d: &Daemon, value: &str) -> bool {
    let ours = d.paths.ssh_socket();
    if value
        .trim_end_matches('"')
        .ends_with(&format!("/{}", config::SSH_SOCKET))
    {
        return true;
    }
    hosts::expand(value).is_some_and(|p| {
        p == ours
            || std::fs::canonicalize(&p).ok() == std::fs::canonicalize(&ours).ok() && p.exists()
    })
}

/// Hosts whose own `IdentityAgent` names another agent: the user's lines
/// first (they win in ssh), then ewe.conf's. `(host, agent)`.
pub fn overridden(d: &Daemon, file: &SshConfig, ewe: &[hosts::EweHost]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let other = |v: &str| !is_safe_socket(d, v);
    for (k, v) in &file.top {
        if k.eq_ignore_ascii_case("identityagent") && other(v) {
            out.push(("*".into(), v.clone()));
        }
    }
    for b in hosts::own_blocks(file) {
        if let Some(v) = b.get("identityagent").filter(|v| other(v)) {
            out.push((b.names.join(" "), v.to_string()));
        }
    }
    for h in ewe {
        if hosts::yours(file, &h.host) {
            continue;
        }
        if let Some(v) = h.get("identityagent").filter(|v| other(v)) {
            out.push((h.host.clone(), v.to_string()));
        }
    }
    out
}

/// A private key file (S23's list): its path, and what can be told
/// without its passphrase.
#[derive(Clone, Debug)]
pub struct KeyFileInfo {
    pub path: PathBuf,
    /// From the key (an OpenSSH key's public half is not encrypted) or the
    /// `.pub` beside it.
    pub fingerprint: Option<String>,
    pub encrypted: bool,
}

/// The file starts with a private key's header (read only that far).
fn has_private_header(path: &Path) -> bool {
    use std::io::Read;
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = Vec::with_capacity(128);
    if f.take(128).read_to_end(&mut head).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&head);
    let t = text.trim_start();
    t.starts_with("-----BEGIN ")
        && t["-----BEGIN ".len()..]
            .split("-----")
            .next()
            .is_some_and(|l| l.ends_with("PRIVATE KEY"))
}

/// Read a private key file (size-checked as `ssh add` is).
pub fn read_private(path: &Path) -> Option<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > keys::MAX_KEY_FILE {
        return None;
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    std::fs::File::open(path)
        .ok()?
        .take(keys::MAX_KEY_FILE + 1)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

/// The private key files Safe looks at (S23): every regular file in
/// `~/.ssh` (not in folders) that starts with a private key's header, and
/// every `IdentityFile` that `~/.ssh/config` (and what it includes, Safe's
/// own file excepted) or ewe.conf names, when it is one.
pub fn key_files(ewe: &[hosts::EweHost]) -> Vec<KeyFileInfo> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !paths.contains(&p) {
            paths.push(p);
        }
    };
    if let Ok(list) = std::fs::read_dir(hosts::ssh_dir()) {
        let mut found: Vec<PathBuf> = list
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.path())
            .collect();
        found.sort();
        found.into_iter().for_each(&mut push);
    }
    for (_, c) in hosts::config_and_includes(&config_file()) {
        for v in &c.identity_files {
            if let Some(p) = hosts::expand(v) {
                push(p);
            }
        }
    }
    for h in ewe {
        for (k, v) in &h.options {
            if k.eq_ignore_ascii_case("identityfile")
                && let Some(p) = hosts::expand(v)
            {
                push(p);
            }
        }
    }
    paths
        .into_iter()
        .filter(|p| !p.starts_with(gate_dir()))
        .filter(|p| p.is_file() && has_private_header(p))
        .filter_map(|p| {
            let bytes = read_private(&p)?;
            let encrypted = keys::is_encrypted(&bytes);
            let public = keys::public_of_private(&bytes).or_else(|| {
                let mut pubf = p.clone().into_os_string();
                pubf.push(".pub");
                let t = std::fs::read_to_string(PathBuf::from(pubf)).ok()?;
                let l = t.lines().next()?.trim().to_string();
                keys::public_blob(&l).map(|_| l)
            });
            let fingerprint = public.as_deref().and_then(keys::fingerprint_of_line);
            Some(KeyFileInfo {
                path: p,
                fingerprint,
                encrypted,
            })
        })
        .collect()
}

/// Another agent that answers: its socket, its name, its public keys.
#[derive(Clone, Debug)]
pub struct OtherAgent {
    pub socket: PathBuf,
    pub name: String,
    pub keys: Vec<String>,
}

fn one_password() -> PathBuf {
    hosts::home().join(ONE_PASSWORD)
}

/// Agent sockets `~/.ssh/config` or ewe.conf names, 1Password's, and the
/// caller's `SSH_AUTH_SOCK`: the ones that exist and answer `ssh-add -L`
/// (5 s each, all at once). Safe's own is never one.
pub fn other_agents(
    d: &Daemon,
    file: &SshConfig,
    ewe: &[hosts::EweHost],
    caller: Option<&str>,
) -> Vec<OtherAgent> {
    let mut values: Vec<String> = file.identity_agents.clone();
    for (_, c) in hosts::config_and_includes(&config_file())
        .into_iter()
        .skip(1)
    {
        values.extend(c.identity_agents);
    }
    for h in ewe {
        if let Some(v) = h.get("identityagent") {
            values.push(v.to_string());
        }
    }
    values.push(one_password().to_string_lossy().into_owned());
    if let Some(c) = caller {
        values.push(c.to_string());
    }
    let mut sockets: Vec<PathBuf> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for v in values {
        let low = v.to_ascii_lowercase();
        if low == "none" || low == "ssh_auth_sock" || is_safe_socket(d, &v) {
            continue;
        }
        let Some(p) = hosts::expand(&v) else { continue };
        let is_socket = std::fs::metadata(&p).is_ok_and(|m| m.file_type().is_socket());
        let real = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
        if is_socket && !seen.contains(&real) {
            seen.push(real);
            sockets.push(p);
        }
    }
    let jobs: Vec<_> = sockets
        .into_iter()
        .map(|sock| {
            std::thread::spawn(move || {
                let env = [(
                    "SSH_AUTH_SOCK".to_string(),
                    sock.to_string_lossy().into_owned(),
                )];
                let (code, out, _) = config::run_full("ssh-add", &["-L"], &env, AGENT_WAIT)?;
                let text = String::from_utf8_lossy(&out).into_owned();
                let keys: Vec<String> = match code {
                    0 => text
                        .lines()
                        .map(str::trim)
                        .filter(|l| keys::public_blob(l).is_some())
                        .map(str::to_string)
                        .collect(),
                    // "The agent has no identities."
                    1 if text.contains("no identities") => Vec::new(),
                    _ => return None,
                };
                Some((sock, keys))
            })
        })
        .collect();
    let op = one_password();
    jobs.into_iter()
        .filter_map(|j| j.join().ok().flatten())
        .map(|(socket, keys)| OtherAgent {
            name: if socket == op {
                "1Password".to_string()
            } else {
                socket
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            },
            socket,
            keys,
        })
        .collect()
}

/// `ssh-status`'s `gate` object (S21).
pub fn status_json(d: &Daemon, caller: Option<&str>) -> Value {
    let file = hosts::read_config();
    let ewe = hosts::ewe_hosts_or_block(&file);
    let safe: Vec<String> = safe_keys(d).into_iter().map(|k| k.fingerprint).collect();
    let in_safe = |fp: &Option<String>| fp.as_ref().is_some_and(|f| safe.contains(f));
    let files: Vec<Value> = key_files(&ewe)
        .into_iter()
        .map(|k| {
            json!({
                "path": k.path,
                "fingerprint": k.fingerprint,
                "in_safe": in_safe(&k.fingerprint),
            })
        })
        .collect();
    let agents: Vec<Value> = other_agents(d, &file, &ewe, caller)
        .into_iter()
        .map(|a| {
            let missing = a
                .keys
                .iter()
                .filter(|l| !in_safe(&keys::fingerprint_of_line(l)))
                .count();
            json!({
                "socket": a.socket,
                "name": a.name,
                "keys": a.keys.len(),
                "missing_from_safe": missing,
            })
        })
        .collect();
    let include = included();
    let link = dir_is_link();
    json!({
        "on": include && !link && ours(&config_file(), CONFIG_MARK),
        "include": include,
        "problem": link.then_some(LINK_PROBLEM),
        "config_file": config_file(),
        "overridden": overridden(d, &file, &ewe)
            .into_iter()
            .map(|(host, agent)| json!({"host": host, "agent": agent}))
            .collect::<Vec<_>>(),
        "key_files": files,
        "other_agents": agents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_the_fingerprints_start_made_safe_for_a_file_name() {
        assert_eq!(
            tag("SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM").as_deref(),
            Some("p2QAMXNIC1TJYWeI")
        );
        assert_eq!(
            tag("SHA256:+DiY3wvvV6TuJJhb/ZisF/zLDA0zPMSvHdkr4UvCOqU").as_deref(),
            Some("-DiY3wvvV6TuJJhb")
        );
        assert_eq!(
            tag("SHA256:ab/c+d_e-fghijklmnop").as_deref(),
            Some("ab_c-d_e-fghijkl")
        );
        assert_eq!(tag("MD5:aa:bb"), None);
        assert_eq!(tag("SHA256:short"), None);
    }

    /// Review F-d: a `~/.ssh/config` that changed since Safe read it (ewe-conf
    /// rewrote its block) is not overwritten; the caller reads it again.
    #[test]
    fn a_config_changed_under_safe_is_not_overwritten() {
        let d = std::env::temp_dir().join(format!("safe-gate-rmw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("config");
        std::fs::write(&f, "A").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            !replace_if_unchanged(&f, "B", "C").unwrap(),
            "changed meanwhile"
        );
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "A");
        assert!(replace_if_unchanged(&f, "A", "C").unwrap());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "C");
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let left: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(left, ["config"], "no temp file left");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_our_exact_lines_go() {
        let text = format!(
            "{INCLUDE_COMMENT}\n{INCLUDE_LINE}\nHost a\n  # {INCLUDE_LINE}\nInclude ~/.ssh/ewe-safe/config2\n{INCLUDE_LINE}\n"
        );
        let (rest, found) = without_our_lines(&text);
        assert!(found);
        assert_eq!(
            rest,
            format!("Host a\n  # {INCLUDE_LINE}\nInclude ~/.ssh/ewe-safe/config2\n")
        );
        assert_eq!(first_directive(&text), Some(INCLUDE_LINE));
        assert_eq!(first_directive("# x\n\n  Host y\n"), Some("Host y"));
    }

    #[test]
    fn a_public_file_has_the_key_and_its_title() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl old comment";
        assert_eq!(
            key_file_text(line, "GitHub\nkey").as_deref(),
            Some(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl GitHub key\n"
            )
        );
        assert_eq!(key_file_text("not a key", "x"), None);
    }

    /// S26: every shipped host key is the one the service publishes. The
    /// fingerprints were copied from these pages on 2026-11-01; a key a
    /// service rotates fails here first.
    #[test]
    fn the_shipped_host_keys_are_the_published_ones() {
        let published: &[(&str, &str, &str, &str)] = &[
            // https://api.github.com/meta (ssh_key_fingerprints)
            (
                "github.com",
                "ssh-ed25519",
                "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
                "https://api.github.com/meta",
            ),
            (
                "github.com",
                "ecdsa-sha2-nistp256",
                "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
                "https://api.github.com/meta",
            ),
            (
                "github.com",
                "ssh-rsa",
                "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
                "https://api.github.com/meta",
            ),
            // https://docs.gitlab.com/user/gitlab_com/ ("SSH host keys fingerprints")
            (
                "gitlab.com",
                "ssh-ed25519",
                "SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8",
                "https://docs.gitlab.com/user/gitlab_com/",
            ),
            (
                "gitlab.com",
                "ecdsa-sha2-nistp256",
                "SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw",
                "https://docs.gitlab.com/user/gitlab_com/",
            ),
            (
                "gitlab.com",
                "ssh-rsa",
                "SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ",
                "https://docs.gitlab.com/user/gitlab_com/",
            ),
            // https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/
            // (the lines themselves: https://bitbucket.org/site/ssh)
            (
                "bitbucket.org",
                "ssh-ed25519",
                "SHA256:ybgmFkzwOSotHTHLJgHO0QN8L0xErw6vd0VhFA9m3SM",
                "https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/",
            ),
            (
                "bitbucket.org",
                "ecdsa-sha2-nistp256",
                "SHA256:FC73VB6C4OQLSCrjEayhMp9UMxS97caD/Yyi2bhW/J0",
                "https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/",
            ),
            (
                "bitbucket.org",
                "ssh-rsa",
                "SHA256:46OSHA1Rmj8E8ERTC6xkNcmGOw9oFxYr0WF6zWW8l1E",
                "https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/",
            ),
            // https://learn.microsoft.com/en-us/azure/devops/repos/git/use-ssh-keys-to-authenticate
            (
                "ssh.dev.azure.com",
                "ssh-rsa",
                "SHA256:ohD8VZEXGWo6Ez8GSEJQ9WpafgLFsOfLOtGGQCQo6Og",
                "https://learn.microsoft.com/en-us/azure/devops/repos/git/use-ssh-keys-to-authenticate",
            ),
            (
                "vs-ssh.visualstudio.com",
                "ssh-rsa",
                "SHA256:ohD8VZEXGWo6Ez8GSEJQ9WpafgLFsOfLOtGGQCQo6Og",
                "https://learn.microsoft.com/en-us/azure/devops/repos/git/use-ssh-keys-to-authenticate",
            ),
            // https://docs.codeberg.org/security/ssh-fingerprint/
            (
                "codeberg.org",
                "ssh-ed25519",
                "SHA256:mIlxA9k46MmM6qdJOdMnAQpzGxF4WIVVL+fj+wZbw0g",
                "https://docs.codeberg.org/security/ssh-fingerprint/",
            ),
            (
                "codeberg.org",
                "ecdsa-sha2-nistp256",
                "SHA256:T9FYDEHELhVkulEKKwge5aVhVTbqCW0MIRwAfpARs/E",
                "https://docs.codeberg.org/security/ssh-fingerprint/",
            ),
            (
                "codeberg.org",
                "ssh-rsa",
                "SHA256:6QQmYi4ppFS4/+zSZ5S4IU+4sa6rwvQ4PbhCtPEBekQ",
                "https://docs.codeberg.org/security/ssh-fingerprint/",
            ),
        ];
        let lines: Vec<(Vec<&str>, &str, String)> = KNOWN_HOSTS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let mut p = l.split_whitespace();
                let names = p.next().unwrap().split(',').collect();
                let kind = p.next().unwrap();
                let fp = keys::fingerprint_of_line(&format!("{kind} {}", p.next().unwrap()))
                    .expect("a key");
                (names, kind, fp)
            })
            .collect();
        for (host, kind, fp, source) in published {
            let found: Vec<&String> = lines
                .iter()
                .filter(|(n, k, _)| n.contains(host) && k == kind)
                .map(|(_, _, f)| f)
                .collect();
            assert_eq!(found, [fp], "{host} {kind}: the key {source} publishes");
        }
        assert_eq!(lines.len(), 13, "no line that isn't checked above");
        assert!(
            lines
                .iter()
                .all(|(n, _, _)| n.iter().all(|h| published.iter().any(|p| p.0 == *h)))
        );
    }
}
