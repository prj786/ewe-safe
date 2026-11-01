//! Git commits signed with a key in Safe (docs/GATE.md S25), as 1Password
//! does it: `git config --global` points Git at the key's public file and
//! at `ewe-safe-ssh-sign` (ssh-keygen with Safe's agent), and Safe writes
//! `~/.ssh/ewe-safe/allowed_signers` so `git verify-commit` works. ewe.conf
//! `[safe] git_sign` (the key's fingerprint) carries it to every computer
//! of the account.
//!
//! Safe touches Git's config only where it applied its own values, and
//! keeps a note of it: `$XDG_STATE_HOME/ewe/safe/git-signing.json`, what it
//! set and what each key held before. Without that note it never unsets
//! anything; turning signing off puts the old values back, each key only
//! while it still holds Safe's value. On another computer of the account a
//! Git with its own signing set up is left alone.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::config;
use crate::daemon::{Daemon, Fail, lk};
use crate::gate;
use crate::log;

type Args = Map<String, Value>;

/// Git's `gpg.ssh.program` while Safe signs (packaging/ewe-safe-ssh-sign).
pub const PROGRAM: &str = "ewe-safe-ssh-sign";
const ALLOWED: &str = "~/.ssh/ewe-safe/allowed_signers";
const KEY_PREFIX: &str = "~/.ssh/ewe-safe/key-";
/// Said once in the log, not every minute.
static OWN_SETUP_SAID: AtomicBool = AtomicBool::new(false);

/// The six keys and their values, for a key's public file (`~` form).
fn wanted(file: &str) -> [(&'static str, String); 6] {
    [
        ("gpg.format", "ssh".into()),
        ("user.signingkey", file.into()),
        ("gpg.ssh.program", PROGRAM.into()),
        ("commit.gpgsign", "true".into()),
        ("tag.gpgsign", "true".into()),
        ("gpg.ssh.allowedSignersFile", ALLOWED.into()),
    ]
}

fn git(args: &[&str]) -> Option<(i32, String)> {
    let (code, out, _) = config::run_full("git", args, &[], Duration::from_secs(10))?;
    Some((code, String::from_utf8_lossy(&out).into_owned()))
}

/// `git config --global --list`, keys in lower case (as Git prints them).
fn global() -> HashMap<String, String> {
    let Some((0, out)) = git(&["config", "--global", "--list", "-z"]) else {
        return HashMap::new();
    };
    out.split('\0')
        .filter_map(|e| {
            let (k, v) = e.split_once('\n').unwrap_or((e, ""));
            (!k.is_empty()).then(|| (k.to_lowercase(), v.to_string()))
        })
        .collect()
}

fn get<'a>(g: &'a HashMap<String, String>, key: &str) -> Option<&'a String> {
    g.get(&key.to_lowercase())
}

fn set(key: &str, value: &str) -> bool {
    git(&["config", "--global", key, value]).is_some_and(|(c, _)| c == 0)
}

fn unset(key: &str) -> bool {
    git(&["config", "--global", "--unset", key]).is_some_and(|(c, _)| c == 0)
}

fn is_safe_key_file(v: &str) -> bool {
    v.starts_with(KEY_PREFIX) || v.contains("/.ssh/ewe-safe/key-")
}

/// A value only Safe sets (so never one to put back later).
fn is_safes_own(key: &str, v: &str) -> bool {
    match key {
        "user.signingkey" => is_safe_key_file(v),
        "gpg.ssh.program" => v == PROGRAM,
        "gpg.ssh.allowedSignersFile" => v == ALLOWED,
        _ => false,
    }
}

/// Git signs with something of the user's own: a signing key that isn't
/// one of Safe's files, or a format other than SSH.
fn own_setup(g: &HashMap<String, String>) -> bool {
    get(g, "user.signingkey").is_some_and(|v| !is_safe_key_file(v))
        || get(g, "gpg.format").is_some_and(|v| v != "ssh")
}

// ── the note of what Safe set ───────────────────────────────────────────

/// `git-signing.json`: the key Safe set Git up with, the values it set,
/// and what each of those keys held before (null: unset).
#[derive(Clone, Debug, Default, PartialEq)]
struct Marker {
    fingerprint: String,
    set: Vec<(String, String)>,
    previous: Vec<(String, Option<String>)>,
}

impl Marker {
    fn set_value(&self, key: &str) -> Option<&str> {
        self.set
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn marker_path(d: &Daemon) -> std::path::PathBuf {
    d.paths.state.join("git-signing.json")
}

fn read_marker(d: &Daemon) -> Option<Marker> {
    let v: Value = serde_json::from_slice(&std::fs::read(marker_path(d)).ok()?).ok()?;
    let pairs = |k: &str| {
        v.get(k)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    };
    Some(Marker {
        fingerprint: v.get("fingerprint")?.as_str()?.to_string(),
        set: pairs("set")
            .into_iter()
            .filter_map(|(k, x)| Some((k, x.as_str()?.to_string())))
            .collect(),
        previous: pairs("previous")
            .into_iter()
            .map(|(k, x)| (k, x.as_str().map(str::to_string)))
            .collect(),
    })
}

fn write_marker(d: &Daemon, m: &Marker) -> Result<(), Fail> {
    let set: Map<String, Value> = m.set.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let previous: Map<String, Value> = m
        .previous
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    let v = json!({"v": 1, "fingerprint": m.fingerprint, "set": set, "previous": previous});
    let mut bytes = serde_json::to_vec_pretty(&v).unwrap_or_default();
    bytes.push(b'\n');
    safe_core::atomic::write(&marker_path(d), &bytes).map_err(|e| {
        Fail::new(
            "internal",
            format!("Safe can't note what it set in Git: {e}"),
        )
    })
}

/// An email that can go in `allowed_signers` as a principal: one word,
/// none of `, * ! # "` (the file's own syntax).
fn valid_email(e: &str) -> bool {
    !e.is_empty()
        && e.len() <= 254
        && !e.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, ',' | '*' | '!' | '#' | '"')
        })
}

/// The email for `allowed_signers`: `--email`, else Git's global
/// `user.email`.
pub fn email(arg: Option<&str>) -> Result<String, Fail> {
    if let Some(e) = arg.map(str::trim).filter(|e| !e.is_empty()) {
        if !valid_email(e) {
            return Err(Fail::bad("That isn't an email address Git can use here."));
        }
        return Ok(e.to_string());
    }
    // --global: the daemon's working folder may be any repository
    let found = git(&["config", "--global", "--get", "user.email"])
        .filter(|(c, o)| *c == 0 && !o.trim().is_empty())
        .map(|(_, o)| o.trim().to_string())
        .ok_or_else(|| {
            Fail::bad("Tell Safe your Git email: --email")
                .hint("ewe-safe ssh sign-commits ID --email you@example.com")
        })?;
    if !valid_email(&found) {
        return Err(Fail::bad(
            "Git's user.email can't go in allowed_signers: give one with --email",
        )
        .hint("ewe-safe ssh sign-commits ID --email you@example.com"));
    }
    Ok(found)
}

/// Why Safe left Git alone on this computer.
#[derive(Debug)]
enum Skip {
    /// Git signs with the user's own setup (converge only).
    OwnSetup,
    Failed(Fail),
}

/// Make Git sign with this key. `by_user` (`sign-commits`, `connect
/// --sign`): set the six keys, noting what they held before. Otherwise
/// (another computer of the account turned it on): leave a Git with its
/// own signing alone, and leave a key the user changed since Safe set it.
/// Whether anything changed.
fn apply(
    d: &Daemon,
    key: &gate::SafeKey,
    email: Option<&str>,
    by_user: bool,
) -> Result<bool, Skip> {
    let g = global();
    let marker = read_marker(d);
    if !by_user && marker.is_none() && own_setup(&g) {
        return Err(Skip::OwnSetup);
    }
    let fail = |f: Fail| Skip::Failed(f);
    let tilde = gate::key_file_tilde(&key.fingerprint)
        .ok_or_else(|| fail(Fail::new("internal", "The key has no fingerprint.")))?;
    gate::write_key_file(&key.line, &key.title).map_err(|e| {
        fail(Fail::new(
            "internal",
            format!("Safe can't write the key's public file: {e}"),
        ))
    })?;
    let mut changed = false;
    if let Some(e) = email.filter(|e| valid_email(e)) {
        let line = format!("{e} namespaces=\"git\" {}\n", key.line);
        changed |= gate::write_if_changed(&gate::allowed_signers_file(), line.as_bytes(), 0o644)
            .map_err(|e| {
                fail(Fail::new(
                    "internal",
                    format!("Safe can't write allowed_signers: {e}"),
                ))
            })?;
    }
    let want = wanted(&tilde);
    // what the keys held before Safe: the note's, else what they hold now
    let previous: Vec<(String, Option<String>)> = match &marker {
        Some(m) => m.previous.clone(),
        None => want
            .iter()
            .map(|(k, _)| {
                let now = get(&g, k).filter(|v| !is_safes_own(k, v)).cloned();
                (k.to_string(), now)
            })
            .collect(),
    };
    // noted first: a crash after a `git config` still knows what to undo
    write_marker(
        d,
        &Marker {
            fingerprint: key.fingerprint.clone(),
            set: want
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            previous,
        },
    )
    .map_err(fail)?;
    for (k, v) in &want {
        let now = get(&g, k);
        if now == Some(v) {
            continue;
        }
        if !by_user && let Some(m) = &marker {
            // a key the user changed (or removed) since Safe set it is theirs
            let safes = m.set_value(k);
            if now.map(String::as_str) != safes && !(now.is_some_and(|x| is_safes_own(k, x))) {
                continue;
            }
        }
        if !set(k, v) {
            return Err(fail(Fail::new(
                "internal",
                format!("git config --global {k} failed"),
            )));
        }
        changed = true;
    }
    Ok(changed)
}

/// Put Git back as it was before Safe: each key Safe set gets its old
/// value back (or is unset when it had none), only while it still holds
/// Safe's value. No note: nothing is touched. The keys it put back.
fn unconfigure(d: &Daemon) -> Vec<String> {
    let mut done = Vec::new();
    if let Some(m) = read_marker(d) {
        let g = global();
        for (k, v) in &m.set {
            if get(&g, k) != Some(v) {
                continue;
            }
            let before = m
                .previous
                .iter()
                .find(|(p, _)| p == k)
                .and_then(|(_, x)| x.clone());
            let ok = match before {
                Some(old) => set(k, &old),
                None => unset(k),
            };
            if ok {
                done.push(k.clone());
            }
        }
        let _ = std::fs::remove_file(marker_path(d));
    }
    let _ = std::fs::remove_file(gate::allowed_signers_file());
    done
}

fn key_json(k: &gate::SafeKey) -> Value {
    k.json()
}

/// `ssh-status`'s `signing`: the account's signing key, or null; `active`
/// (Git here signs with it through Safe) and, when not, `reason`.
pub fn status_json(d: &Daemon) -> Value {
    let st = d.settings();
    let Some(fp) = st.git_sign else {
        return Value::Null;
    };
    let g = global();
    let marker = read_marker(d);
    let key = gate::safe_keys(d).into_iter().find(|k| k.fingerprint == fp);
    let active = marker.as_ref().is_some_and(|m| {
        m.fingerprint == fp
            && get(&g, "user.signingkey").map(String::as_str) == m.set_value("user.signingkey")
    });
    let reason = if active {
        None
    } else if !st.ssh_agent {
        Some("Safe's agent is off on this computer.")
    } else if key.is_none() {
        Some("That key isn't in this safe, or Safe hasn't seen it yet: unlock Safe.")
    } else if marker.is_none() && own_setup(&g) {
        Some(
            "Git on this computer signs with your own setup, so Safe leaves it. To switch, turn signing on here.",
        )
    } else {
        Some("Git on this computer doesn't sign with Safe's key yet.")
    };
    let mut v = match key {
        Some(k) => key_json(&k),
        None => json!({"item_id": null, "title": null, "fingerprint": fp}),
    };
    v["active"] = json!(active);
    v["reason"] = json!(reason);
    v
}

/// Turn signing on with an item's key (`ssh sign-commits ID`, `ssh
/// connect --sign`); records `[safe] git_sign`.
pub fn turn_on(d: &Daemon, item_id: &str, email: &str) -> Result<Value, Fail> {
    let key = gate::safe_keys(d)
        .into_iter()
        .find(|k| k.item_id.as_deref() == Some(item_id))
        .ok_or_else(|| {
            if crate::daemon::rd(&d.snap).locked {
                Fail::locked()
            } else {
                Fail::new("not-found", format!("No SSH key {item_id}."))
            }
        })?;
    if !keys_ok(&key) {
        return Err(Fail::bad("Git signs with Ed25519, ECDSA or RSA keys only."));
    }
    gate::ensure_on(d)?;
    let _turning = lk(&gate::TURNING);
    match apply(d, &key, Some(email), true) {
        Ok(_) => {}
        Err(Skip::Failed(f)) => return Err(f),
        Err(Skip::OwnSetup) => {
            return Err(Fail::new("internal", "Safe left Git's own signing alone."));
        }
    }
    let recorded = config::conf_store("git_sign", &key.fingerprint);
    d.reload_settings();
    log("ssh sign-commits: Git signs commits with a key in Safe");
    Ok(json!({
        "item_id": key.item_id,
        "title": key.title,
        "fingerprint": key.fingerprint,
        "email": email,
        "file": gate::key_file_tilde(&key.fingerprint),
        "allowed_signers": gate::allowed_signers_file(),
        "recorded": recorded,
    }))
}

fn keys_ok(k: &gate::SafeKey) -> bool {
    matches!(k.key_type.as_str(), "ed25519" | "ecdsa" | "rsa")
}

/// `ssh-sign`: `item_id` and `email`, or `off`.
pub fn sign(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    if a.get("off").and_then(Value::as_bool) == Some(true) {
        let _turning = lk(&gate::TURNING);
        let gone = unconfigure(d);
        let recorded = config::conf_store("git_sign", "");
        d.reload_settings();
        log("ssh sign-commits: off");
        return Ok(json!({"signing": null, "unset": gone, "recorded": recorded}));
    }
    let id = a
        .get("item_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| Fail::bad("Which key? Give its item id, or --off."))?;
    let email = email(a.get("email").and_then(Value::as_str))?;
    let v = turn_on(d, id, &email)?;
    Ok(json!({"signing": v}))
}

/// `ssh disable`: signing needs the agent, so it goes too (else every
/// `git commit` would fail). Whether it was on.
pub fn off_for_disable(d: &Daemon) -> bool {
    let was = d.settings().git_sign.is_some() || read_marker(d).is_some();
    if was {
        unconfigure(d);
        config::conf_store("git_sign", "");
        d.reload_settings();
    }
    was
}

/// Make this computer's Git match `[safe] git_sign` (at start and on every
/// settings read): with the agent on and that key in this safe, Git signs
/// with it — unless Git here signs with the user's own setup; with signing
/// off (or the agent off), what Safe set goes back to what it was.
pub fn converge(d: &Daemon) {
    let st = d.settings();
    match st.git_sign.as_deref() {
        Some(fp) if st.ssh_agent && d.is_set_up() => {
            let Some(key) = gate::safe_keys(d).into_iter().find(|k| k.fingerprint == fp) else {
                // not in this safe, or not known yet (locked, no list): wait
                return;
            };
            // a Git email that can't be a principal: no allowed_signers
            let email = email(None).ok();
            match apply(d, &key, email.as_deref(), false) {
                Ok(true) => log("Git signs commits with a key in Safe (ewe.conf: git_sign)"),
                Ok(false) => {}
                Err(Skip::OwnSetup) => {
                    if !OWN_SETUP_SAID.swap(true, Ordering::SeqCst) {
                        log(
                            "ewe.conf has git_sign, but Git here signs with its own setup: left alone",
                        );
                    }
                }
                Err(Skip::Failed(f)) => log(&format!("can't set up commit signing: {}", f.message)),
            }
        }
        // on, but the safe isn't set up here yet: wait
        Some(_) if st.ssh_agent => {}
        // off, or Safe's agent is off: what Safe set goes
        _ => {
            if read_marker(d).is_some() {
                let back = unconfigure(d);
                log(&format!(
                    "commit signing is off here: {} git keys back as they were",
                    back.len()
                ));
            }
        }
    }
}
