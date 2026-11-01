//! Git commits signed with a key in Safe (docs/GATE.md S25), as 1Password
//! does it: `git config --global` points Git at the key's public file and
//! at `ewe-safe-ssh-sign` (ssh-keygen with Safe's agent), and Safe writes
//! `~/.ssh/ewe-safe/allowed_signers` so `git verify-commit` works. ewe.conf
//! `[safe] git_sign` (the key's fingerprint) carries it to every computer
//! of the account.
//!
//! Safe only ever sets, and unsets, the six keys below, and unsets one only
//! while it still holds Safe's value.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
/// What this computer's Git was last made to match (`git_sign`): set by
/// the verbs and by [`converge`]. None: not looked at yet.
static APPLIED: Mutex<Option<Option<String>>> = Mutex::new(None);

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

fn set(key: &str, value: &str) -> bool {
    git(&["config", "--global", key, value]).is_some_and(|(c, _)| c == 0)
}

fn unset(key: &str) -> bool {
    git(&["config", "--global", "--unset", key]).is_some_and(|(c, _)| c == 0)
}

/// Safe's signing is what Git has now.
fn safes_in_git(g: &HashMap<String, String>) -> bool {
    g.get("user.signingkey")
        .is_some_and(|v| v.starts_with(KEY_PREFIX) || v.contains("/.ssh/ewe-safe/key-"))
        || g.get("gpg.ssh.program").is_some_and(|v| v == PROGRAM)
}

/// The email for `allowed_signers`: `--email`, else Git's global
/// `user.email`.
pub fn email(arg: Option<&str>) -> Result<String, Fail> {
    if let Some(e) = arg.map(str::trim).filter(|e| !e.is_empty()) {
        if e.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Fail::bad("That isn't an email address."));
        }
        return Ok(e.to_string());
    }
    // --global: the daemon's working folder may be any repository
    git(&["config", "--global", "--get", "user.email"])
        .filter(|(c, o)| *c == 0 && !o.trim().is_empty())
        .map(|(_, o)| o.trim().to_string())
        .ok_or_else(|| {
            Fail::bad("Tell Safe your Git email: --email")
                .hint("ewe-safe ssh sign-commits ID --email you@example.com")
        })
}

/// Make Git sign with this key: the six keys (only those that differ),
/// `allowed_signers` (when the email is known). Whether anything changed.
fn configure(key: &gate::SafeKey, email: Option<&str>) -> Result<bool, Fail> {
    let fp = &key.fingerprint;
    let tilde = gate::key_file_tilde(fp)
        .ok_or_else(|| Fail::new("internal", "The key has no fingerprint."))?;
    gate::write_key_file(&key.line, &key.title).map_err(|e| {
        Fail::new(
            "internal",
            format!("Safe can't write the key's public file: {e}"),
        )
    })?;
    let mut changed = false;
    if let Some(e) = email {
        let line = format!("{e} namespaces=\"git\" {}\n", key.line);
        changed |= gate::write_if_changed(&gate::allowed_signers_file(), line.as_bytes(), 0o644)
            .map_err(|e| Fail::new("internal", format!("Safe can't write allowed_signers: {e}")))?;
    }
    let g = global();
    for (k, v) in wanted(&tilde) {
        if g.get(&k.to_lowercase()) != Some(&v) {
            if !set(k, &v) {
                return Err(Fail::new(
                    "internal",
                    format!("git config --global {k} failed"),
                ));
            }
            changed = true;
        }
    }
    Ok(changed)
}

/// Take Safe's signing out of Git: each key only while it holds Safe's
/// value; `allowed_signers` goes. The keys it unset.
fn unconfigure() -> Vec<&'static str> {
    let g = global();
    let mut gone = Vec::new();
    if !safes_in_git(&g) {
        let _ = std::fs::remove_file(gate::allowed_signers_file());
        return gone;
    }
    let safes = |k: &str, v: &str| match k {
        "user.signingkey" => v.starts_with(KEY_PREFIX) || v.contains("/.ssh/ewe-safe/key-"),
        "gpg.format" => v == "ssh",
        "gpg.ssh.program" => v == PROGRAM,
        "commit.gpgsign" | "tag.gpgsign" => v == "true",
        "gpg.ssh.allowedsignersfile" => {
            v == ALLOWED || v.ends_with("/.ssh/ewe-safe/allowed_signers")
        }
        _ => false,
    };
    for (k, _) in wanted("") {
        if g.get(&k.to_lowercase())
            .is_some_and(|v| safes(&k.to_lowercase(), v))
            && unset(k)
        {
            gone.push(k);
        }
    }
    let _ = std::fs::remove_file(gate::allowed_signers_file());
    gone
}

fn key_json(k: &gate::SafeKey) -> Value {
    k.json()
}

/// `ssh-status`'s `signing`: the account's signing key, or null.
pub fn status_json(d: &Daemon) -> Value {
    let Some(fp) = d.settings().git_sign else {
        return Value::Null;
    };
    let active = safes_in_git(&global());
    match gate::safe_keys(d).into_iter().find(|k| k.fingerprint == fp) {
        Some(k) => {
            let mut v = key_json(&k);
            v["active"] = json!(active);
            v
        }
        None => json!({"item_id": null, "title": null, "fingerprint": fp, "active": active}),
    }
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
    configure(&key, Some(email))?;
    *lk(&APPLIED) = Some(Some(key.fingerprint.clone()));
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
        let gone = unconfigure();
        *lk(&APPLIED) = Some(None);
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
    let was = d.settings().git_sign.is_some() || safes_in_git(&global());
    if was {
        unconfigure();
        *lk(&APPLIED) = Some(None);
        config::conf_store("git_sign", "");
        d.reload_settings();
    }
    was
}

/// Make this computer's Git match `[safe] git_sign` (at start and on every
/// settings read): with the agent on and that key in this safe, Git signs
/// with it; with signing off (or the agent off), Safe's values go.
pub fn converge(d: &Daemon) {
    let st = d.settings();
    // with signing off and Git already made to match, nothing to look at
    // (one `git config` a minute for nothing is not worth it)
    if st.git_sign.is_none() && *lk(&APPLIED) == Some(None) {
        return;
    }
    *lk(&APPLIED) = Some(st.git_sign.clone());
    match st.git_sign.as_deref() {
        Some(fp) if st.ssh_agent && d.is_set_up() => {
            let Some(key) = gate::safe_keys(d).into_iter().find(|k| k.fingerprint == fp) else {
                // not in this safe, or not known yet (locked, no list): wait
                return;
            };
            let email = email(None).ok();
            match configure(&key, email.as_deref()) {
                Ok(true) => log("Git signs commits with a key in Safe (ewe.conf: git_sign)"),
                Ok(false) => {}
                Err(f) => log(&format!("can't set up commit signing: {}", f.message)),
            }
        }
        Some(_) => {}
        None => {
            if safes_in_git(&global()) {
                let gone = unconfigure();
                log(&format!(
                    "commit signing is off (ewe.conf: git_sign): {} git keys unset",
                    gone.len()
                ));
            }
        }
    }
    if st.git_sign.is_some() && !st.ssh_agent && safes_in_git(&global()) {
        unconfigure();
        log("commit signing is off here: Safe's agent is off");
    }
}
