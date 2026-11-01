//! The `ssh-*` verbs (docs/PROTOCOL.md, "SSH keys"; TRIO.md S2): SSH key
//! items in, the agent on and off. The keys themselves are
//! `safe_core::ssh`; the agent is agent.rs.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use safe_core::Kind;
use safe_core::ssh as keys;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::agent;
use crate::config::{self, CONFIRMS};
use crate::daemon::{Daemon, Fail, item_json, rd};
use crate::gate;
use crate::log;

type Args = Map<String, Value>;

/// What `enable` and `status` say when `ssh_confirm = never`.
const NEVER_WARNING: &str = "ssh_confirm is never: any program running as you can use your SSH keys while Safe is unlocked, without a question.";

fn s<'a>(a: &'a Args, k: &str) -> Option<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn secret(a: &mut Args, k: &str) -> Zeroizing<String> {
    match a.remove(k) {
        Some(Value::String(x)) => Zeroizing::new(x),
        _ => Zeroizing::new(String::new()),
    }
}

fn bad_key(e: keys::SshError) -> Fail {
    Fail::bad(e.0)
}

pub fn dispatch(d: &Arc<Daemon>, verb: &str, a: &mut Args) -> Result<Value, Fail> {
    match verb {
        "ssh-list" => list(d),
        "ssh-add" => add(d, a),
        "ssh-new" => new(d, a),
        "ssh-adopt" => adopt(d, a),
        "ssh-enable" => enable(d, a),
        "ssh-disable" => disable(d),
        "ssh-status" => Ok(status(d, a)),
        // the gate (docs/GATE.md S23–S25)
        "ssh-takeover" => crate::takeover::takeover(d, a),
        "ssh-services" => Ok(crate::connect::services_json()),
        "ssh-connect" => crate::connect::connect(d, a),
        "ssh-test" => crate::connect::test(d, a),
        "ssh-hosts" | "ssh-host-set" | "ssh-host-remove" => crate::hosts::dispatch(d, verb, a),
        "ssh-sign" => crate::signing::sign(d, a),
        other => Err(Fail::bad(format!("There is no verb {other:?}."))),
    }
}

/// The `ssh` object of an item (PROTOCOL.md): plus, for a key the agent
/// offers, `file` (its public file, S22) and `last_used` (`{at, program}`
/// or null: the agent's last signature with it on this computer).
pub fn ssh_json(info: &keys::Info) -> Value {
    let offered = info.agent && keys::supported_line(&info.public_key);
    json!({
        "public_key": info.public_key,
        "fingerprint": info.fingerprint,
        "key_type": info.key_type,
        "agent": info.agent,
        "file": offered.then(|| gate::key_file_tilde(&info.fingerprint)).flatten(),
        "last_used": agent::get().and_then(|ag| ag.last_used(&info.fingerprint)),
    })
}

fn list(d: &Daemon) -> Result<Value, Fail> {
    let snap = rd(&d.snap);
    if !snap.set_up {
        return Err(Fail::not_set_up());
    }
    if snap.locked {
        return Err(Fail::locked());
    }
    let items: Vec<Value> = snap
        .items
        .iter()
        .filter(|x| x.kind == Kind::SshKey)
        .map(item_json)
        .collect();
    drop(snap);
    d.mark_use();
    Ok(json!({"items": items}))
}

/// The key file's bytes (the daemon reads it itself, as `import` does).
fn read_file(path: Option<&str>) -> Result<Zeroizing<Vec<u8>>, Fail> {
    let path = path.ok_or_else(|| Fail::bad("ssh add needs the private key's file"))?;
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(Fail::bad("Give the key file's full path."));
    }
    let cant = |e: std::io::Error| Fail::bad(format!("Safe can't read {}: {e}", p.display()));
    let f = std::fs::File::open(p).map_err(cant)?;
    let size = f.metadata().map_err(cant)?.len();
    if size > keys::MAX_KEY_FILE {
        return Err(Fail::bad(format!(
            "{} is too big to be a private key.",
            p.display()
        )));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(size as usize));
    f.take(keys::MAX_KEY_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(cant)?;
    Ok(buf)
}

/// A key already in the safe (by its public key) isn't added twice.
fn known(d: &Daemon, key: &keys::KeyFile) -> Result<(), Fail> {
    let blob = keys::public_blob(&key.public_key);
    let snap = rd(&d.snap);
    let twice = snap.items.iter().any(|x| {
        x.ssh
            .as_ref()
            .is_some_and(|i| blob.is_some() && keys::public_blob(&i.public_key) == blob)
    });
    if twice {
        return Err(Fail::bad("Safe already has this key."));
    }
    Ok(())
}

fn added(id: String, key: &keys::KeyFile, sync: Value) -> Value {
    json!({
        "item_id": id,
        "ssh": {
            "public_key": key.public_key,
            "fingerprint": key.fingerprint,
            "key_type": key.key_type,
            "agent": true,
        },
        "sync": sync,
    })
}

/// The key's text as the client sent it (`private_key`, a secret), or the
/// file the daemon reads itself (`file`, a full path), size-checked both ways.
fn key_bytes(a: &mut Args) -> Result<Zeroizing<Vec<u8>>, Fail> {
    match a.remove("private_key") {
        Some(Value::String(text)) => {
            let text = Zeroizing::new(text);
            if text.len() as u64 > keys::MAX_KEY_FILE {
                return Err(Fail::bad("That is too big to be a private key."));
            }
            Ok(Zeroizing::new(text.as_bytes().to_vec()))
        }
        _ => read_file(s(a, "file")),
    }
}

fn add(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    let pass = secret(a, "passphrase");
    let bytes = key_bytes(a)?;
    if keys::is_encrypted(&bytes) && pass.is_empty() {
        return Err(Fail::bad("This key has a passphrase: give it too.")
            .hint("ewe-safe ssh add FILE --passphrase-stdin"));
    }
    let key = keys::read_key(&bytes, &pass).map_err(bad_key)?;
    drop(bytes);
    known(d, &key)?;
    let file_stem = s(a, "file_name")
        .or_else(|| s(a, "file"))
        .and_then(|f| Path::new(f).file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| key.file_name.clone());
    let title = s(a, "title")
        .map(str::to_string)
        .or_else(|| Some(key.comment.trim().to_string()).filter(|c| !c.is_empty()))
        .unwrap_or(file_stem);
    let folder = s(a, "folder").unwrap_or("").to_string();
    let (id, sync) =
        d.mutate(|safe| Ok((safe.add_ssh_key(&key, &title, &pass, &folder)?, true)))?;
    log(&format!("an SSH key came in ({})", key.key_type));
    Ok(added(id, &key, sync))
}

fn new(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    let title = s(a, "title")
        .ok_or_else(|| Fail::bad("ssh new needs --title"))?
        .to_string();
    let kind = s(a, "type").unwrap_or("ed25519").to_lowercase();
    let bits = match a.get("bits") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .or_else(|| v.as_str().and_then(|x| x.parse().ok()))
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| Fail::bad("--bits needs a whole number"))?,
        ),
    };
    {
        let snap = rd(&d.snap);
        if !snap.set_up {
            return Err(Fail::not_set_up());
        }
        if snap.locked {
            return Err(Fail::locked());
        }
    }
    let key = keys::generate(&kind, bits, &title).map_err(bad_key)?;
    let folder = s(a, "folder").unwrap_or("").to_string();
    let (id, sync) = d.mutate(|safe| Ok((safe.add_ssh_key(&key, &title, "", &folder)?, true)))?;
    log(&format!("a new SSH key ({})", key.key_type));
    Ok(added(id, &key, sync))
}

fn adopt(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    let dry = a.get("dry_run").and_then(Value::as_bool) == Some(true);
    let report = if dry {
        d.with_held(|h| {
            let mut copy = h.safe.clone();
            copy.adopt_ssh_keys(true).map_err(Fail::from)
        })?
    } else {
        let (r, sync) = d.mutate(|safe| {
            let r = safe.adopt_ssh_keys(false)?;
            let changed = !r.adopted.is_empty();
            Ok((r, changed))
        })?;
        log(&format!("{} notes became SSH keys", r.adopted.len()));
        let mut v = report_json(&r);
        v["sync"] = sync;
        return Ok(v);
    };
    let mut v = report_json(&report);
    v["dry_run"] = json!(true);
    Ok(v)
}

fn report_json(r: &keys::AdoptReport) -> Value {
    json!({
        "adopted": r.adopted.iter().map(|x| json!({"item_id": x.id, "title": x.title})).collect::<Vec<_>>(),
        "skipped": r.skipped.iter().map(|(t, why)| json!({"title": t, "reason": why})).collect::<Vec<_>>(),
    })
}

// ── on and off ──────────────────────────────────────────────────────────

fn identity_agent(d: &Daemon) -> String {
    format!("IdentityAgent {}", d.paths.ssh_socket().display())
}

/// `IdentityAgent` lines in `~/.ssh/config` (read only): with the gate
/// on, Safe's include comes first and wins over them.
fn ssh_config_agents() -> Vec<String> {
    crate::hosts::read_config().identity_agents
}

fn enable(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    let confirm = match s(a, "confirm") {
        None => None,
        Some(c) if CONFIRMS.contains(&c.to_lowercase().as_str()) => Some(c.to_lowercase()),
        Some(_) => return Err(Fail::bad("--confirm is first-use, every-time or never")),
    };
    let mut recorded = config::conf_store("ssh_agent", "true");
    if let Some(c) = &confirm {
        recorded &= config::conf_store("ssh_confirm", c);
    }
    d.reload_settings();
    // the gate (docs/GATE.md S21): only once the setting is recorded — no
    // SSH_AUTH_SOCK or Include pointing at an agent that stays off
    let applied = if recorded && d.settings().ssh_agent {
        let r = gate::apply(d);
        if let Err(e) = &r {
            log(&format!("can't put the SSH gate in place: {e}"));
        }
        r.is_ok()
    } else {
        false
    };
    if let Some(ag) = agent::get() {
        // the public-key list and the key files (S22)
        ag.write_cache();
    }
    let file = gate::env_file();
    let line = identity_agent(d);
    let mut v = json!({
        "enabled": d.settings().ssh_agent,
        "recorded": recorded,
        "socket": d.paths.ssh_socket(),
        "env_file": (applied && file.exists()).then_some(&file),
        "identity_agent": line,
        "hint": "Every ssh and git on this computer asks Safe now: ~/.ssh/config includes ~/.ssh/ewe-safe/config, which names Safe's agent. New sessions also get SSH_AUTH_SOCK.",
        "gate": gate::status_json(d, None),
    });
    if !recorded {
        v["hint"] = json!(
            "ewe-conf could not store [safe] ssh_agent = true, so the agent stays off: check that ewe-conf works"
        );
    }
    if d.settings().ssh_confirm == "never" {
        v["warning"] = json!(NEVER_WARNING);
    }
    Ok(v)
}

fn disable(d: &Arc<Daemon>) -> Result<Value, Fail> {
    // looked at first: once recorded, the worker's convergence may take it
    let file = gate::env_file();
    let had_env = file.exists();
    let recorded = config::conf_store("ssh_agent", "false");
    d.reload_settings();
    // signing needs the agent: commits would fail without it (GATE.md S25)
    let signing_off = crate::signing::off_for_disable(d);
    // the gate's lines and files, only what Safe wrote (S21)
    gate::remove();
    let removed = had_env && !file.exists();
    if let Some(ag) = agent::get() {
        ag.forget_cache();
    }
    Ok(json!({
        "enabled": d.settings().ssh_agent,
        "recorded": recorded,
        "env_file_removed": removed,
        "signing_off": signing_off,
        "gate": gate::status_json(d, None),
    }))
}

fn status(d: &Daemon, a: &Args) -> Value {
    let st = d.settings();
    let socket = d.paths.ssh_socket();
    let caller = s(a, "ssh_auth_sock").map(str::to_string);
    let here = caller.as_deref().is_some_and(|c| {
        let p = Path::new(c);
        p == socket
            || std::fs::canonicalize(p).ok() == std::fs::canonicalize(&socket).ok() && p.exists()
    });
    let file = gate::env_file();
    let mut v = json!({
        "enabled": st.ssh_agent,
        "confirm": st.ssh_confirm,
        "socket": socket,
        "listening": agent::get().is_some_and(|ag| ag.listening()),
        "keys": agent::get().map(|ag| ag.key_count()),
        "locked": rd(&d.snap).locked,
        "ssh_auth_sock": caller,
        "points_here": here,
        "env_file": file.exists().then_some(&file),
        "identity_agent": identity_agent(d),
        "ssh_config_agents": ssh_config_agents(),
        "gate": gate::status_json(d, caller.as_deref()),
        "signing": crate::signing::status_json(d),
    });
    if st.ssh_confirm == "never" {
        v["warning"] = json!(NEVER_WARNING);
    }
    v
}
