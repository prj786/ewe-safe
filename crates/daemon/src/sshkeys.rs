//! The `ssh-*` verbs (docs/PROTOCOL.md, "SSH keys"; TRIO.md S2): SSH key
//! items in, the agent on and off. The keys themselves are
//! `safe_core::ssh`; the agent is agent.rs.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use safe_core::Kind;
use safe_core::ssh as keys;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::agent;
use crate::config::{self, CONFIRMS};
use crate::daemon::{Daemon, Fail, item_json, rd};
use crate::log;

type Args = Map<String, Value>;

/// The environment.d file `enable` writes (and `disable` removes).
const ENV_FILE: &str = "90-ewe-safe-ssh.conf";
const ENV_MARK: &str = "# Written by `ewe-safe ssh enable`";

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
        other => Err(Fail::bad(format!("There is no verb {other:?}."))),
    }
}

/// The `ssh` object of an item (PROTOCOL.md).
pub fn ssh_json(info: &keys::Info) -> Value {
    json!({
        "public_key": info.public_key,
        "fingerprint": info.fingerprint,
        "key_type": info.key_type,
        "agent": info.agent,
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

fn add(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    let pass = secret(a, "passphrase");
    let bytes = read_file(s(a, "file"))?;
    if keys::is_encrypted(&bytes) && pass.is_empty() {
        return Err(Fail::bad("This key has a passphrase: give it too.")
            .hint("ewe-safe ssh add FILE --passphrase-stdin"));
    }
    let key = keys::read_key(&bytes, &pass).map_err(bad_key)?;
    drop(bytes);
    known(d, &key)?;
    let file_stem = s(a, "file")
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

fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".config")
        })
}

fn env_file() -> PathBuf {
    config_home().join("environment.d").join(ENV_FILE)
}

fn identity_agent(d: &Daemon) -> String {
    format!("IdentityAgent {}", d.paths.ssh_socket().display())
}

/// `IdentityAgent` lines in `~/.ssh/config` (read only, never written):
/// one names another agent for every host, and `SSH_AUTH_SOCK` is not
/// asked.
fn ssh_config_agents() -> Vec<String> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(home.join(".ssh/config")) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter_map(|l| {
            let (k, v) = l.split_once(|c: char| c.is_whitespace() || c == '=')?;
            k.eq_ignore_ascii_case("identityagent")
                .then(|| v.trim_start_matches(|c: char| c.is_whitespace() || c == '='))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .filter(|v| !v.is_empty())
        .collect()
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
    let file = env_file();
    let body = format!(
        "{ENV_MARK}: ssh and git use the keys in Safe.\n# `ewe-safe ssh disable` removes this file.\nSSH_AUTH_SOCK=${{XDG_RUNTIME_DIR}}/{}\n",
        config::SSH_SOCKET
    );
    let written = file
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| safe_core::atomic::write(&file, body.as_bytes()));
    if let Err(e) = &written {
        log(&format!("can't write {}: {e}", file.display()));
    }
    if let Some(ag) = agent::get() {
        ag.write_cache();
    }
    let line = identity_agent(d);
    let mut v = json!({
        "enabled": d.settings().ssh_agent,
        "recorded": recorded,
        "socket": d.paths.ssh_socket(),
        "env_file": written.is_ok().then_some(&file),
        "identity_agent": line,
        "hint": format!("New sessions get SSH_AUTH_SOCK. For ssh now, and when ~/.ssh/config names another agent, put this line under Host * in ~/.ssh/config: {line}"),
    });
    if !recorded {
        v["hint"] = json!(
            "ewe-conf could not store [safe] ssh_agent = true, so the agent stays off: check that ewe-conf works"
        );
    }
    Ok(v)
}

fn disable(d: &Arc<Daemon>) -> Result<Value, Fail> {
    let recorded = config::conf_store("ssh_agent", "false");
    d.reload_settings();
    let file = env_file();
    let ours = std::fs::read_to_string(&file).is_ok_and(|t| t.starts_with(ENV_MARK));
    let removed = ours && std::fs::remove_file(&file).is_ok();
    Ok(json!({
        "enabled": d.settings().ssh_agent,
        "recorded": recorded,
        "env_file_removed": removed,
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
    let file = env_file();
    json!({
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
    })
}
