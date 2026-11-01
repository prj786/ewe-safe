//! `ssh-takeover` (docs/GATE.md S23): "Move SSH to Safe". The gate goes
//! on, the private key files in `~/.ssh` come into the safe (files are
//! never changed or deleted), ewe.conf's hosts stop naming another agent,
//! and what another agent holds that Safe doesn't is listed (Safe can't
//! take a private key out of an agent). Needs the safe unlocked, a dry run
//! too. One save for every key that comes in.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use safe_core::ssh as keys;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::config;
use crate::daemon::{Daemon, Fail, rd};
use crate::gate;
use crate::hosts;
use crate::log;

type Args = Map<String, Value>;

/// `passphrases: {"<file>": "<passphrase>"}`: secrets, taken out of the
/// request at once and wiped when dropped.
fn take_passphrases(a: &mut Args) -> HashMap<String, Zeroizing<String>> {
    let mut out = HashMap::new();
    if let Some(Value::Object(m)) = a.remove("passphrases") {
        for (k, v) in m {
            if let Value::String(p) = v {
                out.insert(k, Zeroizing::new(p));
            }
        }
    }
    out
}

/// A key file that comes in: the key, its title, its passphrase.
struct Incoming {
    file: String,
    key: keys::KeyFile,
    title: String,
    pass: Zeroizing<String>,
}

fn file_title(key: &keys::KeyFile, path: &Path) -> String {
    let c = key.comment.trim();
    if c.is_empty() {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| key.file_name.clone())
    } else {
        c.to_string()
    }
}

pub fn takeover(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    let passes = take_passphrases(a);
    let dry = a.get("dry_run").and_then(Value::as_bool) == Some(true);
    let caller = a
        .get("ssh_auth_sock")
        .and_then(Value::as_str)
        .map(str::to_string);
    {
        let snap = rd(&d.snap);
        if !snap.set_up {
            return Err(Fail::not_set_up());
        }
        if snap.locked {
            return Err(Fail::locked());
        }
    }
    // ewe.conf's hosts must be readable: a write after a failed read would
    // drop the others
    let mut ewe = hosts::ewe_hosts()?;

    // 1. the gate
    let mut enabled = d.settings().ssh_agent && gate::is_on();
    if !dry && !enabled {
        let _turning = crate::daemon::lk(&gate::TURNING);
        if !config::conf_store("ssh_agent", "true") {
            return Err(Fail::new(
                "internal",
                "ewe-conf could not store [safe] ssh_agent = true, so Safe can't be your SSH agent",
            )
            .hint("Check that ewe-conf works: ewe-conf get safe"));
        }
        d.reload_settings();
        gate::apply(d).map_err(|e| {
            Fail::new(
                "internal",
                format!("Safe can't put the SSH gate in place: {e}"),
            )
        })?;
        if let Some(ag) = crate::agent::get() {
            ag.write_cache();
        }
        enabled = gate::is_on();
    }

    // 2. key files
    let safe = gate::safe_keys(d);
    let in_safe = |fp: &str| safe.iter().find(|k| k.fingerprint == fp);
    let mut already = Vec::new();
    let mut needs = Vec::new();
    let mut skipped = Vec::new();
    let mut incoming: Vec<Incoming> = Vec::new();
    for kf in gate::key_files(&ewe) {
        let file = kf.path.to_string_lossy().into_owned();
        if let Some(k) = kf.fingerprint.as_deref().and_then(in_safe) {
            already.push(json!({"item_id": k.item_id, "title": k.title, "file": file}));
            continue;
        }
        if kf
            .fingerprint
            .as_ref()
            .is_some_and(|fp| incoming.iter().any(|i| &i.key.fingerprint == fp))
        {
            // the same key in two files comes in once
            continue;
        }
        let Some(bytes) = gate::read_private(&kf.path) else {
            skipped.push(json!({"file": file, "reason": "Safe can't read this file."}));
            continue;
        };
        let pass = if kf.encrypted {
            match passes.get(&file) {
                Some(p) if !p.is_empty() => p.clone(),
                _ => {
                    needs.push(json!(file));
                    continue;
                }
            }
        } else {
            Zeroizing::new(String::new())
        };
        match keys::read_key(&bytes, &pass) {
            Ok(key) => {
                if let Some(k) = in_safe(&key.fingerprint) {
                    already.push(json!({"item_id": k.item_id, "title": k.title, "file": file}));
                    continue;
                }
                let title = file_title(&key, &kf.path);
                incoming.push(Incoming {
                    file,
                    key,
                    title,
                    pass,
                });
            }
            Err(e) => skipped.push(json!({"file": file, "reason": e.0})),
        }
    }
    let ids: Vec<Option<String>> = if dry || incoming.is_empty() {
        vec![None; incoming.len()]
    } else {
        let (ids, _) = d.mutate(|s| {
            let mut ids = Vec::new();
            for i in &incoming {
                ids.push(Some(s.add_ssh_key(&i.key, &i.title, &i.pass, "")?));
            }
            Ok((ids, true))
        })?;
        log(&format!("ssh takeover: {} key files came in", ids.len()));
        ids
    };
    let imported: Vec<Value> = incoming
        .iter()
        .zip(&ids)
        .map(|(i, id)| json!({"item_id": id, "title": i.title, "file": i.file}))
        .collect();
    let mut files_left: Vec<String> = already
        .iter()
        .chain(&imported)
        .filter_map(|v| v["file"].as_str().map(str::to_string))
        .collect();
    files_left.sort();
    files_left.dedup();

    // 3. ewe.conf's hosts: no IdentityAgent but Safe's
    let socket = d.paths.ssh_socket();
    let is_ours =
        |v: &str| v.ends_with(&format!("/{}", config::SSH_SOCKET)) || Path::new(v) == socket;
    let mut fixed = Vec::new();
    for h in &mut ewe {
        if h.get("identityagent").is_some_and(|v| !is_ours(v)) {
            h.remove("identityagent");
            fixed.push(h.host.clone());
        }
    }
    if !dry && !fixed.is_empty() {
        hosts::store_ewe_hosts(&ewe)?;
        log(&format!(
            "ssh takeover: {} hosts in ewe.conf ask Safe now",
            fixed.len()
        ));
    }
    let file = hosts::read_config();
    let overridden: Vec<Value> = gate::overridden(d, &file, &ewe)
        .into_iter()
        .map(|(host, agent)| json!({"host": host, "agent": agent}))
        .collect();

    // 4. other agents: what only they hold
    let now_safe: Vec<String> = safe
        .iter()
        .map(|k| k.fingerprint.clone())
        .chain(incoming.iter().map(|i| i.key.fingerprint.clone()))
        .collect();
    let mut missing = Vec::new();
    for ag in gate::other_agents(d, &file, &ewe, caller.as_deref()) {
        for line in &ag.keys {
            let Some(fp) = keys::fingerprint_of_line(line) else {
                continue;
            };
            if now_safe.contains(&fp) {
                continue;
            }
            let comment = line
                .split_whitespace()
                .skip(2)
                .collect::<Vec<_>>()
                .join(" ");
            missing.push(json!({
                "agent": ag.name,
                "comment": comment,
                "fingerprint": fp,
                "key_type": keys::key_type_of_line(line),
            }));
        }
    }

    let mut hint = Vec::new();
    if !files_left.is_empty() {
        hint.push(
            "Safe signs for these key files now. Delete the files when you are ready.".to_string(),
        );
    }
    if !missing.is_empty() {
        hint.push("Import them from 1Password first: Safe → Import (or `ewe-safe import op`), then `ewe-safe ssh adopt`.".to_string());
    }
    if !needs.is_empty() {
        hint.push(
            "Some key files have a passphrase: give it, and Safe takes them in too.".to_string(),
        );
    }
    let mut v = json!({
        "enabled": enabled,
        "gate": gate::status_json(d, caller.as_deref()),
        "imported": imported,
        "already": already,
        "needs_passphrase": needs,
        "skipped": skipped,
        "hosts_fixed": fixed,
        "overridden": overridden,
        "missing_from_safe": missing,
        "files_left": files_left,
        "hint": (!hint.is_empty()).then(|| hint.join(" ")),
    });
    if dry {
        v["dry_run"] = json!(true);
    } else {
        v["sync"] = crate::daemon::sync_json(&rd(&d.snap));
    }
    Ok(v)
}
