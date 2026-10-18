//! The verbs (docs/PROTOCOL.md). `status`, `summary`, `list`, `search` and
//! `match` answer from the snapshot alone; nothing here logs a value, a
//! title or a username.

use std::sync::Arc;

use safe_core::{Draft, Field, Kind, generator, search};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::clip;
use crate::daemon::{Daemon, Fail, item_json, place_json, rd, sync_json};

type Args = Map<String, Value>;

fn s<'a>(a: &'a Args, k: &str) -> Option<&'a str> {
    a.get(k).and_then(Value::as_str)
}

fn n(a: &Args, k: &str) -> Result<Option<u64>, Fail> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(x)) => x
            .as_u64()
            .map(Some)
            .ok_or_else(|| Fail::bad(format!("--{} needs a whole number", k.replace('_', "-")))),
        Some(Value::String(x)) => x
            .parse()
            .map(Some)
            .map_err(|_| Fail::bad(format!("--{} needs a whole number", k.replace('_', "-")))),
        Some(_) => Err(Fail::bad(format!(
            "--{} needs a whole number",
            k.replace('_', "-")
        ))),
    }
}

fn b(a: &Args, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

/// A repeatable option: an array, or one string.
fn list(a: &Args, k: &str) -> Vec<String> {
    match a.get(k) {
        Some(Value::Array(v)) => v
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(x)) if !x.trim().is_empty() => vec![x.trim().to_string()],
        _ => Vec::new(),
    }
}

/// A secret taken out of the request, so it lives only in a wiped buffer.
fn secret(a: &mut Args, k: &str) -> Option<Zeroizing<String>> {
    match a.remove(k) {
        Some(Value::String(x)) => Some(Zeroizing::new(x)),
        _ => None,
    }
}

/// The snapshot, when the safe can be read: set up and unlocked.
fn open_snap(d: &Daemon) -> Result<std::sync::RwLockReadGuard<'_, crate::daemon::Snapshot>, Fail> {
    let snap = rd(&d.snap);
    if !snap.set_up {
        return Err(Fail::not_set_up());
    }
    if snap.locked {
        return Err(Fail::locked());
    }
    Ok(snap)
}

fn id(a: &Args) -> Result<String, Fail> {
    s(a, "id")
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Fail::bad("Which item? Give its id."))
}

pub fn dispatch(d: &Arc<Daemon>, verb: &str, a: &mut Args) -> Result<Value, Fail> {
    match verb {
        "ping" => Ok(json!({"pong": true})),
        "version" => Ok(json!({"version": safe_core::VERSION, "protocol": 1})),
        "status" => Ok(status(d)),
        "summary" => Ok(summary(d)),
        "init" | "open" => {
            let place = s(a, "place")
                .ok_or_else(|| {
                    Fail::bad(format!("{verb} needs --place local or --place nextcloud"))
                })?
                .to_string();
            let location = s(a, "location").map(str::to_string);
            let pw = secret(a, "password")
                .ok_or_else(|| Fail::bad("The master password is missing."))?;
            if verb == "init" {
                d.init(&place, location.as_deref(), &pw)
            } else {
                d.open(&place, location.as_deref(), &pw)
            }
        }
        "unlock" => {
            if b(a, "ask") {
                return Err(Fail::bad(
                    "--ask belongs to the ewe-safe CLI (it opens the prompt and waits); over the socket, send the password",
                ));
            }
            // login unlock (docs/SYSTEM.md §2): the login password, not the master
            if a.contains_key("login_password") {
                return crate::login::unlock(d, a);
            }
            let pw = secret(a, "password")
                .ok_or_else(|| Fail::bad("The master password is missing."))?;
            let items = d.unlock(&pw)?;
            Ok(json!({"items": items}))
        }
        // login unlock (docs/SYSTEM.md §2): the verbs, and the fresh-presence
        // confirm for a card fill (docs/SYSTEM.md §4)
        "login-status" => Ok(crate::login::status(d)),
        "login-enable" => crate::login::enable(d, a),
        "login-disable" => crate::login::disable(d),
        "confirm" => crate::login::confirm(d, a),
        "lock" => {
            d.lock("user");
            Ok(json!({"locked": true}))
        }
        "list" => list_items(d, a),
        "search" => {
            let text = s(a, "text").unwrap_or("");
            let snap = open_snap(d)?;
            let items: Vec<Value> = search::rank(&snap.items, text)
                .into_iter()
                .map(item_json)
                .collect();
            drop(snap);
            d.mark_use();
            Ok(json!({"items": items}))
        }
        "match" => matches(d, a),
        "show" => {
            let id = id(a)?;
            let notes_too = b(a, "reveal_notes");
            d.with_held(|h| {
                let sum = h.safe.summary(&id)?;
                let mut v = item_json(&sum);
                if sum.kind == Kind::Login || notes_too {
                    v["notes"] = json!(h.safe.draft(&id)?.notes.as_str());
                }
                Ok(json!({"item": v}))
            })
        }
        "reveal" => {
            let id = id(a)?;
            let field = s(a, "field").unwrap_or("password").to_string();
            let (value, left) = reveal(d, &id, &field)?;
            let mut v = json!({"value": value.as_str()});
            if let Some(left) = left {
                v["expires_in"] = json!(left);
            }
            Ok(v)
        }
        "copy" => {
            let id = id(a)?;
            let field = s(a, "field").unwrap_or("password").to_string();
            let clear = n(a, "clear_after")?.unwrap_or(d.settings().clipboard_clear_seconds);
            let (value, _) = reveal(d, &id, &field)?;
            clip::copy(
                d,
                &value,
                s(a, "wayland_display").map(str::to_string),
                clear,
            )?;
            Ok(json!({"copied": field, "cleared_after": clear}))
        }
        "add" => add(d, a),
        "edit" => edit(d, a),
        "rm" => {
            let id = id(a)?;
            let ((), sync) = d.mutate(|safe| Ok((safe.trash(&id)?, true)))?;
            Ok(json!({"sync": sync}))
        }
        "restore" => {
            let id = id(a)?;
            let ((), sync) = d.mutate(|safe| Ok((safe.restore(&id)?, true)))?;
            Ok(json!({"sync": sync}))
        }
        "generate" => {
            let (value, bits) = generate(d, a)?;
            Ok(json!({"value": value.as_str(), "bits": bits.round()}))
        }
        "sync" => {
            if !d.is_set_up() {
                return Err(Fail::not_set_up());
            }
            d.sync_once();
            Ok(json!({"sync": sync_json(&rd(&d.snap))}))
        }
        "place" => {
            let snap = rd(&d.snap);
            if !snap.set_up {
                return Err(Fail::not_set_up());
            }
            let probe = snap.probe.as_ref().map(|p| {
                json!({
                    "guarded": p.guarded,
                    "checked_at": p.checked_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                })
            });
            Ok(json!({
                "place": snap.place.as_ref().map(place_json),
                "sync": sync_json(&snap),
                "probe": probe,
            }))
        }
        "import" => crate::import::import(d, a),
        "resolve" => crate::resolve::resolve(d, a),
        "passkey-list" => crate::passkey::list(d, a),
        "passkey-create" => crate::passkey::create(d, a),
        "passkey-get" => crate::passkey::get(d, a),
        v if v.starts_with("ssh-") => crate::sshkeys::dispatch(d, v, a),
        "passwd" => {
            let new = secret(a, "new_password")
                .ok_or_else(|| Fail::bad("The new master password is missing."))?;
            if rd(&d.snap).locked {
                let cur = secret(a, "password").ok_or_else(Fail::locked)?;
                d.unlock(&cur)?;
            }
            d.passwd(&new)
        }
        other => Err(Fail::bad(format!("There is no verb {other:?}."))),
    }
}

fn status(d: &Daemon) -> Value {
    let snap = rd(&d.snap);
    // login unlock (docs/SYSTEM.md §2): a second method, and its own object
    let login = crate::login::status(d);
    let methods: Vec<&str> = if login["enabled"] == true {
        vec!["password", "login"]
    } else {
        vec!["password"]
    };
    let mut v = json!({
        "set_up": snap.set_up,
        "locked": snap.locked,
        "read_only": snap.reasons.is_some(),
        "place": snap.place.as_ref().map(place_json),
        "unlock_methods": methods,
        "login": login,
        "items": if snap.locked { Value::Null } else { json!(snap.items.len()) },
        "sync": sync_json(&snap),
        "version": safe_core::VERSION,
    });
    if let Some(r) = &snap.reasons {
        v["reasons"] = json!(r);
    }
    if let Some(u) = &snap.upgrade_from {
        // a KDBX 3.x/4.0 file becomes KDBX 4.1 at its next save (SPIKE-0, C5)
        v["upgrade_from"] = json!(u);
    }
    v
}

/// Counts and states only: what the companion may know (PLAN.md S8).
fn summary(d: &Daemon) -> Value {
    let snap = rd(&d.snap);
    json!({
        "locked": snap.locked,
        "items": if snap.locked { Value::Null } else { json!(snap.items.len()) },
        "sync_state": snap.sync.as_ref().map(|x| x.state.clone()),
    })
}

fn list_items(d: &Daemon, a: &Args) -> Result<Value, Fail> {
    let kind = match s(a, "kind") {
        None => None,
        Some(k) => {
            Some(Kind::parse(k).ok_or_else(|| Fail::bad("--kind is login, note or ssh-key"))?)
        }
    };
    let tag = s(a, "tag").map(str::to_lowercase);
    let snap = open_snap(d)?;
    let from = if b(a, "deleted") {
        &snap.deleted
    } else {
        &snap.items
    };
    let items: Vec<Value> = from
        .iter()
        .filter(|x| kind.is_none_or(|k| x.kind == k))
        .filter(|x| {
            tag.as_ref()
                .is_none_or(|t| x.tags.iter().any(|y| y.to_lowercase() == *t))
        })
        .map(item_json)
        .collect();
    drop(snap);
    d.mark_use();
    Ok(json!({"items": items}))
}

fn matches(d: &Daemon, a: &Args) -> Result<Value, Fail> {
    let limit = n(a, "limit")?.unwrap_or(0) as usize;
    let snap = open_snap(d)?;
    let found = search::match_logins(
        &snap.items,
        s(a, "class").unwrap_or(""),
        s(a, "title").unwrap_or(""),
        s(a, "url").unwrap_or(""),
        s(a, "query").unwrap_or(""),
    );
    let items: Vec<Value> = found
        .iter()
        .take(if limit == 0 { usize::MAX } else { limit })
        .map(|m| {
            let mut v = item_json(m.item);
            v["score"] = json!(m.score);
            v["reason"] = json!(m.reason);
            v
        })
        .collect();
    drop(snap);
    d.mark_use();
    Ok(json!({"items": items}))
}

/// One value; for `otp`, the current code and the seconds it stays valid.
fn reveal(d: &Daemon, id: &str, field: &str) -> Result<(Zeroizing<String>, Option<u64>), Fail> {
    d.with_held(|h| {
        if field == "otp" {
            let draft = h.safe.draft(id)?;
            if draft.otp.is_empty() {
                return Err(Fail::new("not-found", "This item has no one-time code."));
            }
            let totp = safe_core::otp::Totp::parse(&draft.otp).map_err(|e| {
                Fail::new("not-found", format!("The one-time code can't be read: {e}"))
            })?;
            let (code, left) = totp.now();
            return Ok((code, Some(left)));
        }
        Ok((h.safe.reveal(id, &Field::parse(field))?, None))
    })
}

fn generate(d: &Daemon, a: &Args) -> Result<(Zeroizing<String>, f64), Fail> {
    let st = d.settings();
    let bad = |e: generator::GeneratorError| Fail::bad(e.to_string());
    match n(a, "words")? {
        Some(w) => {
            let w = w as usize;
            Ok((
                generator::passphrase(w, "-").map_err(bad)?,
                generator::passphrase_bits(w),
            ))
        }
        None => {
            let len = n(a, "length")?
                .map(|x| x as usize)
                .unwrap_or(st.generator_length);
            let (symbols, digits) = (!b(a, "no_symbols"), !b(a, "no_digits"));
            Ok((
                generator::password_with(len, symbols, digits).map_err(bad)?,
                generator::password_bits_with(len, symbols, digits),
            ))
        }
    }
}

fn add(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    let kind = match s(a, "kind").unwrap_or("login") {
        "login" => Kind::Login,
        "note" => Kind::Note,
        _ => return Err(Fail::bad("--kind is login or note")),
    };
    let title = s(a, "title")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Fail::bad("add needs --title"))?
        .to_string();
    let mut draft = Draft {
        kind,
        title,
        username: s(a, "username").unwrap_or("").trim().to_string(),
        websites: list(a, "url"),
        apps: list(a, "app"),
        tags: list(a, "tag"),
        ..Draft::default()
    };
    if let Some(p) = secret(a, "password_value") {
        draft.password = p;
    } else if b(a, "generate") {
        draft.password = generate(d, a)?.0;
    }
    if let Some(notes) = secret(a, "notes") {
        draft.notes = notes;
    }
    let folder = s(a, "folder").unwrap_or("").to_string();
    let (id, sync) = d.mutate(|safe| Ok((safe.add_in(&draft, &folder)?, true)))?;
    // `id` is the socket's own request id (server.rs puts it on every
    // reply), so the new item's id travels as `item_id`
    Ok(json!({"item_id": id, "sync": sync}))
}

fn add_unique(to: &mut Vec<String>, more: Vec<String>) -> bool {
    let mut changed = false;
    for m in more {
        if !to.iter().any(|x| x.eq_ignore_ascii_case(&m)) {
            to.push(m);
            changed = true;
        }
    }
    changed
}

fn remove_all(from: &mut Vec<String>, gone: &[String]) -> bool {
    let before = from.len();
    from.retain(|x| !gone.iter().any(|g| g.eq_ignore_ascii_case(x)));
    from.len() != before
}

fn edit(d: &Arc<Daemon>, a: &mut Args) -> Result<Value, Fail> {
    let id = id(a)?;
    let title = s(a, "title").map(|t| t.trim().to_string());
    if title.as_deref() == Some("") {
        return Err(Fail::bad("A title can't be empty."));
    }
    let username = s(a, "username").map(|u| u.trim().to_string());
    let (urls, apps, tags) = (list(a, "url"), list(a, "app"), list(a, "tag"));
    let (no_apps, no_tags) = (list(a, "remove_app"), list(a, "remove_tag"));
    let clear_url = b(a, "clear_url");
    let folder = s(a, "folder").map(str::to_string);
    let password = match secret(a, "password_value") {
        Some(p) => Some(p),
        None if b(a, "generate") => Some(generate(d, a)?.0),
        None => None,
    };
    let notes = secret(a, "notes");
    let no_passkey = b(a, "remove_passkey");
    let ((), sync) = d.mutate(|safe| {
        let mut draft = safe.draft(&id)?;
        let mut changed = false;
        if let Some(t) = title {
            changed |= draft.title != t;
            draft.title = t;
        }
        if let Some(u) = username {
            changed |= draft.username != u;
            draft.username = u;
        }
        if clear_url && !draft.websites.is_empty() {
            draft.websites.clear();
            changed = true;
        }
        changed |= add_unique(&mut draft.websites, urls);
        changed |= add_unique(&mut draft.apps, apps);
        changed |= remove_all(&mut draft.apps, &no_apps);
        changed |= add_unique(&mut draft.tags, tags);
        changed |= remove_all(&mut draft.tags, &no_tags);
        if let Some(p) = password {
            changed |= *draft.password != *p;
            draft.password = p;
        }
        if let Some(nt) = notes {
            changed |= *draft.notes != *nt;
            draft.notes = nt;
        }
        if changed {
            safe.update(&id, &draft)?;
        }
        let mut moved = false;
        if let Some(f) = folder {
            let before = safe.summary(&id)?.folder;
            safe.move_to(&id, &f)?;
            moved = safe.summary(&id)?.folder != before;
        }
        let unkeyed = no_passkey && safe.remove_passkey(&id)?;
        Ok(((), changed || moved || unkeyed))
    })?;
    Ok(json!({"sync": sync}))
}
