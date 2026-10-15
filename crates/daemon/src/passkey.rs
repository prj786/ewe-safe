//! The passkey verbs (docs/PROTOCOL.md): `passkey-list` answers from the
//! snapshot, `passkey-create` saves through the tracked save like `add`,
//! `passkey-get` signs from the unlocked safe and saves nothing.
//!
//! Safe checks no origin: the browser took it from the frame and decided
//! which site asks. Here the RP ID is only checked for its shape and the
//! client data hash for its length. Nothing here logs an id, a title, a
//! username or a key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use chrono::NaiveDateTime;
use safe_core::passkey::{self, Flags, Key, New, PasskeyError};
use safe_core::{Draft, Kind};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::daemon::{Daemon, Fail, lk, rd};

type Args = Map<String, Value>;

/// When this daemon last used each credential: a sign-in moves a passkey up
/// the list without a save (the file's own `LastAccessTime` counts too).
/// Keyed by a hash, so no credential id stays here after a lock.
fn used() -> &'static Mutex<HashMap<[u8; 32], NaiveDateTime>> {
    static USED: OnceLock<Mutex<HashMap<[u8; 32], NaiveDateTime>>> = OnceLock::new();
    USED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn used_key(credential_id: &str) -> [u8; 32] {
    Sha256::digest(credential_id.as_bytes()).into()
}

fn now() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

fn s<'a>(a: &'a Args, k: &str) -> Option<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn b(a: &Args, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

/// A list of ids (one string is a list of one), each in base64url.
fn ids(a: &Args, k: &str) -> Vec<String> {
    match a.get(k) {
        Some(Value::Array(v)) => v
            .iter()
            .filter_map(Value::as_str)
            .filter(|x| !x.trim().is_empty())
            .map(passkey::normalize_id)
            .collect(),
        Some(Value::String(x)) if !x.trim().is_empty() => vec![passkey::normalize_id(x)],
        _ => Vec::new(),
    }
}

fn rp_id(a: &Args) -> Result<String, Fail> {
    let rp = s(a, "rp_id").ok_or_else(|| Fail::bad("Which site? Give its rp_id."))?;
    if passkey::valid_rp_id(rp) {
        Ok(rp.to_string())
    } else {
        Err(Fail::bad(
            "rp_id must be a lowercase host name, such as github.com.",
        ))
    }
}

fn client_data_hash(a: &Args) -> Result<Vec<u8>, Fail> {
    s(a, "client_data_hash")
        .and_then(passkey::from_b64)
        .filter(|h| h.len() == 32)
        .ok_or_else(|| Fail::bad("client_data_hash must be 32 bytes (SHA-256), base64url."))
}

fn failed(e: PasskeyError) -> Fail {
    match e {
        PasskeyError::Unsupported(m) => Fail::new("unsupported", m),
        PasskeyError::Key(m) => Fail::new("internal", m),
    }
}

fn not_found() -> Fail {
    Fail::new("not-found", "Safe has no such passkey for this site.")
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

/// `passkey-list`: the passkeys for one site (every one without `rp_id`),
/// only those `allow` names when it names any. Best first: last used, then
/// title.
pub fn list(d: &Daemon, a: &Args) -> Result<Value, Fail> {
    let rp = match a.get("rp_id") {
        None | Some(Value::Null) => None,
        Some(_) => Some(rp_id(a)?),
    };
    let allow = ids(a, "allow");
    let snap = open_snap(d)?;
    let seen = lk(used()).clone();
    let mut found: Vec<_> = snap
        .items
        .iter()
        .filter_map(|i| i.passkey.as_ref().map(|p| (i, p)))
        .filter(|(_, p)| rp.as_ref().is_none_or(|r| p.rp_id == *r))
        .filter(|(_, p)| allow.is_empty() || allow.contains(&p.credential_id))
        .map(|(i, p)| {
            (
                i,
                p,
                seen.get(&used_key(&p.credential_id)).copied().max(p.used),
            )
        })
        .collect();
    found.sort_by(|x, y| {
        y.2.cmp(&x.2)
            .then_with(|| x.0.title.to_lowercase().cmp(&y.0.title.to_lowercase()))
    });
    let passkeys: Vec<Value> = found
        .iter()
        .map(|(i, p, _)| {
            json!({
                "item_id": i.id,
                "title": i.title,
                "username": if p.username.is_empty() { &i.username } else { &p.username },
                "rp_id": p.rp_id,
                "credential_id": p.credential_id,
            })
        })
        .collect();
    drop(snap);
    d.mark_use();
    Ok(json!({"passkeys": passkeys}))
}

/// `passkey-create`: a new key for the site, on the login the browser
/// named or on a new one. One save (merge-safe, like `add`).
pub fn create(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    let rp_id = rp_id(a)?;
    client_data_hash(a)?; // `none` attestation signs nothing, but the shape is checked
    let user_id = s(a, "user_id")
        .and_then(passkey::from_b64)
        .filter(|u| !u.is_empty() && u.len() <= passkey::USER_HANDLE_MAX)
        .ok_or_else(|| Fail::bad("user_id must be 1 to 64 bytes, base64url."))?;
    let user_name = s(a, "user_name").unwrap_or("").to_string();
    let title = s(a, "rp_name").unwrap_or(&rp_id).to_string();
    let algorithms: Vec<i64> = match a.get("algorithms") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(v)) => v
            .iter()
            .map(|x| {
                x.as_i64()
                    .ok_or_else(|| Fail::bad("algorithms are COSE ids, such as -7."))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(Fail::bad("algorithms is a list of COSE ids.")),
    };
    let exclude = ids(a, "exclude");
    let item_id = s(a, "item_id").map(str::to_string);
    // the website of a new login: the page's origin when it is one, else
    // the RP ID's
    let website = s(a, "origin")
        .and_then(|o| url::Url::parse(o).ok())
        .filter(|u| matches!(u.scheme(), "https" | "http") && u.host_str().is_some())
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|| format!("https://{rp_id}"));
    let flags = Flags {
        up: true,
        uv: b(a, "user_verified"),
        be: true,
        bs: true,
    };

    // WebAuthn's order: no algorithm we make → NotSupportedError, before
    // the exclude list is looked at
    let alg = passkey::choose(&algorithms).ok_or_else(|| {
        Fail::new(
            "unsupported",
            "Safe can't make a passkey with an algorithm this site accepts.",
        )
    })?;
    let key = Key::generate(alg).map_err(failed)?;
    let raw_id = passkey::new_credential_id().map_err(failed)?;
    let credential_id = passkey::b64url(&raw_id);
    let new = New {
        rp_id: rp_id.clone(),
        username: user_name.clone(),
        credential_id: credential_id.clone(),
        pem: key.pem.clone(),
        user_handle: passkey::b64url(&user_id),
    };

    let (item_id, sync) = d.mutate(|safe| {
        let taken = safe
            .items()
            .iter()
            .filter_map(|i| i.passkey.as_ref())
            .any(|p| p.rp_id == rp_id && exclude.contains(&p.credential_id));
        if taken {
            return Err(Fail::new(
                "excluded",
                "Your safe already has a passkey for this account on this site.",
            ));
        }
        let id = match &item_id {
            Some(id) => {
                if safe.summary(id)?.kind != Kind::Login {
                    return Err(Fail::bad("A passkey goes on a login, not on a note."));
                }
                safe.set_passkey(id, &new)?;
                id.clone()
            }
            None => {
                let draft = Draft {
                    kind: Kind::Login,
                    title: title.clone(),
                    username: user_name.clone(),
                    websites: vec![website.clone()],
                    ..Draft::default()
                };
                safe.add_passkey_login(&draft, &new)?
            }
        };
        Ok((id, true))
    })?;
    lk(used()).insert(used_key(&credential_id), now());

    let auth = passkey::attested_data(&rp_id, flags, &passkey::AAGUID, &raw_id, &key.cose);
    Ok(json!({
        "item_id": item_id,
        "credential_id": credential_id,
        "attestation_object": passkey::b64url(&passkey::attestation_object(&auth)),
        "authenticator_data": passkey::b64url(&auth),
        "public_key": passkey::b64url(&key.spki),
        "public_key_algorithm": alg.cose(),
        "sync": sync,
    }))
}

/// `passkey-get`: sign the browser's client data hash with the passkey the
/// user picked. Saves nothing.
pub fn get(d: &Daemon, a: &Args) -> Result<Value, Fail> {
    let rp_id = rp_id(a)?;
    let credential_id = s(a, "credential_id")
        .map(passkey::normalize_id)
        .ok_or_else(|| Fail::bad("Which passkey? Give its credential_id."))?;
    let hash = client_data_hash(a)?;
    let uv = b(a, "user_verified");

    let item_id = {
        let snap = open_snap(d)?;
        snap.items
            .iter()
            .find(|i| {
                i.passkey
                    .as_ref()
                    .is_some_and(|p| p.rp_id == rp_id && p.credential_id == credential_id)
            })
            .map(|i| i.id.clone())
            .ok_or_else(not_found)?
    };
    let (auth, signature, user_handle) = d.with_held(|h| {
        // read again under the lock: a sync may have changed the item since
        let secret = h
            .safe
            .passkey_secret(&item_id)?
            .filter(|x| x.rp_id == rp_id && x.credential_id == credential_id)
            .ok_or_else(not_found)?;
        let flags = Flags {
            up: true,
            uv,
            be: secret.be,
            bs: secret.bs,
        };
        let auth = passkey::assertion_data(&rp_id, flags);
        let (_, sig) = passkey::sign(&secret.pem, &auth, &hash).map_err(failed)?;
        Ok((auth, sig, secret.user_handle))
    })?;
    lk(used()).insert(used_key(&credential_id), now());
    Ok(json!({
        "item_id": item_id,
        "credential_id": credential_id,
        "authenticator_data": passkey::b64url(&auth),
        "signature": passkey::b64url(&signature),
        "user_handle": if user_handle.is_empty() { Value::Null } else { json!(user_handle) },
    }))
}
