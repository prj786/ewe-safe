//! Passkeys (WebAuthn credentials), kept the way KeePassXC keeps them, so
//! KeePassXC, KeePassDX and Strongbox use a passkey made in Safe and Safe
//! uses theirs (docs/FORMAT.md, "Passkeys").
//!
//! - The fields on a login entry: [`store`], [`info_of`], [`secret_of`],
//!   [`remove`].
//! - A new key ([`Key::generate`]): ES256 (P-256) or EdDSA (Ed25519). The
//!   private half is PKCS#8 PEM, as KeePassXC writes it; the public half is
//!   a COSE_Key (for the site) and SPKI DER (for the browser's
//!   `getPublicKey()`).
//! - What an authenticator answers: authenticator data, a `none`
//!   attestation object (CBOR), an assertion signature ([`sign`]).
//!
//! No RS256: the `rsa` crate's private-key operations aren't constant-time
//! (RUSTSEC-2023-0071), and every site that asks for RS256 also takes ES256.
//! An RS256 passkey another app made is listed, and signing with it answers
//! [`PasskeyError::Unsupported`].
//!
//! Safe checks no origin here: the browser decided which site is asking.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::NaiveDateTime;
use keepass::db::Entry;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::pkcs8::der::Decode as _;
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// The entry's fields: KeePassXC's names (src/core/EntryAttributes.cpp),
// read the same by KeePassDX (PasskeyEntryFields.kt) and Strongbox.
pub const PREFIX: &str = "KPEX_PASSKEY";
pub const USERNAME: &str = "KPEX_PASSKEY_USERNAME";
pub const CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const PRIVATE_KEY_PEM: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
pub const FLAG_BE: &str = "KPEX_PASSKEY_FLAG_BE";
pub const FLAG_BS: &str = "KPEX_PASSKEY_FLAG_BS";
/// Strongbox's names. Read first when present, as KeePassXC reads them;
/// never written.
pub const GENERATED_USER_ID: &str = "KPEX_PASSKEY_GENERATED_USER_ID";
pub const KPXC_USERNAME: &str = "KPXC_PASSKEY_USERNAME";
/// The tag KeePassXC and KeePassDX put on an entry with a passkey.
pub const TAG: &str = "Passkey";

/// Safe's own AAGUID: 452b824e-42d3-4324-bc6c-581888ca2851.
pub const AAGUID: [u8; 16] = [
    0x45, 0x2b, 0x82, 0x4e, 0x42, 0xd3, 0x43, 0x24, 0xbc, 0x6c, 0x58, 0x18, 0x88, 0xca, 0x28, 0x51,
];
/// A new credential id: 32 random bytes, as KeePassXC makes them.
pub const CREDENTIAL_ID_LEN: usize = 32;
/// WebAuthn's limit for `user.id`.
pub const USER_HANDLE_MAX: usize = 64;

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";
// PKCS#8 algorithm identifiers (DER of the OIDs)
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyError {
    /// A key type Safe can't sign with (RS256), or no algorithm it can make.
    Unsupported(String),
    /// The stored key can't be read, or a key couldn't be made.
    Key(String),
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasskeyError::Unsupported(e) | PasskeyError::Key(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PasskeyError {}

/// The algorithms Safe makes keys for (COSE ids, RFC 9053).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    /// ECDSA with P-256 and SHA-256: COSE -7.
    Es256,
    /// Ed25519: COSE -8.
    EdDsa,
}

impl Alg {
    pub fn cose(self) -> i64 {
        match self {
            Alg::Es256 => -7,
            Alg::EdDsa => -8,
        }
    }

    pub fn from_cose(id: i64) -> Option<Alg> {
        match id {
            -7 => Some(Alg::Es256),
            -8 => Some(Alg::EdDsa),
            _ => None,
        }
    }
}

/// The first algorithm in the site's list (its order) that Safe makes. An
/// empty list means WebAuthn's default: ES256, then RS256.
pub fn choose(site: &[i64]) -> Option<Alg> {
    if site.is_empty() {
        return Some(Alg::Es256);
    }
    site.iter().find_map(|id| Alg::from_cose(*id))
}

/// base64url without padding, as WebAuthn and KeePassXC write bytes.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url or standard base64, with or without padding (another app may
/// have written either).
pub fn from_b64(text: &str) -> Option<Vec<u8>> {
    let t: String = text
        .trim()
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(t).ok()
}

/// An id in the one form Safe compares and answers: base64url, no padding.
/// Text that isn't base64 stays as it is.
pub fn normalize_id(text: &str) -> String {
    match from_b64(text) {
        Some(b) if !b.is_empty() => b64url(&b),
        _ => text.trim().to_string(),
    }
}

/// A syntactically valid host name for an RP ID: lowercase ASCII labels
/// (punycode for the others), no trailing dot, not an IP address. Whether
/// the page may use it is the browser's check.
pub fn valid_rp_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 253 {
        return false;
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    };
    let labels: Vec<&str> = id.split('.').collect();
    labels.iter().all(|l| label_ok(l))
        && !labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

// ── keys ────────────────────────────────────────────────────────────────

/// A new credential key.
pub struct Key {
    pub alg: Alg,
    /// The private key, PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).
    pub pem: Zeroizing<String>,
    /// The public key as a COSE_Key (CBOR), for the attested credential data.
    pub cose: Vec<u8>,
    /// The public key as SubjectPublicKeyInfo DER.
    pub spki: Vec<u8>,
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, PasskeyError> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom::fill(b.as_mut()).map_err(|e| PasskeyError::Key(format!("no randomness: {e}")))?;
    Ok(b)
}

/// A new credential id ([`CREDENTIAL_ID_LEN`] random bytes).
pub fn new_credential_id() -> Result<Vec<u8>, PasskeyError> {
    Ok(random::<CREDENTIAL_ID_LEN>()?.to_vec())
}

impl Key {
    pub fn generate(alg: Alg) -> Result<Key, PasskeyError> {
        match alg {
            Alg::Es256 => {
                // a random 32-byte string is a valid scalar but for odds of
                // about 2^-32; draw again then
                let secret = loop {
                    if let Ok(k) = p256::SecretKey::from_slice(random::<32>()?.as_ref()) {
                        break k;
                    }
                };
                Key::es256(&secret)
            }
            Alg::EdDsa => {
                let seed = random::<32>()?;
                Key::ed25519(&ed25519_dalek::SigningKey::from_bytes(&seed))
            }
        }
    }

    fn es256(secret: &p256::SecretKey) -> Result<Key, PasskeyError> {
        let bad = |e: &dyn std::fmt::Display| PasskeyError::Key(format!("P-256 key: {e}"));
        let pem = secret.to_pkcs8_pem(LineEnding::LF).map_err(|e| bad(&e))?;
        let public = secret.public_key();
        let spki = public.to_public_key_der().map_err(|e| bad(&e))?;
        Ok(Key {
            alg: Alg::Es256,
            pem,
            cose: cose_of(&public),
            spki: spki.as_bytes().to_vec(),
        })
    }

    fn ed25519(signing: &ed25519_dalek::SigningKey) -> Result<Key, PasskeyError> {
        let bad = |e: &dyn std::fmt::Display| PasskeyError::Key(format!("Ed25519 key: {e}"));
        // PKCS#8 v1 (the 32-byte seed only), as KeePassXC (Botan) and
        // OpenSSL write it; ed25519-dalek's own encoding adds the public key
        let pem = ed25519_dalek::pkcs8::KeypairBytes {
            secret_key: signing.to_bytes(),
            public_key: None,
        }
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| bad(&e))?;
        let public = signing.verifying_key();
        let spki = public.to_public_key_der().map_err(|e| bad(&e))?;
        let mut cose = Vec::new();
        map(&mut cose, 4);
        int(&mut cose, 1); // kty
        int(&mut cose, 1); // OKP
        int(&mut cose, 3); // alg
        int(&mut cose, Alg::EdDsa.cose());
        int(&mut cose, -1); // crv
        int(&mut cose, 6); // Ed25519
        int(&mut cose, -2); // x
        bytes(&mut cose, &public.to_bytes());
        Ok(Key {
            alg: Alg::EdDsa,
            pem,
            cose,
            spki: spki.as_bytes().to_vec(),
        })
    }
}

/// An EC2 COSE_Key, keys in CTAP2's canonical order (1, 3, -1, -2, -3), as
/// KeePassXC writes it.
fn cose_of(public: &p256::PublicKey) -> Vec<u8> {
    let point = public.to_sec1_point(false);
    let raw = point.as_bytes(); // 0x04 | x | y
    let mut out = Vec::new();
    map(&mut out, 5);
    int(&mut out, 1); // kty
    int(&mut out, 2); // EC2
    int(&mut out, 3); // alg
    int(&mut out, Alg::Es256.cose());
    int(&mut out, -1); // crv
    int(&mut out, 1); // P-256
    int(&mut out, -2); // x
    bytes(&mut out, &raw[1..33]);
    int(&mut out, -3); // y
    bytes(&mut out, &raw[33..65]);
    out
}

/// The DER inside a PEM. Lenient on line breaks: KeePassXC reads a key
/// with none, so another app may write one that way.
fn pem_der(pem: &str) -> Result<Zeroizing<Vec<u8>>, PasskeyError> {
    let body = pem
        .split_once(PEM_BEGIN)
        .and_then(|(_, rest)| rest.split_once(PEM_END))
        .map(|(body, _)| body)
        .ok_or_else(|| PasskeyError::Key("the passkey's key isn't a PKCS#8 PEM".into()))?;
    let b64: Zeroizing<String> =
        Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
    STANDARD
        .decode(b64.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| PasskeyError::Key("the passkey's key isn't valid base64".into()))
}

enum Signing {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

fn signing_key(pem: &str) -> Result<Signing, PasskeyError> {
    let der = pem_der(pem)?;
    let info = p256::pkcs8::PrivateKeyInfoRef::from_der(&der)
        .map_err(|e| PasskeyError::Key(format!("the passkey's key can't be read: {e}")))?;
    let oid = info.algorithm.oid.as_bytes();
    if oid == OID_EC_PUBLIC_KEY {
        let secret = p256::SecretKey::from_pkcs8_der(&der).map_err(|e| {
            PasskeyError::Unsupported(format!("Safe signs only with P-256 EC keys ({e})"))
        })?;
        Ok(Signing::Es256(p256::ecdsa::SigningKey::from(&secret)))
    } else if oid == OID_ED25519 {
        let kp = ed25519_dalek::pkcs8::KeypairBytes::try_from(info)
            .map_err(|e| PasskeyError::Key(format!("the Ed25519 key can't be read: {e}")))?;
        let key = ed25519_dalek::SigningKey::try_from(&kp)
            .map_err(|e| PasskeyError::Key(format!("the Ed25519 key can't be read: {e}")))?;
        Ok(Signing::EdDsa(key))
    } else if oid == OID_RSA {
        Err(PasskeyError::Unsupported(
            "This passkey uses RSA, which Safe can't sign with yet".into(),
        ))
    } else {
        Err(PasskeyError::Unsupported(
            "This passkey's key type isn't one Safe knows".into(),
        ))
    }
}

/// The public key of a stored passkey, as SPKI DER (for checks and tests).
pub fn public_spki(pem: &str) -> Result<(Alg, Vec<u8>), PasskeyError> {
    let bad = |e: &dyn std::fmt::Display| PasskeyError::Key(format!("public key: {e}"));
    match signing_key(pem)? {
        Signing::Es256(k) => Ok((
            Alg::Es256,
            k.verifying_key()
                .to_public_key_der()
                .map_err(|e| bad(&e))?
                .as_bytes()
                .to_vec(),
        )),
        Signing::EdDsa(k) => Ok((
            Alg::EdDsa,
            k.verifying_key()
                .to_public_key_der()
                .map_err(|e| bad(&e))?
                .as_bytes()
                .to_vec(),
        )),
    }
}

/// The assertion signature over `authenticatorData || clientDataHash`:
/// DER (ECDSA, deterministic per RFC 6979, as Botan signs for KeePassXC)
/// or the 64 raw bytes (Ed25519).
pub fn sign(
    pem: &str,
    auth_data: &[u8],
    client_data_hash: &[u8],
) -> Result<(Alg, Vec<u8>), PasskeyError> {
    let mut msg = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    msg.extend_from_slice(auth_data);
    msg.extend_from_slice(client_data_hash);
    match signing_key(pem)? {
        Signing::Es256(k) => {
            use p256::ecdsa::signature::Signer as _;
            let sig: p256::ecdsa::Signature = k.sign(&msg);
            Ok((Alg::Es256, sig.to_der().as_bytes().to_vec()))
        }
        Signing::EdDsa(k) => {
            use ed25519_dalek::Signer as _;
            Ok((Alg::EdDsa, k.sign(&msg).to_bytes().to_vec()))
        }
    }
}

// ── authenticator data ──────────────────────────────────────────────────

/// The flags an answer carries (WebAuthn §6.1). AT is set by
/// [`attested_data`] itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// User present: always, the user clicked.
    pub up: bool,
    /// User verified: the browser says so (Safe unlocked + a click).
    pub uv: bool,
    /// Backup eligible.
    pub be: bool,
    /// Backed up: the passkey lives in the synced file.
    pub bs: bool,
}

impl Flags {
    fn byte(self, at: bool) -> u8 {
        let mut b = 0u8;
        if self.up {
            b |= 0x01;
        }
        if self.uv {
            b |= 0x04;
        }
        if self.be {
            b |= 0x08;
        }
        if self.bs {
            b |= 0x10;
        }
        if at {
            b |= 0x40;
        }
        b
    }
}

pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// `get`'s authenticator data: rpIdHash | flags | signCount (always 0:
/// a synced passkey can't keep a counter).
pub fn assertion_data(rp_id: &str, flags: Flags) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags.byte(false));
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// `create`'s authenticator data: the same, with AT and the attested
/// credential data (AAGUID | id length | id | COSE public key).
pub fn attested_data(
    rp_id: &str,
    flags: Flags,
    aaguid: &[u8; 16],
    credential_id: &[u8],
    cose: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(55 + credential_id.len() + cose.len());
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags.byte(true));
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(aaguid);
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(cose);
    out
}

/// `{"fmt": "none", "attStmt": {}, "authData": …}` in CBOR, keys in
/// CTAP2's canonical order (KeePassXC's order too).
pub fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len() + 32);
    map(&mut out, 3);
    text(&mut out, "fmt");
    text(&mut out, "none");
    text(&mut out, "attStmt");
    map(&mut out, 0);
    text(&mut out, "authData");
    bytes(&mut out, auth_data);
    out
}

// The little CBOR (RFC 8949) WebAuthn needs: definite lengths only.

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

fn int(out: &mut Vec<u8>, i: i64) {
    if i >= 0 {
        head(out, 0, i as u64);
    } else {
        head(out, 1, (-1 - i) as u64);
    }
}

fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn text(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn map(out: &mut Vec<u8>, pairs: u64) {
    head(out, 5, pairs);
}

// ── the entry ───────────────────────────────────────────────────────────

/// What a list may show of a passkey: never the key or the user handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub rp_id: String,
    /// The site's `user.name` (the entry's own username is separate).
    pub username: String,
    /// base64url, no padding.
    pub credential_id: String,
    /// The entry's last use (its `LastAccessTime`), for ordering.
    pub used: Option<NaiveDateTime>,
}

/// A passkey to put on an entry.
pub struct New {
    pub rp_id: String,
    pub username: String,
    /// base64url, no padding.
    pub credential_id: String,
    pub pem: Zeroizing<String>,
    /// base64url, no padding.
    pub user_handle: String,
}

/// What signing needs, read from the entry.
pub struct Secret {
    pub rp_id: String,
    pub pem: Zeroizing<String>,
    /// base64url, no padding (as stored when it isn't base64).
    pub user_handle: String,
    pub credential_id: String,
    pub be: bool,
    pub bs: bool,
}

fn field<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
    entry.get(name).map(str::trim).filter(|v| !v.is_empty())
}

/// KeePassXC's choice: Strongbox's id when it is there.
fn credential_id_of(entry: &Entry) -> Option<&str> {
    field(entry, GENERATED_USER_ID).or_else(|| field(entry, CREDENTIAL_ID))
}

/// "1" or "true" (KeePassXC reads both); absent = set, as KeePassXC defaults.
fn flag(entry: &Entry, name: &str) -> bool {
    match field(entry, name) {
        None => true,
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
    }
}

/// The entry's passkey, if it has one Safe can use: a relying party, a
/// credential id and a key.
pub fn info_of(entry: &Entry) -> Option<Info> {
    let rp_id = field(entry, RELYING_PARTY)?;
    let credential_id = credential_id_of(entry)?;
    field(entry, PRIVATE_KEY_PEM)?;
    Some(Info {
        rp_id: rp_id.to_string(),
        username: field(entry, KPXC_USERNAME)
            .or_else(|| field(entry, USERNAME))
            .unwrap_or_default()
            .to_string(),
        credential_id: normalize_id(credential_id),
        used: entry.times.last_access,
    })
}

pub fn secret_of(entry: &Entry) -> Option<Secret> {
    let info = info_of(entry)?;
    Some(Secret {
        rp_id: info.rp_id,
        // as stored, newline and all
        pem: Zeroizing::new(entry.get(PRIVATE_KEY_PEM)?.to_string()),
        user_handle: field(entry, USER_HANDLE)
            .map(normalize_id)
            .unwrap_or_default(),
        credential_id: info.credential_id,
        be: flag(entry, FLAG_BE),
        bs: flag(entry, FLAG_BS),
    })
}

/// Any passkey field, or the tag.
pub fn has_any(entry: &Entry) -> bool {
    entry
        .fields
        .keys()
        .any(|k| k.starts_with(PREFIX) || k == KPXC_USERNAME)
        || entry.tags.iter().any(|t| t == TAG)
}

/// Remove the passkey: every `KPEX_PASSKEY*` field (KeePassXC's rule),
/// Strongbox's username and the tag. Says whether anything went.
pub fn remove(entry: &mut Entry) -> bool {
    let before = (entry.fields.len(), entry.tags.len());
    entry
        .fields
        .retain(|k, _| !(k.starts_with(PREFIX) || k == KPXC_USERNAME));
    entry.tags.retain(|t| t != TAG);
    before != (entry.fields.len(), entry.tags.len())
}

/// Put a passkey on an entry exactly as KeePassXC's `addPasskeyToEntry`
/// does: the five fields (credential id, key and user handle protected),
/// both backup flags "1", the tag. One passkey per entry: an old one goes
/// first, Strongbox's fields with it.
pub fn store(entry: &mut Entry, p: &New) {
    remove(entry);
    entry.set_unprotected(USERNAME, p.username.as_str());
    entry.set_protected(CREDENTIAL_ID, p.credential_id.as_str());
    entry.set_protected(PRIVATE_KEY_PEM, p.pem.as_str());
    entry.set_unprotected(RELYING_PARTY, p.rp_id.as_str());
    entry.set_protected(USER_HANDLE, p.user_handle.as_str());
    entry.set_unprotected(FLAG_BE, "1");
    entry.set_unprotected(FLAG_BS, "1");
    if !entry.tags.iter().any(|t| t == TAG) {
        entry.tags.push(TAG.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;
    use p256::pkcs8::DecodePublicKey as _;

    /// A CBOR reader written apart from the writer above, so the bytes are
    /// checked by something that didn't make them.
    #[derive(Debug, PartialEq)]
    enum Cbor {
        Int(i128),
        Bytes(Vec<u8>),
        Text(String),
        Map(Vec<(Cbor, Cbor)>),
    }

    fn read(b: &[u8], at: &mut usize) -> Cbor {
        let first = b[*at];
        *at += 1;
        let (major, info) = (first >> 5, first & 0x1f);
        let n: u64 = match info {
            0..=23 => info as u64,
            24..=27 => {
                let len = 1usize << (info - 24);
                let mut v = 0u64;
                for _ in 0..len {
                    v = (v << 8) | b[*at] as u64;
                    *at += 1;
                }
                v
            }
            _ => panic!("indefinite or reserved length"),
        };
        match major {
            0 => Cbor::Int(n as i128),
            1 => Cbor::Int(-1 - n as i128),
            2 | 3 => {
                let s = b[*at..*at + n as usize].to_vec();
                *at += n as usize;
                if major == 2 {
                    Cbor::Bytes(s)
                } else {
                    Cbor::Text(String::from_utf8(s).expect("utf-8"))
                }
            }
            5 => Cbor::Map(
                (0..n)
                    .map(|_| {
                        let k = read(b, at);
                        (k, read(b, at))
                    })
                    .collect(),
            ),
            m => panic!("major type {m} not expected here"),
        }
    }

    fn whole(b: &[u8]) -> Cbor {
        let mut at = 0;
        let v = read(b, &mut at);
        assert_eq!(at, b.len(), "nothing after the item");
        v
    }

    fn get<'a>(m: &'a Cbor, key: &Cbor) -> &'a Cbor {
        match m {
            Cbor::Map(pairs) => &pairs.iter().find(|(k, _)| k == key).expect("key").1,
            _ => panic!("not a map"),
        }
    }

    fn keys(m: &Cbor) -> Vec<&Cbor> {
        match m {
            Cbor::Map(pairs) => pairs.iter().map(|(k, _)| k).collect(),
            _ => panic!("not a map"),
        }
    }

    fn verify(alg: Alg, spki: &[u8], msg: &[u8], sig: &[u8]) {
        match alg {
            Alg::Es256 => {
                use p256::ecdsa::signature::Verifier as _;
                let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki).expect("spki");
                let s = p256::ecdsa::Signature::from_der(sig).expect("DER signature");
                vk.verify(msg, &s).expect("ES256 signature verifies");
            }
            Alg::EdDsa => {
                use ed25519_dalek::Verifier as _;
                let vk = ed25519_dalek::VerifyingKey::from_public_key_der(spki).expect("spki");
                let s = ed25519_dalek::Signature::from_slice(sig).expect("64 bytes");
                vk.verify(msg, &s).expect("EdDSA signature verifies");
            }
        }
    }

    #[test]
    fn the_site_order_picks_the_algorithm() {
        assert_eq!(choose(&[-257, -8, -7]), Some(Alg::EdDsa));
        assert_eq!(choose(&[-7, -8]), Some(Alg::Es256));
        assert_eq!(choose(&[]), Some(Alg::Es256), "WebAuthn's default");
        assert_eq!(choose(&[-257, -35]), None);
    }

    #[test]
    fn rp_ids() {
        for ok in [
            "github.com",
            "login.example.co.uk",
            "localhost",
            "xn--e1afmkfd.xn--p1ai",
            "a-b.example",
        ] {
            assert!(valid_rp_id(ok), "{ok}");
        }
        for bad in [
            "",
            "GitHub.com",
            "example.com.",
            ".example.com",
            "exa mple.com",
            "127.0.0.1",
            "[::1]",
            "-a.example",
            "a..example",
            "https://github.com",
            "github.com:443",
        ] {
            assert!(!valid_rp_id(bad), "{bad}");
        }
    }

    #[test]
    fn ids_compare_in_one_form() {
        let raw = [0xfbu8, 0xff, 0x01, 0x02];
        assert_eq!(b64url(&raw), "-_8BAg");
        for written in ["-_8BAg", "+/8BAg==", "-_8BAg=="] {
            assert_eq!(normalize_id(written), "-_8BAg");
            assert_eq!(from_b64(written).expect("decodes"), raw);
        }
        assert_eq!(normalize_id(" not base64! "), "not base64!");
    }

    #[test]
    fn es256_creates_signs_and_verifies() {
        let key = Key::generate(Alg::Es256).expect("key");
        assert!(key.pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(key.pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
        // the PKCS#8 shape KeePassXC (Botan) writes: v0, id-ecPublicKey with
        // the P-256 curve, an ECPrivateKey holding the public point
        assert!(pem_der(&key.pem).unwrap().starts_with(&[
            0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
        ]));
        assert_eq!(
            public_spki(&key.pem).unwrap(),
            (Alg::Es256, key.spki.clone())
        );

        // the COSE key: canonical order, and the same point as the SPKI
        let cose = whole(&key.cose);
        assert_eq!(
            keys(&cose),
            [
                &Cbor::Int(1),
                &Cbor::Int(3),
                &Cbor::Int(-1),
                &Cbor::Int(-2),
                &Cbor::Int(-3)
            ]
        );
        assert_eq!(get(&cose, &Cbor::Int(1)), &Cbor::Int(2));
        assert_eq!(get(&cose, &Cbor::Int(3)), &Cbor::Int(-7));
        assert_eq!(get(&cose, &Cbor::Int(-1)), &Cbor::Int(1));
        let (Cbor::Bytes(x), Cbor::Bytes(y)) =
            (get(&cose, &Cbor::Int(-2)), get(&cose, &Cbor::Int(-3)))
        else {
            panic!("x and y are bytes");
        };
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&key.spki).expect("spki");
        let point = vk.to_sec1_point(false);
        assert_eq!(
            (&point.as_bytes()[1..33], &point.as_bytes()[33..]),
            (&x[..], &y[..])
        );

        let data = assertion_data(
            "github.com",
            Flags {
                up: true,
                uv: true,
                be: true,
                bs: true,
            },
        );
        let hash = Sha256::digest(b"{\"type\":\"webauthn.get\"}");
        let (alg, sig) = sign(&key.pem, &data, &hash).expect("sign");
        assert_eq!(alg, Alg::Es256);
        let mut msg = data.clone();
        msg.extend_from_slice(&hash);
        verify(alg, &key.spki, &msg, &sig);
        // deterministic (RFC 6979), as Botan signs for KeePassXC
        assert_eq!(sign(&key.pem, &data, &hash).unwrap().1, sig);
    }

    #[test]
    fn eddsa_creates_signs_and_verifies() {
        let key = Key::generate(Alg::EdDsa).expect("key");
        // PKCS#8 v1, 48 bytes, as OpenSSL and Botan write an Ed25519 key
        let der = pem_der(&key.pem).unwrap();
        assert_eq!(der.len(), 48);
        assert_eq!(
            &der[..16],
            &[
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20
            ]
        );
        let cose = whole(&key.cose);
        assert_eq!(get(&cose, &Cbor::Int(1)), &Cbor::Int(1));
        assert_eq!(get(&cose, &Cbor::Int(3)), &Cbor::Int(-8));
        assert_eq!(get(&cose, &Cbor::Int(-1)), &Cbor::Int(6));
        let Cbor::Bytes(x) = get(&cose, &Cbor::Int(-2)) else {
            panic!("x is bytes");
        };
        assert_eq!(&key.spki[key.spki.len() - 32..], &x[..]);

        let data = assertion_data(
            "example.org",
            Flags {
                up: true,
                ..Flags::default()
            },
        );
        let hash = [7u8; 32];
        let (alg, sig) = sign(&key.pem, &data, &hash).expect("sign");
        assert_eq!((alg, sig.len()), (Alg::EdDsa, 64));
        let mut msg = data.clone();
        msg.extend_from_slice(&hash);
        verify(alg, &key.spki, &msg, &sig);
    }

    #[test]
    fn a_pem_without_line_breaks_still_signs() {
        // KeePassXC's own tests store keys this way; Botan reads them
        let key = Key::generate(Alg::Es256).expect("key");
        let flat: String = key.pem.lines().collect();
        let (_, sig) = sign(&flat, b"data", &[0; 32]).expect("sign");
        let mut msg = b"data".to_vec();
        msg.extend_from_slice(&[0; 32]);
        verify(Alg::Es256, &key.spki, &msg, &sig);
    }

    #[test]
    fn rsa_and_garbage_are_refused_clearly() {
        // a PKCS#8 header with the rsaEncryption OID (the key itself is
        // never reached)
        let mut der = vec![0x30, 0x16, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09];
        der.extend_from_slice(OID_RSA);
        der.extend_from_slice(&[0x05, 0x00, 0x04, 0x02, 0x30, 0x00]);
        let pem = format!("{PEM_BEGIN}\n{}\n{PEM_END}\n", STANDARD.encode(&der));
        assert!(matches!(
            sign(&pem, b"x", &[0; 32]),
            Err(PasskeyError::Unsupported(_))
        ));
        assert!(matches!(
            sign("pem", b"x", &[0; 32]),
            Err(PasskeyError::Key(_))
        ));
    }

    #[test]
    fn the_attestation_object_is_none_with_the_credential() {
        let key = Key::generate(Alg::Es256).expect("key");
        let id = new_credential_id().expect("id");
        let flags = Flags {
            up: true,
            uv: true,
            be: true,
            bs: true,
        };
        let auth = attested_data("webauthn.io", flags, &AAGUID, &id, &key.cose);
        let att = whole(&attestation_object(&auth));
        assert_eq!(
            keys(&att),
            [
                &Cbor::Text("fmt".into()),
                &Cbor::Text("attStmt".into()),
                &Cbor::Text("authData".into())
            ]
        );
        assert_eq!(
            get(&att, &Cbor::Text("fmt".into())),
            &Cbor::Text("none".into())
        );
        assert_eq!(get(&att, &Cbor::Text("attStmt".into())), &Cbor::Map(vec![]));
        let Cbor::Bytes(a) = get(&att, &Cbor::Text("authData".into())) else {
            panic!("authData is bytes");
        };
        // the layout, read by offset as an RP reads it
        assert_eq!(&a[..32], &Sha256::digest(b"webauthn.io")[..]);
        assert_eq!(a[32], 0x5d, "UP UV BE BS AT, as KeePassXC sets them");
        assert_eq!(&a[33..37], &[0, 0, 0, 0], "sign count 0");
        assert_eq!(&a[37..53], &AAGUID);
        assert_eq!(
            u16::from_be_bytes([a[53], a[54]]) as usize,
            CREDENTIAL_ID_LEN
        );
        assert_eq!(&a[55..87], &id[..]);
        assert_eq!(
            whole(&a[87..]),
            whole(&key.cose),
            "the COSE key ends the data"
        );

        let get_flags = assertion_data(
            "webauthn.io",
            Flags {
                up: true,
                uv: false,
                be: true,
                bs: true,
            },
        );
        assert_eq!(
            (get_flags.len(), get_flags[32]),
            (37, 0x19),
            "UP BE BS, no AT"
        );
    }

    #[test]
    fn cbor_lengths() {
        for n in [0u64, 23, 24, 255, 256, 65535, 65536, 1 << 40] {
            let mut out = Vec::new();
            head(&mut out, 0, n);
            assert_eq!(whole(&out), Cbor::Int(n as i128), "{n}");
        }
        let mut out = Vec::new();
        int(&mut out, -257);
        assert_eq!(out, [0x39, 0x01, 0x00]);
    }

    #[test]
    fn the_fields_keepassxc_writes() {
        let mut db = Database::new();
        let id = db.root_mut().add_entry().id();
        let mut e = db.entry_mut(id).expect("entry");
        // leftovers of a Strongbox passkey go with the old one
        e.set_protected(GENERATED_USER_ID, "old");
        e.set_unprotected(KPXC_USERNAME, "old-user");
        e.set_unprotected("KPEX_PASSKEY_PRF", "x");
        e.tags = vec!["work".into()];
        let key = Key::generate(Alg::Es256).expect("key");
        store(
            &mut e,
            &New {
                rp_id: "github.com".into(),
                username: "sam".into(),
                credential_id: "Y3JlZA".into(),
                pem: key.pem.clone(),
                user_handle: "dXNlcg".into(),
            },
        );
        let protected = |k: &str| e.fields[k].is_protected();
        assert!(protected(CREDENTIAL_ID) && protected(PRIVATE_KEY_PEM) && protected(USER_HANDLE));
        assert!(!protected(USERNAME) && !protected(RELYING_PARTY));
        assert_eq!((e.get(FLAG_BE), e.get(FLAG_BS)), (Some("1"), Some("1")));
        assert!(e.get(GENERATED_USER_ID).is_none() && e.get(KPXC_USERNAME).is_none());
        assert!(e.get("KPEX_PASSKEY_PRF").is_none());
        assert_eq!(e.tags, ["work", "Passkey"]);
        assert_eq!(
            info_of(&e).map(|i| (i.rp_id, i.username, i.credential_id)),
            Some(("github.com".into(), "sam".into(), "Y3JlZA".into()))
        );
        let s = secret_of(&e).expect("secret");
        assert_eq!((s.user_handle.as_str(), s.be, s.bs), ("dXNlcg", true, true));
        assert!(format!("{:?}", info_of(&e)).find("PRIVATE").is_none());

        // Strongbox's names win when present, as KeePassXC reads them
        e.set_protected(GENERATED_USER_ID, "c2I=");
        e.set_unprotected(KPXC_USERNAME, "sam@phone");
        e.set_unprotected(FLAG_BS, "false");
        let i = info_of(&e).expect("info");
        assert_eq!(
            (i.credential_id.as_str(), i.username.as_str()),
            ("c2I", "sam@phone")
        );
        assert!(!secret_of(&e).expect("secret").bs);

        assert!(remove(&mut e));
        assert!(!has_any(&e) && info_of(&e).is_none());
        assert_eq!(e.tags, ["work"]);
        assert!(!remove(&mut e), "nothing left to remove");
    }
}
