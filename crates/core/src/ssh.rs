//! SSH keys in the safe (docs/FORMAT.md, "SSH keys"; TRIO.md S2). An SSH
//! key is a **KeeAgent** entry, the way KeePassXC's SSH agent support reads
//! one (`src/sshagent/KeeAgentSettings.cpp`), so the file stays portable:
//!
//! | what | where |
//! |---|---|
//! | the private key, OpenSSH format | an attachment named as ssh-keygen names the file (`id_ed25519`) |
//! | which attachment, and whether an agent may use it | the attachment `KeeAgent.settings` (XML, [`KeeAgent`]) |
//! | the key's passphrase, if it has one | the entry's password |
//! | the public key and its fingerprint | unprotected fields `public_key` and `fingerprint`, so a list never opens the key |
//! | kind SSH key | custom data `ewe.kind = ssh-key`; an entry another app made is one when it has `KeeAgent.settings` |
//!
//! Keys are read in OpenSSH form or as PEM (PKCS#8, which 1Password
//! exports; PKCS#1; SEC1) and always stored as OpenSSH: KeePassXC reads no
//! PKCS#8. [`sign`] is what the daemon's agent does with them.

use std::fmt;

use keepass::db::{EntryId, EntryRef, Value, fields};
use ssh_key::encoding::Encode as _;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::item::{self, Draft, Kind, Summary};
use crate::safe::{Error, Safe};

/// The attachment KeeAgent and KeePassXC read the settings from.
pub const SETTINGS: &str = "KeeAgent.settings";
pub const PUBLIC_KEY: &str = "public_key";
pub const FINGERPRINT: &str = "fingerprint";
/// The name `reveal` knows the private key by (it is an attachment).
pub const PRIVATE_KEY: &str = "private_key";
/// The ssh-agent flags that pick RSA's hash (draft-miller-ssh-agent, 4.5.1).
pub const RSA_SHA2_256: u32 = 0x02;
pub const RSA_SHA2_512: u32 = 0x04;
/// A private key file bigger than this isn't one (KeePassXC's limit too).
pub const MAX_KEY_FILE: u64 = 1024 * 1024;

/// Why a key can't be read, made or used: a sentence for the user, never a
/// value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshError(pub String);

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SshError {}

fn err(message: impl Into<String>) -> SshError {
    SshError(message.into())
}

// ── KeeAgent.settings ───────────────────────────────────────────────────

/// KeeAgent's per-entry settings, field for field as KeePassXC keeps them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeeAgent {
    /// `AllowUseOfSshKey`: an agent may use the key. Safe's agent lists
    /// only these.
    pub allow_use: bool,
    /// `AddAtDatabaseOpen`: KeePassXC adds the key to the running agent
    /// when the file is unlocked.
    pub add_at_open: bool,
    /// `RemoveAtDatabaseClose`: and takes it out again when it locks.
    pub remove_at_close: bool,
    pub confirm: bool,
    pub lifetime: bool,
    pub lifetime_seconds: i64,
    /// `SelectedType`: `attachment` or `file` (a path on one computer).
    pub selected_type: String,
    pub attachment_name: String,
    pub save_to_temp_file: bool,
    pub file_name: String,
}

impl Default for KeeAgent {
    /// KeePassXC's `KeeAgentSettings::reset()`.
    fn default() -> KeeAgent {
        KeeAgent {
            allow_use: false,
            add_at_open: false,
            remove_at_close: false,
            confirm: false,
            lifetime: false,
            lifetime_seconds: 600,
            selected_type: "file".to_string(),
            attachment_name: String::new(),
            save_to_temp_file: false,
            file_name: String::new(),
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl KeeAgent {
    /// What Safe writes for a key it stores: the attachment, and the three
    /// switches on. KeePassXC's editor recomputes `AllowUseOfSshKey` as
    /// "add at open or remove at close" on every save, so with those off a
    /// KeePassXC edit would take the key out of every agent.
    pub fn for_attachment(name: &str) -> KeeAgent {
        KeeAgent {
            allow_use: true,
            add_at_open: true,
            remove_at_close: true,
            selected_type: "attachment".to_string(),
            attachment_name: name.to_string(),
            ..KeeAgent::default()
        }
    }

    /// The key is in the entry, and an agent may use it.
    pub fn usable(&self) -> bool {
        self.allow_use && self.selected_type == "attachment" && !self.attachment_name.is_empty()
    }

    /// The XML byte for byte as KeePassXC's `toXml()` writes it
    /// (QXmlStreamWriter, indent 2).
    pub fn to_xml(&self) -> Vec<u8> {
        let b = |v: bool| if v { "true" } else { "false" };
        let el = |indent: &str, name: &str, text: &str| {
            if text.is_empty() {
                format!("{indent}<{name}/>\n")
            } else {
                format!("{indent}<{name}>{}</{name}>\n", escape(text))
            }
        };
        let mut x = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        x.push_str(
            "<EntrySettings xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" \
             xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n",
        );
        x.push_str(&el("  ", "AllowUseOfSshKey", b(self.allow_use)));
        x.push_str(&el("  ", "AddAtDatabaseOpen", b(self.add_at_open)));
        x.push_str(&el("  ", "RemoveAtDatabaseClose", b(self.remove_at_close)));
        x.push_str(&el("  ", "UseConfirmConstraintWhenAdding", b(self.confirm)));
        x.push_str(&el(
            "  ",
            "UseLifetimeConstraintWhenAdding",
            b(self.lifetime),
        ));
        x.push_str(&el(
            "  ",
            "LifetimeConstraintDuration",
            &self.lifetime_seconds.to_string(),
        ));
        x.push_str("  <Location>\n");
        x.push_str(&el("    ", "SelectedType", &self.selected_type));
        x.push_str(&el("    ", "AttachmentName", &self.attachment_name));
        x.push_str(&el(
            "    ",
            "SaveAttachmentToTempFile",
            b(self.save_to_temp_file),
        ));
        x.push_str(&el("    ", "FileName", &self.file_name));
        x.push_str("  </Location>\n</EntrySettings>\n");
        x.into_bytes()
    }

    /// Read the settings as KeePassXC does: the root must be
    /// `EntrySettings`; unknown elements are skipped; a boolean is true when
    /// its text starts with `t`. UTF-8 (a byte-order mark is fine) or UTF-16
    /// with its mark (KeeAgent on Windows). None when it isn't settings.
    pub fn from_xml(bytes: &[u8]) -> Option<KeeAgent> {
        use quick_xml::Reader;
        use quick_xml::events::Event;

        let text = decode_text(bytes)?;
        let mut reader = Reader::from_str(&text);
        let mut s = KeeAgent::default();
        let mut stack: Vec<String> = Vec::new();
        let mut value = String::new();
        let mut rooted = false;
        loop {
            match reader.read_event() {
                Ok(Event::Start(e)) => {
                    let name = e.local_name().into_inner().to_string();
                    if stack.is_empty() {
                        if name != "EntrySettings" {
                            return None;
                        }
                        rooted = true;
                    }
                    stack.push(name);
                    value.clear();
                }
                Ok(Event::Empty(e)) => {
                    if stack.is_empty() {
                        return (e.local_name().into_inner() == "EntrySettings")
                            .then(KeeAgent::default);
                    }
                    let name = e.local_name().into_inner().to_string();
                    s.set(&stack, &name, "");
                }
                Ok(Event::Text(t)) => value.push_str(t.as_ref()),
                Ok(Event::CData(t)) => {
                    let c: &str = t.as_ref();
                    value.push_str(c);
                }
                Ok(Event::GeneralRef(r)) => {
                    let named = match r.as_ref() {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        _ => None,
                    };
                    if let Some(c) = named.or_else(|| r.resolve_char_ref().ok().flatten()) {
                        value.push(c);
                    }
                }
                Ok(Event::End(_)) => {
                    let name = stack.pop()?;
                    let v = std::mem::take(&mut value);
                    s.set(&stack, &name, v.trim());
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(_) => return None,
            }
        }
        rooted.then_some(s)
    }

    /// One element's text, `name` inside `parents`.
    fn set(&mut self, parents: &[String], name: &str, v: &str) {
        let flag = || v.get(..1).is_some_and(|c| c.eq_ignore_ascii_case("t"));
        let path: Vec<&str> = parents.iter().map(String::as_str).collect();
        match (path.as_slice(), name) {
            (["EntrySettings"], "AllowUseOfSshKey") => self.allow_use = flag(),
            (["EntrySettings"], "AddAtDatabaseOpen") => self.add_at_open = flag(),
            (["EntrySettings"], "RemoveAtDatabaseClose") => self.remove_at_close = flag(),
            (["EntrySettings"], "UseConfirmConstraintWhenAdding") => self.confirm = flag(),
            (["EntrySettings"], "UseLifetimeConstraintWhenAdding") => self.lifetime = flag(),
            (["EntrySettings"], "LifetimeConstraintDuration") => {
                self.lifetime_seconds = v.parse().unwrap_or(0)
            }
            (["EntrySettings", "Location"], "SelectedType") => self.selected_type = v.to_string(),
            (["EntrySettings", "Location"], "AttachmentName") => {
                self.attachment_name = v.to_string()
            }
            (["EntrySettings", "Location"], "SaveAttachmentToTempFile") => {
                self.save_to_temp_file = flag()
            }
            (["EntrySettings", "Location"], "FileName") => self.file_name = v.to_string(),
            _ => {}
        }
    }
}

/// UTF-8 (with or without its mark) or UTF-16 with its mark.
fn decode_text(bytes: &[u8]) -> Option<String> {
    let utf16 = |b: &[u8], le: bool| -> Option<String> {
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if le {
                    u16::from_le_bytes(*c)
                } else {
                    u16::from_be_bytes(*c)
                }
            })
            .collect();
        String::from_utf16(&units).ok()
    };
    let text = match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8(rest.to_vec()).ok()?,
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true)?,
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false)?,
        _ => String::from_utf8(bytes.to_vec()).ok()?,
    };
    // the declaration may still say utf-16: the text is decoded already
    Some(match text.find("?>") {
        Some(end) if text.trim_start().starts_with("<?xml") => text[end + 2..].to_string(),
        _ => text,
    })
}

// ── keys ────────────────────────────────────────────────────────────────

/// A private key ready to be stored: the attachment's text and what a list
/// shows of it.
#[derive(Clone)]
pub struct KeyFile {
    /// OpenSSH format; still encrypted when the key has a passphrase.
    pub openssh: Zeroizing<String>,
    /// The OpenSSH public line (`ssh-ed25519 AAAA… comment`).
    pub public_key: String,
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    pub key_type: String,
    /// The attachment's name, the file name ssh-keygen gives such a key.
    pub file_name: String,
    pub encrypted: bool,
    /// The key's own comment ("" when it has none, or it is encrypted).
    pub comment: String,
}

impl fmt::Debug for KeyFile {
    /// Never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile")
            .field("public_key", &self.public_key)
            .field("fingerprint", &self.fingerprint)
            .field("key_type", &self.key_type)
            .field("file_name", &self.file_name)
            .field("encrypted", &self.encrypted)
            .finish_non_exhaustive()
    }
}

/// What a list shows of an SSH key (PROTOCOL.md, the item summary's `ssh`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub public_key: String,
    pub fingerprint: String,
    /// `ed25519`, `ecdsa`, `rsa`, `dsa`, or the algorithm's own name.
    pub key_type: String,
    /// `KeeAgent.settings` lets an agent use it and the key is in the entry.
    pub agent: bool,
}

pub fn key_type(alg: &Algorithm) -> String {
    match alg {
        Algorithm::Ed25519 => "ed25519".to_string(),
        Algorithm::Ecdsa { .. } => "ecdsa".to_string(),
        Algorithm::Rsa { .. } => "rsa".to_string(),
        Algorithm::Dsa => "dsa".to_string(),
        other => other.as_str().to_string(),
    }
}

fn file_name(alg: &Algorithm) -> String {
    match alg {
        Algorithm::Ed25519 => "id_ed25519",
        Algorithm::Ecdsa { .. } => "id_ecdsa",
        Algorithm::Rsa { .. } => "id_rsa",
        Algorithm::Dsa => "id_dsa",
        Algorithm::SkEd25519 => "id_ed25519_sk",
        Algorithm::SkEcdsaSha2NistP256 => "id_ecdsa_sk",
        _ => "id_key",
    }
    .to_string()
}

/// The PEM label of the first block (`OPENSSH PRIVATE KEY`, `PRIVATE KEY`, …).
fn pem_label(text: &str) -> Option<&str> {
    let start = text.find("-----BEGIN ")? + "-----BEGIN ".len();
    let end = text[start..].find("-----")?;
    Some(&text[start..start + end])
}

/// It looks like a private key file Safe may read.
pub fn is_private_key(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(pem_label)
        .is_some_and(|l| l.ends_with("PRIVATE KEY"))
}

/// The key has a passphrase (OpenSSH), or is a PEM file that is encrypted.
pub fn is_encrypted(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    match pem_label(text) {
        Some("OPENSSH PRIVATE KEY") => {
            PrivateKey::from_openssh(text.trim()).is_ok_and(|k| k.is_encrypted())
        }
        Some(l) => l == "ENCRYPTED PRIVATE KEY" || text.contains("Proc-Type: 4,ENCRYPTED"),
        None => false,
    }
}

/// A PEM key (PKCS#8, PKCS#1, SEC1) as an unencrypted OpenSSH key.
fn from_pem(text: &str, label: &str) -> Result<PrivateKey, SshError> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    use rsa::pkcs1::DecodeRsaPrivateKey as _;

    if label == "ENCRYPTED PRIVATE KEY" || text.contains("Proc-Type: 4,ENCRYPTED") {
        return Err(err(
            "This key is an encrypted PEM file, which Safe can't read: make it an OpenSSH key first (ssh-keygen -p -f FILE)",
        ));
    }
    let rsa_pair = |k: rsa::RsaPrivateKey| -> Result<KeypairData, SshError> {
        RsaKeypair::try_from(k)
            .map(KeypairData::from)
            .map_err(|e| err(format!("This RSA key can't be used: {e}")))
    };
    let p256_pair = |k: p256::SecretKey| {
        KeypairData::from(EcdsaKeypair::NistP256 {
            public: k.public_key().into(),
            private: k.into(),
        })
    };
    let p384_pair = |k: p384::SecretKey| {
        KeypairData::from(EcdsaKeypair::NistP384 {
            public: k.public_key().into(),
            private: k.into(),
        })
    };
    let pem = text.trim();
    let data = match label {
        "PRIVATE KEY" => {
            if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
                KeypairData::from(Ed25519Keypair::from(k))
            } else if let Ok(k) = p256::SecretKey::from_pkcs8_pem(pem) {
                p256_pair(k)
            } else if let Ok(k) = p384::SecretKey::from_pkcs8_pem(pem) {
                p384_pair(k)
            } else if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
                rsa_pair(k)?
            } else {
                return Err(err(
                    "This PKCS#8 key is of a kind Safe can't use (Ed25519, ECDSA P-256/P-384 and RSA are)",
                ));
            }
        }
        "RSA PRIVATE KEY" => rsa_pair(
            rsa::RsaPrivateKey::from_pkcs1_pem(pem)
                .map_err(|_| err("This RSA key file can't be read"))?,
        )?,
        "EC PRIVATE KEY" => {
            if let Ok(k) = p256::SecretKey::from_sec1_pem(pem) {
                p256_pair(k)
            } else if let Ok(k) = p384::SecretKey::from_sec1_pem(pem) {
                p384_pair(k)
            } else {
                return Err(err(
                    "This ECDSA key is of a curve Safe can't use (P-256 and P-384 are)",
                ));
            }
        }
        other => {
            return Err(err(format!(
                "A {} file isn't a private key Safe can read",
                other.to_lowercase()
            )));
        }
    };
    PrivateKey::new(data, "").map_err(|e| err(format!("This key can't be used: {e}")))
}

/// Any key file Safe reads, as a key (encrypted ones stay encrypted).
fn parse(text: &str) -> Result<PrivateKey, SshError> {
    let label = pem_label(text).ok_or_else(|| {
        err("This isn't a private key file (an OpenSSH or PEM key, such as ~/.ssh/id_ed25519)")
    })?;
    if label == "OPENSSH PRIVATE KEY" {
        PrivateKey::from_openssh(text.trim())
            .map_err(|e| err(format!("This OpenSSH key can't be read: {e}")))
    } else {
        from_pem(text, label)
    }
}

/// Read a private key file's bytes for storing. An encrypted OpenSSH key is
/// kept as it is (its passphrase goes in the entry's password); `passphrase`
/// is checked against it when given. Any other form becomes an unencrypted
/// OpenSSH key.
pub fn read_key(bytes: &[u8], passphrase: &str) -> Result<KeyFile, SshError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| err("This isn't a private key file: it isn't text"))?;
    let key = parse(text)?;
    let (stored, comment) = if key.is_encrypted() {
        if !passphrase.is_empty() {
            let open = key
                .decrypt(passphrase)
                .map_err(|_| err("That passphrase doesn't open the key"))?;
            (
                Zeroizing::new(text.to_string()),
                open.comment().as_str_lossy().to_string(),
            )
        } else {
            (Zeroizing::new(text.to_string()), String::new())
        }
    } else if pem_label(text) == Some("OPENSSH PRIVATE KEY") {
        (
            Zeroizing::new(text.to_string()),
            key.comment().as_str_lossy().to_string(),
        )
    } else {
        let openssh = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| err(format!("This key can't be written as OpenSSH: {e}")))?;
        (openssh, String::new())
    };
    Ok(describe(&key, stored, comment))
}

fn describe(key: &PrivateKey, openssh: Zeroizing<String>, comment: String) -> KeyFile {
    let mut public: PublicKey = key.public_key().clone();
    public.set_comment(comment.as_str());
    KeyFile {
        openssh,
        public_key: public
            .to_openssh()
            .unwrap_or_default()
            .trim_end()
            .to_string(),
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        key_type: key_type(&key.algorithm()),
        file_name: file_name(&key.algorithm()),
        encrypted: key.is_encrypted(),
        comment,
    }
}

/// A new key: `ed25519` (the default), `ecdsa` (256 or 384 bits) or `rsa`
/// (2048, 3072 or 4096 bits; 3072 as ssh-keygen). `comment` goes in the key.
pub fn generate(kind: &str, bits: Option<u32>, comment: &str) -> Result<KeyFile, SshError> {
    use ssh_key::getrandom::SysRng;
    use ssh_key::rand_core::UnwrapErr;

    let mut rng = UnwrapErr(SysRng);
    let data = match (kind, bits) {
        ("ed25519", None) => KeypairData::from(Ed25519Keypair::random(&mut rng)),
        ("ed25519", Some(_)) => return Err(err("An Ed25519 key has no --bits")),
        ("ecdsa", None | Some(256)) => KeypairData::from(
            EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP256).map_err(|e| err(e.to_string()))?,
        ),
        ("ecdsa", Some(384)) => KeypairData::from(
            EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP384).map_err(|e| err(e.to_string()))?,
        ),
        ("ecdsa", Some(_)) => return Err(err("--bits for an ECDSA key is 256 or 384")),
        ("rsa", b) => {
            let b = b.unwrap_or(3072);
            if ![2048, 3072, 4096].contains(&b) {
                return Err(err("--bits for an RSA key is 2048, 3072 or 4096"));
            }
            KeypairData::from(
                RsaKeypair::random(&mut rng, b as usize).map_err(|e| err(e.to_string()))?,
            )
        }
        _ => return Err(err("--type is ed25519, ecdsa or rsa")),
    };
    let key = PrivateKey::new(data, comment).map_err(|e| err(e.to_string()))?;
    let openssh = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| err(e.to_string()))?;
    Ok(describe(&key, openssh, comment.to_string()))
}

/// The wire form of a public key (what an agent lists and is asked to sign
/// with), from its OpenSSH line.
pub fn public_blob(line: &str) -> Option<Vec<u8>> {
    PublicKey::from_openssh(line.trim()).ok()?.to_bytes().ok()
}

/// An OpenSSH public line, without its comment, from the wire form.
pub fn public_line(blob: &[u8]) -> Option<String> {
    let mut k = PublicKey::from_bytes(blob).ok()?;
    k.set_comment("");
    k.to_openssh().ok().map(|l| l.trim_end().to_string())
}

/// Sign `data` with a stored key (draft-miller-ssh-agent, SIGN_REQUEST):
/// the signature in SSH's wire form (algorithm name, then the signature).
/// RSA signs with SHA-512 or SHA-256 as `flags` ask; plain `ssh-rsa`
/// (SHA-1) is refused.
pub fn sign(
    key_text: &str,
    passphrase: &str,
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>, SshError> {
    use signature::Signer as _;

    let mut key = parse(key_text)?;
    if key.is_encrypted() {
        key = key
            .decrypt(passphrase)
            .map_err(|_| err("The passphrase in the item doesn't open the key"))?;
    }
    let failed = |e: signature::Error| err(format!("The key couldn't sign: {e}"));
    let sig = match key.key_data() {
        KeypairData::Rsa(pair) => {
            let hash = if flags & RSA_SHA2_512 != 0 {
                HashAlg::Sha512
            } else if flags & RSA_SHA2_256 != 0 {
                HashAlg::Sha256
            } else {
                return Err(err(
                    "ssh-rsa (SHA-1) signatures are refused: use rsa-sha2-256 or rsa-sha2-512",
                ));
            };
            (pair, Some(hash)).try_sign(data).map_err(failed)?
        }
        other => other.try_sign(data).map_err(failed)?,
    };
    sig.encode_vec()
        .map_err(|e| err(format!("The signature couldn't be written: {e}")))
}

// ── entries ─────────────────────────────────────────────────────────────

/// The entry's `KeeAgent.settings`, if it has readable ones.
pub fn settings_of(e: &EntryRef<'_>) -> Option<KeeAgent> {
    let a = e.attachment_by_name(SETTINGS)?;
    KeeAgent::from_xml(a.data.get())
}

/// The private key's text, from the attachment the settings name.
fn key_text_of(e: &EntryRef<'_>, s: &KeeAgent) -> Option<Zeroizing<String>> {
    if s.selected_type != "attachment" || s.attachment_name.is_empty() {
        return None;
    }
    let a = e.attachment_by_name(&s.attachment_name)?;
    std::str::from_utf8(a.data.get())
        .ok()
        .map(|t| Zeroizing::new(t.to_string()))
}

/// Make a summary right for an SSH key: an entry another app made is one
/// when it has `KeeAgent.settings`; the `ssh` part comes from the
/// `public_key` and `fingerprint` fields, or from the key's own public part
/// (readable without its passphrase) when the entry has no such fields.
pub fn refine(e: &EntryRef<'_>, s: &mut Summary) {
    let settings = settings_of(e);
    if s.kind == Kind::Login && settings.is_some() {
        s.kind = Kind::SshKey;
    }
    if s.kind != Kind::SshKey {
        return;
    }
    let field = |k: &str| e.get(k).unwrap_or("").trim().to_string();
    let mut info = Info {
        public_key: field(PUBLIC_KEY),
        fingerprint: field(FINGERPRINT),
        key_type: String::new(),
        agent: false,
    };
    let key = settings.as_ref().and_then(|st| key_text_of(e, st));
    if info.public_key.is_empty()
        && let Some(text) = &key
        && let Ok(k) = parse(text)
    {
        info.public_key = k
            .public_key()
            .to_openssh()
            .unwrap_or_default()
            .trim_end()
            .to_string();
        info.fingerprint = k.fingerprint(HashAlg::Sha256).to_string();
    }
    if let Ok(k) = PublicKey::from_openssh(&info.public_key) {
        info.key_type = key_type(&k.algorithm());
        if info.fingerprint.is_empty() {
            info.fingerprint = k.fingerprint(HashAlg::Sha256).to_string();
        }
    }
    info.agent = key.is_some() && settings.is_some_and(|st| st.usable());
    s.ssh = Some(info);
}

/// Put a key into an entry: the key's attachment, `KeeAgent.settings`, and
/// the two plain fields. The attachment gets the key's file name, or
/// `<name>.1`, `.2`, … (KeePassXC's own choice) when the entry already has
/// a file by that name.
fn put_key(e: &mut keepass::db::EntryMut<'_>, key: &KeyFile) {
    let mut name = key.file_name.clone();
    let mut n = 1;
    while e.attachment_by_name_mut(&name).is_some() || name == SETTINGS {
        name = format!("{}.{n}", key.file_name);
        n += 1;
    }
    e.add_attachment(
        name.clone(),
        Value::protected(key.openssh.as_bytes().to_vec()),
    );
    e.add_attachment(
        SETTINGS,
        Value::unprotected(KeeAgent::for_attachment(&name).to_xml()),
    );
    e.set_unprotected(PUBLIC_KEY, key.public_key.clone());
    e.set_unprotected(FINGERPRINT, key.fingerprint.clone());
}

/// The draft an SSH key item starts from.
pub fn draft(title: &str, passphrase: &str) -> Draft {
    Draft {
        kind: Kind::SshKey,
        title: title.to_string(),
        password: Zeroizing::new(passphrase.to_string()),
        ..Draft::default()
    }
}

/// One note `adopt` turned into an SSH key (or would), or left alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adopted {
    pub id: String,
    pub title: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdoptReport {
    pub adopted: Vec<Adopted>,
    /// (title, why): looked like a 1Password SSH key, but isn't one Safe can use.
    pub skipped: Vec<(String, String)>,
}

/// A note an earlier import made from 1Password's SSH Key category: its
/// text starts with the category (`SSH key` from a 1PUX, `Ssh key` through
/// `op`) and one of its protected fields holds the private key. Returns the
/// key, or why it can't be used.
fn from_1password(e: &EntryRef<'_>) -> Option<Result<KeyFile, String>> {
    if item::kind_of(e) != Kind::Note {
        return None;
    }
    let notes = e.get(fields::NOTES).unwrap_or("");
    let first = notes.lines().next().unwrap_or("").trim();
    if !first.eq_ignore_ascii_case("ssh key") {
        return None;
    }
    let mut keys = e.fields.iter().filter(|(k, v)| {
        v.is_protected()
            && k.as_str() != fields::PASSWORD
            && k.as_str() != fields::NOTES
            && is_private_key(v.get().as_bytes())
    });
    let (_, value) = keys.next()?;
    let text = Zeroizing::new(value.get().to_string());
    if keys.next().is_some() {
        return Some(Err("it holds more than one private key".to_string()));
    }
    Some(read_key(text.as_bytes(), "").map_err(|e| e.0))
}

impl Safe {
    /// A new SSH key item ("" is the top folder); returns its id.
    pub fn add_ssh_key(
        &mut self,
        key: &KeyFile,
        title: &str,
        passphrase: &str,
        folder: &str,
    ) -> Result<String, Error> {
        let id = self.add_in(&draft(title, passphrase), folder)?;
        let eid = entry_id(&id)?;
        let mut e = self
            .db_mut()
            .entry_mut(eid)
            .ok_or_else(|| Error::NotFound(id.clone()))?;
        put_key(&mut e, key);
        Ok(id)
    }

    /// Put an imported key into an entry just made (`import`).
    pub(crate) fn put_imported_key(&mut self, id: &str, key: &KeyFile) -> Result<(), Error> {
        let eid = entry_id(id)?;
        let mut e = self
            .db_mut()
            .entry_mut(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        put_key(&mut e, key);
        Ok(())
    }

    /// The private key's text and the passphrase (the entry's password) of
    /// an SSH key item. Never logged by the caller.
    pub fn ssh_private(&self, id: &str) -> Result<(Zeroizing<String>, Zeroizing<String>), Error> {
        let e = self
            .database()
            .entry(entry_id(id)?)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        let missing = || Error::NotFound(format!("{id}: no SSH key"));
        let settings = settings_of(&e).ok_or_else(missing)?;
        let text = key_text_of(&e, &settings).ok_or_else(missing)?;
        let pass = Zeroizing::new(e.get(fields::PASSWORD).unwrap_or("").to_string());
        Ok((text, pass))
    }

    /// Turn the notes an earlier 1Password import made from SSH keys into
    /// SSH key items, in place: same id, the note text stays in the notes,
    /// every field stays; the key's attachment, `KeeAgent.settings`,
    /// `public_key` and `fingerprint` are added, and the note as it was
    /// goes to the item's history. `dry_run` changes nothing.
    pub fn adopt_ssh_keys(&mut self, dry_run: bool) -> Result<AdoptReport, Error> {
        let mut found: Vec<(EntryId, String, KeyFile)> = Vec::new();
        let mut report = AdoptReport::default();
        for e in self.database().iter_all_entries() {
            if self.in_bin(e.parent().id()) {
                continue;
            }
            let title = e.get(fields::TITLE).unwrap_or("").to_string();
            match from_1password(&e) {
                None => {}
                Some(Ok(key)) => found.push((e.id(), title, key)),
                Some(Err(why)) => report.skipped.push((title, why)),
            }
        }
        report.skipped.sort();
        found.sort_by_key(|(_, t, _)| t.to_lowercase());
        if !dry_run && !found.is_empty() {
            self.writable()?;
        }
        let max = self.history_max();
        for (id, title, key) in found {
            if !dry_run {
                let mut e = self
                    .db_mut()
                    .entry_mut(id)
                    .ok_or_else(|| Error::NotFound(id.to_string()))?;
                e.edit_tracking(|t| {
                    let mut m = t.as_mut();
                    m.custom_data.insert(
                        item::KIND_KEY.to_string(),
                        keepass::db::CustomDataItem {
                            value: Some(item::custom_value(item::KIND_SSH)),
                            last_modification_time: Some(keepass::db::Times::now()),
                        },
                    );
                    put_key(&mut m, &key);
                    m.times.last_modification = Some(keepass::db::Times::now());
                });
                crate::safe::settle_history(&mut e, max);
            }
            report.adopted.push(Adopted {
                id: id.to_string(),
                title,
            });
        }
        Ok(report)
    }
}

fn entry_id(id: &str) -> Result<EntryId, Error> {
    uuid::Uuid::parse_str(id)
        .map(EntryId::from)
        .map_err(|_| Error::NotFound(id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KeePassXC's `toXml()` for a key in the attachment `id_ed25519`, with
    /// the switches Safe sets (tests/ssh/README.md).
    const KEEPASSXC_XML: &[u8] = include_bytes!("../../../tests/ssh/KeeAgent.settings");
    /// KeeAgent on Windows: UTF-16 with its mark, CRLF, an element KeePassXC
    /// doesn't know, the location first.
    const KEEAGENT_XML: &str = "<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n<EntrySettings xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\r\n  <Location>\r\n    <SelectedType>attachment</SelectedType>\r\n    <AttachmentName>work &amp; play.key</AttachmentName>\r\n    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>\r\n    <FileName />\r\n  </Location>\r\n  <AllowUseOfSshKey>True</AllowUseOfSshKey>\r\n  <UseDestinationConstraintWhenAdding>false</UseDestinationConstraintWhenAdding>\r\n  <LifetimeConstraintDuration>3600</LifetimeConstraintDuration>\r\n</EntrySettings>";

    #[test]
    fn keeagent_xml_is_keepassxcs_byte_for_byte_and_reads_back() {
        let s = KeeAgent::for_attachment("id_ed25519");
        assert_eq!(
            String::from_utf8_lossy(&s.to_xml()),
            String::from_utf8_lossy(KEEPASSXC_XML)
        );
        assert_eq!(KeeAgent::from_xml(KEEPASSXC_XML), Some(s.clone()));
        assert!(s.usable());
        // the defaults round-trip too (empty elements)
        let d = KeeAgent::default();
        assert_eq!(KeeAgent::from_xml(&d.to_xml()), Some(d.clone()));
        assert!(!d.usable());
        // names that need escaping
        let odd = KeeAgent::for_attachment("a <b> & c");
        assert_eq!(KeeAgent::from_xml(&odd.to_xml()), Some(odd));
    }

    #[test]
    fn keeagent_from_windows_reads_too() {
        let mut bytes = vec![0xFF, 0xFE];
        for u in KEEAGENT_XML.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let s = KeeAgent::from_xml(&bytes).expect("settings");
        assert!(s.allow_use && s.usable());
        assert!(!s.add_at_open);
        assert_eq!(s.attachment_name, "work & play.key");
        assert_eq!(s.lifetime_seconds, 3600);
        assert_eq!(s.file_name, "");
        assert_eq!(KeeAgent::from_xml(b"<Other/>"), None);
        assert_eq!(KeeAgent::from_xml(b"not xml <"), None);
    }

    fn verify(kf: &KeyFile, data: &[u8], sig: &[u8]) {
        use ssh_key::encoding::Decode as _;
        let public = PublicKey::from_openssh(&kf.public_key).expect("public");
        let sig = ssh_key::Signature::decode(&mut &sig[..]).expect("decode");
        signature::Verifier::verify(&public, data, &sig).expect("verifies");
    }

    #[test]
    fn every_key_type_signs_and_verifies() {
        let data = b"session id and the rest";
        for (kind, bits, alg) in [
            ("ed25519", None, "ssh-ed25519"),
            ("ecdsa", None, "ecdsa-sha2-nistp256"),
            ("ecdsa", Some(384), "ecdsa-sha2-nistp384"),
            ("rsa", Some(2048), "rsa-sha2-512"),
        ] {
            let kf = generate(kind, bits, "test").expect(kind);
            assert!(kf.public_key.ends_with(" test"), "{}", kf.public_key);
            assert!(kf.fingerprint.starts_with("SHA256:"));
            let sig = sign(&kf.openssh, "", data, RSA_SHA2_512).expect("sign");
            assert!(
                sig[4..].starts_with(alg.as_bytes()),
                "{kind}: {}",
                String::from_utf8_lossy(&sig)
            );
            verify(&kf, data, &sig);
        }
        let rsa = generate("rsa", Some(2048), "").expect("rsa");
        let sig = sign(&rsa.openssh, "", data, RSA_SHA2_256).expect("sha-256");
        assert!(sig[4..].starts_with(b"rsa-sha2-256"));
        verify(&rsa, data, &sig);
        assert!(
            sign(&rsa.openssh, "", data, 0).is_err(),
            "no SHA-1 signatures"
        );
        assert!(generate("dsa", None, "").is_err());
        assert!(generate("rsa", Some(1024), "").is_err());
    }

    #[test]
    fn a_passphrase_stays_on_the_key() {
        use ssh_key::getrandom::SysRng;
        let kf = generate("ed25519", None, "laptop").expect("key");
        let key = PrivateKey::from_openssh(kf.openssh.as_str()).expect("parse");
        let locked = key.encrypt(&mut SysRng, "hunter2").expect("encrypt");
        let text = locked.to_openssh(LineEnding::LF).expect("text");
        assert!(is_encrypted(text.as_bytes()));
        assert!(!is_encrypted(kf.openssh.as_bytes()));

        let stored = read_key(text.as_bytes(), "hunter2").expect("read");
        assert!(stored.encrypted);
        assert_eq!(stored.openssh.as_str(), text.as_str(), "kept as it was");
        assert_eq!(stored.fingerprint, kf.fingerprint);
        assert_eq!(stored.public_key, kf.public_key, "the comment, once open");
        assert!(read_key(text.as_bytes(), "wrong").is_err());
        let unread = read_key(text.as_bytes(), "").expect("public part only");
        assert_eq!(unread.fingerprint, kf.fingerprint);

        let data = b"x";
        verify(
            &stored,
            data,
            &sign(&text, "hunter2", data, 0).expect("sign"),
        );
        assert!(sign(&text, "nope", data, 0).is_err());
    }

    #[test]
    fn pem_keys_become_openssh() {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        use rsa::pkcs1::EncodeRsaPrivateKey as _;

        let lf = ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF;
        let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pem = ed.to_pkcs8_pem(lf).expect("pem");
        let kf = read_key(pem.as_bytes(), "").expect("pkcs8 ed25519");
        assert!(
            kf.openssh
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert_eq!(
            (kf.key_type.as_str(), kf.file_name.as_str()),
            ("ed25519", "id_ed25519")
        );
        assert_eq!(
            kf.public_key,
            PublicKey::from(Ed25519Keypair::from(ed).public)
                .to_openssh()
                .unwrap()
        );

        let ec = p256::SecretKey::from_bytes(&[9u8; 32].into()).expect("p256");
        let kf = read_key(ec.to_pkcs8_pem(lf).expect("pem").as_bytes(), "").expect("p256");
        assert_eq!(
            (kf.key_type.as_str(), kf.file_name.as_str()),
            ("ecdsa", "id_ecdsa")
        );
        let sec1 = ec.to_sec1_pem(lf).expect("sec1");
        assert_eq!(
            read_key(sec1.as_bytes(), "").expect("sec1").fingerprint,
            kf.fingerprint
        );

        let rsa_kf = generate("rsa", Some(2048), "").expect("rsa");
        let pair = PrivateKey::from_openssh(rsa_kf.openssh.as_str()).unwrap();
        let KeypairData::Rsa(r) = pair.key_data() else {
            panic!("rsa")
        };
        let rk = rsa::RsaPrivateKey::try_from(r).expect("rsa key");
        let p1 = rk.to_pkcs1_pem(lf).expect("pkcs1");
        let kf = read_key(p1.as_bytes(), "").expect("pkcs1");
        assert_eq!(kf.fingerprint, rsa_kf.fingerprint);
        let p8 = rk.to_pkcs8_pem(lf).expect("pkcs8");
        assert_eq!(
            read_key(p8.as_bytes(), "").expect("pkcs8 rsa").fingerprint,
            rsa_kf.fingerprint
        );

        for bad in [
            &b"hello"[..],
            b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----\n",
        ] {
            assert!(read_key(bad, "").is_err());
        }
    }

    #[test]
    fn blobs_and_lines_meet() {
        let kf = generate("ed25519", None, "c").expect("key");
        let blob = public_blob(&kf.public_key).expect("blob");
        let line = public_line(&blob).expect("line");
        assert!(kf.public_key.starts_with(&line));
        assert_eq!(public_blob(&line), Some(blob));
        assert_eq!(public_blob("not a key"), None);
    }
}
