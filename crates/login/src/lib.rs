//! The login unlock's files (docs/SYSTEM.md §2): this computer's session key
//! **W**, sealed by the login password, and the blobs W seals (the master
//! password, the keyring). Never synced; everything lives in
//! `$XDG_STATE_HOME/ewe/safe/`, `0600`.
//!
//! | file | what | sealed by |
//! |---|---|---|
//! | `login.key` | W (32 random bytes) | Argon2id(login password) |
//! | `master.wrap` | the safe's master password | W |
//! | `keyring.safe` | the app secrets | W |
//!
//! Each file is JSON: `{"v": 1, "kind", "kdf" (login.key only), "nonce",
//! "ct"}`, sealed with XChaCha20-Poly1305 and the `kind` as associated data,
//! so a blob can't be passed off as another. Writes are atomic (temp, fsync,
//! rename, fsync the folder).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub const LOGIN_KEY: &str = "login.key";
pub const MASTER_WRAP: &str = "master.wrap";
pub const KEYRING: &str = "keyring.safe";

pub const KIND_LOGIN_KEY: &str = "ewe-safe-login-key";
pub const KIND_MASTER: &str = "ewe-safe-master";
pub const KIND_KEYRING: &str = "ewe-safe-keyring";

const VERSION: u64 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug)]
pub enum Error {
    /// The file isn't there.
    Missing,
    /// The password (or W) doesn't open it.
    WrongKey,
    /// Not a file this crate wrote, or a kind other than the one asked for.
    Corrupt(String),
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Missing => write!(f, "the file isn't there"),
            Error::WrongKey => write!(f, "the password doesn't open it"),
            Error::Corrupt(why) => write!(f, "the file can't be read: {why}"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        if e.kind() == io::ErrorKind::NotFound {
            Error::Missing
        } else {
            Error::Io(e)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// W: this computer's session key. Wiped when dropped.
#[derive(Clone)]
pub struct SessionKey(Zeroizing<[u8; KEY_LEN]>);

impl SessionKey {
    pub fn generate() -> SessionKey {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(k.as_mut()).expect("the system's random source");
        SessionKey(k)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<SessionKey> {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        if bytes.len() != KEY_LEN {
            return None;
        }
        k.copy_from_slice(bytes);
        Some(SessionKey(k))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(…)")
    }
}

impl PartialEq for SessionKey {
    /// Constant time: W is compared after a login password opened a file.
    fn eq(&self, other: &SessionKey) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

/// Argon2id's cost for `login.key`. Opening reads the cost from the file;
/// only sealing picks one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Kdf {
    /// 64 MiB, 3 passes, 2 lanes: about half a second on the dev laptop.
    pub const STANDARD: Kdf = Kdf {
        m_kib: 64 * 1024,
        t: 3,
        p: 2,
    };

    /// For tests only: fast, and still a real Argon2id.
    pub const CHEAP: Kdf = Kdf {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    /// `STANDARD`, or `EWE_SAFE_LOGIN_KDF=<m_kib>,<t>,<p>` (sandboxes and
    /// tests; the daemon's tests set it low as they do the KDBX one).
    pub fn from_env() -> Kdf {
        std::env::var("EWE_SAFE_LOGIN_KDF")
            .ok()
            .and_then(|v| {
                let n: Vec<u32> = v.split(',').filter_map(|x| x.trim().parse().ok()).collect();
                match n[..] {
                    [m, t, p] if m >= 8 * p && t >= 1 && p >= 1 => Some(Kdf { m_kib: m, t, p }),
                    _ => None,
                }
            })
            .unwrap_or(Kdf::STANDARD)
    }

    fn derive(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: self.m_kib,
            time_cost: self.t,
            lanes: self.p,
            secret: &[],
            ad: &[],
            hash_length: KEY_LEN as u32,
            thread_mode: argon2::ThreadMode::Parallel,
        };
        argon2::hash_raw(password, salt, &config)
            .map(Zeroizing::new)
            .map_err(|e| Error::Corrupt(format!("argon2: {e}")))
    }

    fn to_json(self, salt: &[u8]) -> Value {
        json!({"alg": "argon2id", "m_kib": self.m_kib, "t": self.t, "p": self.p,
               "salt": STANDARD.encode(salt)})
    }

    fn from_json(v: &Value) -> Result<(Kdf, Vec<u8>)> {
        let bad = |why: &str| Error::Corrupt(why.to_string());
        if v.get("alg").and_then(Value::as_str) != Some("argon2id") {
            return Err(bad("unknown key derivation"));
        }
        let num = |k: &str| {
            v.get(k)
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| bad("key derivation settings"))
        };
        let kdf = Kdf {
            m_kib: num("m_kib")?,
            t: num("t")?,
            p: num("p")?,
        };
        // a file that asks for absurd memory is not ours: refuse, don't allocate
        if kdf.p == 0 || kdf.t == 0 || kdf.m_kib < 8 * kdf.p || kdf.m_kib > 4 * 1024 * 1024 {
            return Err(bad("key derivation settings"));
        }
        let salt = b64(v.get("salt"))?;
        if salt.len() < 16 {
            return Err(bad("salt"));
        }
        Ok((kdf, salt))
    }
}

fn b64(v: Option<&Value>) -> Result<Vec<u8>> {
    v.and_then(Value::as_str)
        .and_then(|s| STANDARD.decode(s).ok())
        .ok_or_else(|| Error::Corrupt("a field isn't base64".to_string()))
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system's random source");
    b
}

fn seal_with(key: &[u8], kind: &str, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("a 32-byte key");
    let nonce: [u8; NONCE_LEN] = random();
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: kind.as_bytes(),
            },
        )
        .expect("sealing never fails for a valid key and nonce");
    (nonce.to_vec(), ct)
}

fn open_with(key: &[u8], kind: &str, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("a 32-byte key");
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| Error::Corrupt("nonce".to_string()))?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ct,
                aad: kind.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::WrongKey)
}

fn read_json(path: &Path, kind: &str) -> Result<Value> {
    let bytes = fs::read(path)?;
    let v: Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt("not JSON".to_string()))?;
    if v.get("v").and_then(Value::as_u64) != Some(VERSION) {
        return Err(Error::Corrupt("unknown version".to_string()));
    }
    if v.get("kind").and_then(Value::as_str) != Some(kind) {
        return Err(Error::Corrupt(format!("not a {kind} file")));
    }
    Ok(v)
}

/// Write `bytes` to `path` whole or not at all, `0600`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

// ── login.key: W under the login password ───────────────────────────────

/// Seal `w` under `login_password` into `path` (a fresh salt each time).
/// Used to make `login.key` and to re-seal it after the password changed.
pub fn seal_key(path: &Path, w: &SessionKey, login_password: &[u8], kdf: Kdf) -> Result<()> {
    let salt: [u8; SALT_LEN] = random();
    let kek = kdf.derive(login_password, &salt)?;
    let (nonce, ct) = seal_with(&kek, KIND_LOGIN_KEY, w.as_bytes());
    let v = json!({
        "v": VERSION,
        "kind": KIND_LOGIN_KEY,
        "kdf": kdf.to_json(&salt),
        "nonce": STANDARD.encode(nonce),
        "ct": STANDARD.encode(ct),
    });
    write_atomic(path, v.to_string().as_bytes())?;
    Ok(())
}

/// A new W, sealed under `login_password` into `path`.
pub fn create_key(path: &Path, login_password: &[u8], kdf: Kdf) -> Result<SessionKey> {
    let w = SessionKey::generate();
    seal_key(path, &w, login_password, kdf)?;
    Ok(w)
}

/// W from `path`, if `login_password` opens it ([`Error::WrongKey`] if not).
pub fn open_key(path: &Path, login_password: &[u8]) -> Result<SessionKey> {
    let v = read_json(path, KIND_LOGIN_KEY)?;
    let (kdf, salt) = Kdf::from_json(v.get("kdf").unwrap_or(&Value::Null))?;
    let kek = kdf.derive(login_password, &salt)?;
    let plain = open_with(
        &kek,
        KIND_LOGIN_KEY,
        &b64(v.get("nonce"))?,
        &b64(v.get("ct"))?,
    )?;
    SessionKey::from_bytes(&plain).ok_or_else(|| Error::Corrupt("key length".to_string()))
}

/// `passwd` through PAM: open with the old password, seal with the new one.
/// The cost stays what the file had, unless `kdf` asks for another.
pub fn rewrap_key(path: &Path, old: &[u8], new: &[u8], kdf: Option<Kdf>) -> Result<SessionKey> {
    let w = open_key(path, old)?;
    let cost = match kdf {
        Some(k) => k,
        None => {
            let v = read_json(path, KIND_LOGIN_KEY)?;
            Kdf::from_json(v.get("kdf").unwrap_or(&Value::Null))?.0
        }
    };
    seal_key(path, &w, new, cost)?;
    Ok(w)
}

// ── blobs under W ────────────────────────────────────────────────────────

/// Seal `plaintext` under W into `path` as a `kind` file.
pub fn seal(path: &Path, kind: &str, w: &SessionKey, plaintext: &[u8]) -> Result<()> {
    let (nonce, ct) = seal_with(w.as_bytes(), kind, plaintext);
    let v = json!({
        "v": VERSION,
        "kind": kind,
        "nonce": STANDARD.encode(nonce),
        "ct": STANDARD.encode(ct),
    });
    write_atomic(path, v.to_string().as_bytes())?;
    Ok(())
}

/// What `path` holds, if it is a `kind` file sealed by W.
pub fn open(path: &Path, kind: &str, w: &SessionKey) -> Result<Zeroizing<Vec<u8>>> {
    let v = read_json(path, kind)?;
    open_with(
        w.as_bytes(),
        kind,
        &b64(v.get("nonce"))?,
        &b64(v.get("ct"))?,
    )
}

/// The master password from `master.wrap`.
pub fn open_master(path: &Path, w: &SessionKey) -> Result<Zeroizing<String>> {
    let bytes = open(path, KIND_MASTER, w)?;
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::Corrupt("not UTF-8".to_string()))
}

pub fn seal_master(path: &Path, w: &SessionKey, master: &str) -> Result<()> {
    seal(path, KIND_MASTER, w, master.as_bytes())
}

/// Remove a file if it is there (disable, release). Never fails because it
/// was already gone.
pub fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn the_login_password_opens_w_and_another_does_not() {
        let d = dir();
        let p = d.path().join(LOGIN_KEY);
        let w = create_key(&p, b"hunter2", Kdf::CHEAP).unwrap();
        assert_eq!(open_key(&p, b"hunter2").unwrap(), w);
        assert!(matches!(open_key(&p, b"hunter3"), Err(Error::WrongKey)));
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_missing_file_says_so() {
        let d = dir();
        assert!(matches!(
            open_key(&d.path().join(LOGIN_KEY), b"x"),
            Err(Error::Missing)
        ));
    }

    #[test]
    fn rewrap_keeps_w_and_drops_the_old_password() {
        let d = dir();
        let p = d.path().join(LOGIN_KEY);
        let w = create_key(&p, b"old", Kdf::CHEAP).unwrap();
        assert_eq!(rewrap_key(&p, b"old", b"new", None).unwrap(), w);
        assert_eq!(open_key(&p, b"new").unwrap(), w);
        assert!(matches!(open_key(&p, b"old"), Err(Error::WrongKey)));
        assert!(matches!(
            rewrap_key(&p, b"old", b"newer", None),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn blobs_open_only_with_their_w_and_their_kind() {
        let d = dir();
        let p = d.path().join(MASTER_WRAP);
        let w = SessionKey::generate();
        seal_master(&p, &w, "correct horse").unwrap();
        assert_eq!(open_master(&p, &w).unwrap().as_str(), "correct horse");
        assert!(matches!(
            open_master(&p, &SessionKey::generate()),
            Err(Error::WrongKey)
        ));
        // the same bytes passed off as a keyring file: refused by kind
        assert!(matches!(open(&p, KIND_KEYRING, &w), Err(Error::Corrupt(_))));
    }

    #[test]
    fn a_tampered_kind_or_ciphertext_fails_closed() {
        let d = dir();
        let p = d.path().join(KEYRING);
        let w = SessionKey::generate();
        seal(&p, KIND_KEYRING, &w, b"{}").unwrap();
        let mut v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        v["kind"] = json!(KIND_MASTER);
        fs::write(&p, v.to_string()).unwrap();
        // right kind asked, but the ciphertext was sealed for another kind
        assert!(matches!(open(&p, KIND_MASTER, &w), Err(Error::WrongKey)));
        let mut v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        v["kind"] = json!(KIND_KEYRING);
        let mut ct = STANDARD.decode(v["ct"].as_str().unwrap()).unwrap();
        ct[0] ^= 1;
        v["ct"] = json!(STANDARD.encode(ct));
        fs::write(&p, v.to_string()).unwrap();
        assert!(matches!(open(&p, KIND_KEYRING, &w), Err(Error::WrongKey)));
    }

    #[test]
    fn absurd_kdf_settings_are_refused_before_any_work() {
        let d = dir();
        let p = d.path().join(LOGIN_KEY);
        create_key(&p, b"pw", Kdf::CHEAP).unwrap();
        let mut v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        v["kdf"]["m_kib"] = json!(u32::MAX);
        fs::write(&p, v.to_string()).unwrap();
        assert!(matches!(open_key(&p, b"pw"), Err(Error::Corrupt(_))));
    }

    #[test]
    fn the_env_override_is_parsed_or_ignored() {
        // SAFETY: no other test in this crate reads the variable
        unsafe { std::env::set_var("EWE_SAFE_LOGIN_KDF", "64,1,1") };
        assert_eq!(Kdf::from_env(), Kdf::CHEAP);
        unsafe { std::env::set_var("EWE_SAFE_LOGIN_KDF", "nonsense") };
        assert_eq!(Kdf::from_env(), Kdf::STANDARD);
        unsafe { std::env::remove_var("EWE_SAFE_LOGIN_KDF") };
    }

    #[test]
    fn the_standard_cost_is_what_the_contract_says() {
        assert_eq!(
            Kdf::STANDARD,
            Kdf {
                m_kib: 65536,
                t: 3,
                p: 2
            }
        );
    }
}
