//! The Secret Service's transfer encryption (spec 0.2, "Transfer of
//! Secrets"): `plain`, and `dh-ietf1024-sha256-aes128-cbc-pkcs7` — a
//! Diffie-Hellman exchange in RFC 2409's second Oakley group (1024 bits,
//! generator 2), the shared value through HKDF-SHA256 (no salt, no info) to
//! a 16-byte key, each secret then AES-128-CBC with PKCS#7 padding and a
//! fresh IV. This is what libsecret (and gnome-keyring, KeePassXC) speak;
//! libsecret falls back to `plain` only when a service answers NotSupported.
//!
//! The shared value is padded to the prime's 128 bytes before HKDF, as
//! libsecret's `egg_dh_gen_secret` does.

use aes::Aes128;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U1024};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const PLAIN: &str = "plain";
pub const DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 §6.2, the second Oakley group.
const PRIME: U1024 = U1024::from_be_hex(concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
));
const BYTES: usize = 128;
pub const IV_LEN: usize = 16;

fn params() -> FixedMontyParams<{ U1024::LIMBS }> {
    FixedMontyParams::new_vartime(Odd::new(PRIME).expect("the Oakley prime is odd"))
}

fn pow(base: &U1024, exp: &U1024) -> U1024 {
    FixedMontyForm::new(base, &params()).pow(exp).retrieve()
}

/// A big-endian number of at most 128 bytes (leading zeros may be missing).
fn from_be(bytes: &[u8]) -> Option<U1024> {
    let bytes = match bytes.iter().position(|b| *b != 0) {
        Some(i) => &bytes[i..],
        None => &[][..],
    };
    if bytes.len() > BYTES {
        return None;
    }
    let mut padded = Zeroizing::new([0u8; BYTES]);
    padded[BYTES - bytes.len()..].copy_from_slice(bytes);
    Some(U1024::from_be_slice(padded.as_ref()))
}

fn to_be(n: &U1024) -> Zeroizing<[u8; BYTES]> {
    let mut out = Zeroizing::new([0u8; BYTES]);
    out.copy_from_slice(n.to_be_bytes().as_ref());
    out
}

/// One side of the exchange: our private exponent and public value.
pub struct KeyPair {
    private: Zeroizing<[u8; BYTES]>,
    pub public: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let mut private = Zeroizing::new([0u8; BYTES]);
        getrandom::fill(private.as_mut()).expect("the system's random source");
        let x = U1024::from_be_slice(private.as_ref());
        let public = to_be(&pow(&U1024::from_u8(2), &x)).to_vec();
        KeyPair { private, public }
    }

    /// The AES key for a peer's public value; `None` when the value isn't
    /// one (out of range: 0, 1, p−1 or more).
    pub fn aes_key(&self, peer: &[u8]) -> Option<Zeroizing<[u8; 16]>> {
        let y = from_be(peer)?;
        let one = U1024::ONE;
        let top = PRIME.wrapping_sub(&one);
        if y <= one || y >= top {
            return None;
        }
        let x = U1024::from_be_slice(self.private.as_ref());
        let shared = to_be(&pow(&y, &x));
        Some(hkdf16(shared.as_ref()))
    }
}

/// HKDF-SHA256 (RFC 5869) with no salt (= 32 zero bytes) and no info, the
/// first 16 bytes of output.
fn hkdf16(ikm: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut extract =
        <Hmac<Sha256> as KeyInit>::new_from_slice(&[0u8; 32]).expect("HMAC takes any key");
    extract.update(ikm);
    let mut prk = extract.finalize().into_bytes();
    let mut expand = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk).expect("HMAC takes any key");
    prk.as_mut_slice().zeroize();
    expand.update(&[1u8]);
    let mut okm = expand.finalize().into_bytes();
    let mut key = Zeroizing::new([0u8; 16]);
    key.copy_from_slice(&okm[..16]);
    okm.as_mut_slice().zeroize();
    key
}

/// AES-128-CBC with PKCS#7 under `key`: (iv, ciphertext).
pub fn encrypt(key: &[u8; 16], plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut iv = [0u8; IV_LEN];
    getrandom::fill(&mut iv).expect("the system's random source");
    let ct =
        cbc::Encryptor::<Aes128>::new(key.into(), (&iv).into()).encrypt_padded_vec::<Pkcs7>(plain);
    (iv.to_vec(), ct)
}

/// The plain bytes, or `None` when `iv` or the padding is wrong.
pub fn decrypt(key: &[u8; 16], iv: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let iv: [u8; IV_LEN] = iv.try_into().ok()?;
    if ct.is_empty() || !ct.len().is_multiple_of(16) {
        return None;
    }
    cbc::Decryptor::<Aes128>::new(key.into(), (&iv).into())
        .decrypt_padded_vec::<Pkcs7>(ct)
        .ok()
        .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_reach_the_same_key() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let ka = a.aes_key(&b.public).unwrap();
        let kb = b.aes_key(&a.public).unwrap();
        assert_eq!(*ka, *kb);
        // a public value with its leading zeros cut is the same number
        let trimmed: Vec<u8> = b.public.iter().copied().skip_while(|x| *x == 0).collect();
        assert_eq!(*a.aes_key(&trimmed).unwrap(), *ka);
    }

    #[test]
    fn values_out_of_range_are_refused() {
        let a = KeyPair::generate();
        assert!(a.aes_key(&[]).is_none());
        assert!(a.aes_key(&[1]).is_none());
        assert!(a.aes_key(&PRIME.to_be_bytes()).is_none());
        assert!(a.aes_key(&[0xff; 129]).is_none());
        let p_minus_1 = PRIME.wrapping_sub(&U1024::ONE);
        assert!(a.aes_key(&p_minus_1.to_be_bytes()).is_none());
    }

    #[test]
    fn a_secret_round_trips_and_a_wrong_key_fails() {
        let k = [7u8; 16];
        let (iv, ct) = encrypt(&k, b"hunter2");
        assert_eq!(ct.len(), 16);
        assert_eq!(&decrypt(&k, &iv, &ct).unwrap()[..], b"hunter2");
        // an empty secret still has one block of padding
        let (iv0, ct0) = encrypt(&k, b"");
        assert_eq!(ct0.len(), 16);
        assert!(decrypt(&k, &iv0, &ct0).unwrap().is_empty());
        assert!(decrypt(&[8u8; 16], &iv, &ct).is_none_or(|p| &p[..] != b"hunter2"));
        assert!(decrypt(&k, &iv[..8], &ct).is_none());
    }

    #[test]
    fn hkdf_matches_rfc_5869_with_no_salt() {
        // RFC 5869 A.3: IKM = 22 × 0x0b, no salt, no info; OKM starts so
        let okm = hkdf16(&[0x0b; 22]);
        assert_eq!(
            okm.as_ref(),
            &[
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31
            ]
        );
    }
}
