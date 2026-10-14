//! One-time codes (RFC 6238) from an `otpauth://totp/…` URI, the way
//! authenticator apps read it: 6 digits, 30 seconds and SHA-1 unless the URI
//! says otherwise; the base32 secret with or without padding, any case,
//! spaces ignored.

use std::time::{SystemTime, UNIX_EPOCH};

use totp_lite::{Sha1, Sha256, Sha512, totp_custom};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OtpError {
    NotTotp,
    Secret,
    Digits,
    Period,
    Algorithm,
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OtpError::NotTotp => "not an otpauth://totp/ address",
            OtpError::Secret => "the secret is missing or not base32",
            OtpError::Digits => "digits must be 6 to 8",
            OtpError::Period => "the period must be 1 to 300 seconds",
            OtpError::Algorithm => "the algorithm must be SHA1, SHA256 or SHA512",
        })
    }
}

impl std::error::Error for OtpError {}

pub fn decode_secret(text: &str) -> Option<Vec<u8>> {
    let mut clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &clean);
    clean.zeroize();
    bytes.filter(|b| !b.is_empty())
}

impl Totp {
    pub fn parse(uri: &str) -> Result<Totp, OtpError> {
        let url = Url::parse(uri.trim()).map_err(|_| OtpError::NotTotp)?;
        if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
            return Err(OtpError::NotTotp);
        }
        let mut secret = None;
        let mut digits = 6;
        let mut period = 30;
        let mut algorithm = Algorithm::Sha1;
        for (k, v) in url.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = decode_secret(&v),
                "digits" => digits = v.parse().map_err(|_| OtpError::Digits)?,
                "period" => period = v.parse().map_err(|_| OtpError::Period)?,
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(OtpError::Algorithm),
                    }
                }
                _ => {}
            }
        }
        if !(6..=8).contains(&digits) {
            return Err(OtpError::Digits);
        }
        if !(1..=300).contains(&period) {
            return Err(OtpError::Period);
        }
        Ok(Totp {
            secret: Zeroizing::new(secret.ok_or(OtpError::Secret)?),
            digits,
            period,
            algorithm,
        })
    }

    pub fn code_at(&self, unix: u64) -> Zeroizing<String> {
        Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => totp_custom::<Sha1>(self.period, self.digits, &self.secret, unix),
            Algorithm::Sha256 => {
                totp_custom::<Sha256>(self.period, self.digits, &self.secret, unix)
            }
            Algorithm::Sha512 => {
                totp_custom::<Sha512>(self.period, self.digits, &self.secret, unix)
            }
        })
    }

    /// The code now and the seconds it stays valid.
    pub fn now(&self) -> (Zeroizing<String>, u64) {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (self.code_at(unix), self.period - unix % self.period)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, 8 digits, the ASCII seeds base32-encoded
    const SEED1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SEED256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SEED512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    fn uri(seed: &str, alg: &str) -> String {
        format!("otpauth://totp/x?secret={seed}&digits=8&algorithm={alg}")
    }

    #[test]
    fn rfc_6238_vectors() {
        let cases = [
            (59u64, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1234567890, "89005924", "91819424", "93441116"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        let s1 = Totp::parse(&uri(SEED1, "SHA1")).expect("sha1");
        let s256 = Totp::parse(&uri(SEED256, "SHA256")).expect("sha256");
        let s512 = Totp::parse(&uri(SEED512, "SHA512")).expect("sha512");
        for (t, a, b, c) in cases {
            assert_eq!(s1.code_at(t).as_str(), a, "sha1 at {t}");
            assert_eq!(s256.code_at(t).as_str(), b, "sha256 at {t}");
            assert_eq!(s512.code_at(t).as_str(), c, "sha512 at {t}");
        }
    }

    #[test]
    fn defaults_are_what_authenticator_apps_use() {
        let t = Totp::parse("otpauth://totp/Bank:sam?secret=JBSWY3DPEHPK3PXP&issuer=Bank")
            .expect("parse");
        assert_eq!((t.digits, t.period, t.algorithm), (6, 30, Algorithm::Sha1));
        assert_eq!(t.now().0.len(), 6);
    }

    #[test]
    fn secrets_with_or_without_padding_and_in_any_case() {
        // 26 characters: valid only without padding
        let unpadded =
            Totp::parse("otpauth://totp/x?secret=jbswy3dpehpk3pxpjbswy3dpeh").expect("unpadded");
        let padded =
            Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEH%3D%3D%3D%3D%3D%3D")
                .expect("padded");
        assert_eq!(
            unpadded.code_at(1_000_000).as_str(),
            padded.code_at(1_000_000).as_str()
        );
        assert!(Totp::parse("otpauth://totp/x?secret=JBSW Y3DP EHPK 3PXP").is_ok());
    }

    #[test]
    fn bad_uris() {
        assert_eq!(
            Totp::parse("https://example.com").err(),
            Some(OtpError::NotTotp)
        );
        assert_eq!(
            Totp::parse("otpauth://hotp/x?secret=JBSWY3DP").err(),
            Some(OtpError::NotTotp)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x").err(),
            Some(OtpError::Secret)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=!!!").err(),
            Some(OtpError::Secret)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=JBSWY3DP&digits=12").err(),
            Some(OtpError::Digits)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=JBSWY3DP&period=0").err(),
            Some(OtpError::Period)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5").err(),
            Some(OtpError::Algorithm)
        );
    }
}
