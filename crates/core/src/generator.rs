//! Passwords and passphrases from the system's random source (getrandom).
//!
//! - Characters: letters and digits, symbols optional; at least one of each
//!   class used. Drawn uniformly, and redrawn whole when a class is missing,
//!   so every allowed password is equally likely.
//! - Words: the EFF long list (7776 words, 12.9 bits each; NOTICE).

use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// No quotes, backslash or space: they break shells and some login forms.
const SYMBOLS: &str = "!#$%&*+-=?@^_~";

const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;

#[derive(Debug, PartialEq, Eq)]
pub enum GeneratorError {
    Length(usize),
    Words(usize),
    Random(String),
}

impl std::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneratorError::Length(n) => {
                write!(f, "length {n} is outside {MIN_LENGTH}–{MAX_LENGTH}")
            }
            GeneratorError::Words(n) => write!(f, "{n} words is outside {MIN_WORDS}–{MAX_WORDS}"),
            GeneratorError::Random(e) => write!(f, "no randomness: {e}"),
        }
    }
}

impl std::error::Error for GeneratorError {}

/// A uniform index below `n`, by rejection sampling (no modulo bias).
fn below(n: usize) -> Result<usize, GeneratorError> {
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).map_err(|e| GeneratorError::Random(e.to_string()))?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok((v % n) as usize);
        }
    }
}

fn words() -> impl Iterator<Item = &'static str> {
    WORDLIST.lines().filter_map(|l| l.split('\t').nth(1))
}

/// A password of `length` characters.
pub fn password(length: usize, symbols: bool) -> Result<Zeroizing<String>, GeneratorError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(GeneratorError::Length(length));
    }
    let mut classes = vec![LOWER, UPPER, DIGITS];
    if symbols {
        classes.push(SYMBOLS);
    }
    let alphabet: Vec<char> = classes.concat().chars().collect();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(length));
        for _ in 0..length {
            out.push(alphabet[below(alphabet.len())?]);
        }
        if classes.iter().all(|c| out.chars().any(|x| c.contains(x))) {
            return Ok(out);
        }
    }
}

/// A passphrase of `count` words joined by `separator`.
pub fn passphrase(count: usize, separator: &str) -> Result<Zeroizing<String>, GeneratorError> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&count) {
        return Err(GeneratorError::Words(count));
    }
    let list: Vec<&str> = words().collect();
    let mut out = Zeroizing::new(String::new());
    for i in 0..count {
        if i > 0 {
            out.push_str(separator);
        }
        out.push_str(list[below(list.len())?]);
    }
    Ok(out)
}

/// Bits of entropy of [`password`] (an upper bound: the class rule trims a
/// little) and of [`passphrase`].
pub fn password_bits(length: usize, symbols: bool) -> f64 {
    let n = LOWER.len() + UPPER.len() + DIGITS.len() + if symbols { SYMBOLS.len() } else { 0 };
    length as f64 * (n as f64).log2()
}

pub fn passphrase_bits(count: usize) -> f64 {
    count as f64 * (words().count() as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_the_eff_long_list() {
        let list: Vec<&str> = words().collect();
        assert_eq!(list.len(), 7776);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[7775], "zoom");
        let mut sorted = list.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 7776, "no duplicate words");
    }

    #[test]
    fn passwords_have_every_class_and_the_length() {
        for _ in 0..200 {
            let p = password(12, true).expect("password");
            assert_eq!(p.chars().count(), 12);
            for class in [LOWER, UPPER, DIGITS, SYMBOLS] {
                assert!(p.chars().any(|c| class.contains(c)), "{class} missing");
            }
            let q = password(8, false).expect("password");
            assert!(q.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn characters_are_spread_evenly() {
        // 62 symbols over 62 000 draws: each should land near 1000
        let mut seen = std::collections::HashMap::new();
        for _ in 0..1000 {
            for c in password(62, false).expect("password").chars() {
                *seen.entry(c).or_insert(0u32) += 1;
            }
        }
        assert_eq!(seen.len(), 62);
        assert!(seen.values().all(|&n| (800..1200).contains(&n)), "{seen:?}");
    }

    #[test]
    fn passphrases() {
        let p = passphrase(5, "-").expect("passphrase");
        let parts: Vec<&str> = p.split('-').collect();
        assert!(
            parts.len() >= 5,
            "hyphenated words may add parts: {parts:?}"
        );
        assert!((64.0..65.0).contains(&passphrase_bits(5)));
        // 76 symbols: 6.25 bits each
        assert!((124.0..126.0).contains(&password_bits(20, true)));
    }

    #[test]
    fn limits() {
        assert_eq!(password(7, true), Err(GeneratorError::Length(7)));
        assert_eq!(passphrase(2, " "), Err(GeneratorError::Words(2)));
    }
}
