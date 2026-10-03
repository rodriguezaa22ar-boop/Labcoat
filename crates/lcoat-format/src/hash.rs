//! `Sha256Hex`: the one hash type everything else anchors on.

use std::fmt;
use std::io::{self, Read};
use std::path::Path;

use crate::canonical::canonical_line;
use crate::json::Value;
use crate::sha256::{self, Sha256};

/// A SHA-256 digest as 64 lowercase hex characters, the only form the
/// packets, receipts and ledger ever record.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// Hash arbitrary bytes.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(sha256::to_hex(&sha256::digest(bytes)))
    }

    /// Hash a file's contents, streaming.
    pub fn of_file(path: &Path) -> io::Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut h = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(Self(sha256::to_hex(&h.finalize())))
    }

    /// The hash the shell build computes with `jq -cS . | sha256sum`:
    /// canonical form plus a trailing newline.
    pub fn of_canonical(v: &Value) -> Self {
        Self::of_bytes(&canonical_line(v))
    }

    /// Parse a recorded hash. Anything but 64 lowercase hex characters is
    /// rejected, matching the `^[a-f0-9]{64}$` check in the receipt verifier.
    pub fn parse(s: &str) -> Result<Self, HashError> {
        if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(s.to_owned()))
        } else {
            Err(HashError::Malformed(s.to_owned()))
        }
    }

    /// The hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Sha256Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Hex({}…)", &self.0[..12])
    }
}

/// Errors from parsing recorded hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    /// Not 64 lowercase hex characters.
    Malformed(String),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::Malformed(s) => {
                write!(f, "malformed sha256 (want 64 lowercase hex chars): {s:?}")
            }
        }
    }
}

impl std::error::Error for HashError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_uppercase_and_short() {
        assert!(Sha256Hex::parse(&"A".repeat(64)).is_err());
        assert!(Sha256Hex::parse(&"a".repeat(63)).is_err());
        assert!(Sha256Hex::parse(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn empty_input_hash_is_the_well_known_value() {
        assert_eq!(
            Sha256Hex::of_bytes(b"").as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
