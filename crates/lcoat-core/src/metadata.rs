//! The metadata-only boundary, as a type.
//!
//! Packets, receipts and ledger details may hold hashes, paths, counts, IDs
//! and short labels: never raw tool output, secrets or credentials. Lite
//! enforced this with a scanner on each write path and a test that the
//! scanner was called. Here the scanner is the *only* way to obtain a
//! [`MetadataOnly`], and every writer in `lcoat-core` takes `MetadataOnly`,
//! so a write path that skips the scan has nothing to pass and does not
//! compile.
//!
//! The patterns are the shell build's `atlas_receipt_forbidden_content_paths`
//! (via the Go build's `receipt.go`), reproduced here with plain
//! case-insensitive matching so the three implementations reject the same
//! content. The original regular expressions are quoted beside each list.

use std::collections::BTreeSet;
use std::fmt;

use lcoat_format::json::Value;

// (?i)^(…)$ : the key is exactly one of these.
const BAD_KEY_EXACT: &[&str] = &[
    "raw_artifact",
    "raw_artifacts",
    "raw_body",
    "raw_request",
    "raw_response",
    "raw_prompt",
    "raw_model_output",
    "system_prompt",
    "tool_output_body",
    "tool_call_raw",
    "raw_logs",
    "raw_job_output",
    "raw_workflow_output",
    "artifact_body",
    "artifact_content",
    "raw_payload",
    "payload",
    "request_body",
    "response_body",
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "authorization",
    "cookie",
    "session",
    "private_key",
    "credential",
    "webhook_secret",
    "workflow_secret",
    "environment_secret",
    "github_token",
];

// (?i)(^|[_-])(…)([_-]|$) : the key contains one of these as a token
// delimited by `_`, `-` or the ends of the key.
const BAD_KEY_PART: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "authorization",
    "cookie",
    "session",
    "private_key",
    "credential",
];

// (?i) literal markers anywhere in a value.
const BAD_VALUE_LITERAL: &[&str] = &[
    "password=",
    "passwd=",
    "api_key=",
    "secret=",
    "token=",
    "github_token=",
    "webhook_secret=",
    "workflow_secret=",
    "environment_secret=",
    "authorization:",
    "set-cookie:",
    "session=",
    "cookie=",
];

// (?i)BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY
const PRIVATE_KEY_MARKERS: &[&str] = &[
    "begin private key",
    "begin rsa private key",
    "begin openssh private key",
    "begin ec private key",
];

/// A string that has passed the forbidden-content scan.
///
/// The field is private and there is no `From<String>`; [`MetadataOnly::scan`]
/// is the only constructor. Cloning and displaying are fine: the invariant is
/// about how the value came to exist, not where it goes afterwards.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MetadataOnly(String);

impl MetadataOnly {
    /// Scan `raw` and wrap it if it carries no forbidden content.
    pub fn scan(raw: &str) -> Result<Self, Forbidden> {
        if value_is_forbidden(raw) {
            return Err(Forbidden::Value);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Scan a key name (for user-supplied keys, such as receipt fields).
    pub fn scan_key(key: &str) -> Result<Self, Forbidden> {
        if key_is_forbidden(key) {
            return Err(Forbidden::Key(key.to_owned()));
        }
        Self::scan(key)
    }

    /// The scanned text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetadataOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for MetadataOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetadataOnly({:?})", self.0)
    }
}

/// Why a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forbidden {
    /// The key name itself is a forbidden field (`password`, `raw_body`, ...).
    Key(String),
    /// The value matched a credential or raw-content marker.
    Value,
}

impl fmt::Display for Forbidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Forbidden::Key(k) => write!(f, "forbidden key: {k}"),
            Forbidden::Value => f.write_str("value matches a forbidden raw-content marker"),
        }
    }
}

impl std::error::Error for Forbidden {}

/// Whether a key name is forbidden, exactly or as a delimited token.
pub fn key_is_forbidden(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if BAD_KEY_EXACT.contains(&k.as_str()) {
        return true;
    }
    let is_delim = |b: u8| b == b'_' || b == b'-';
    let bytes = k.as_bytes();
    BAD_KEY_PART.iter().any(|part| {
        let p = part.as_bytes();
        (0..=bytes.len().saturating_sub(p.len())).any(|i| {
            bytes[i..].starts_with(p)
                && (i == 0 || is_delim(bytes[i - 1]))
                && (i + p.len() == bytes.len() || is_delim(bytes[i + p.len()]))
        })
    })
}

/// Whether a string value carries a credential or raw-content marker.
pub fn value_is_forbidden(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    if BAD_VALUE_LITERAL.iter().any(|m| v.contains(m)) {
        return true;
    }
    if PRIVATE_KEY_MARKERS.iter().any(|m| v.contains(m)) {
        return true;
    }
    // bearer[ \t]
    if v.match_indices("bearer")
        .any(|(i, _)| matches!(v.as_bytes().get(i + 6), Some(b' ' | b'\t')))
    {
        return true;
    }
    // gh[pousr]_[A-Za-z0-9_]{20,}  (GitHub token shapes)
    let b = v.as_bytes();
    v.match_indices("gh").any(|(i, _)| {
        matches!(b.get(i + 2), Some(b'p' | b'o' | b'u' | b's' | b'r'))
            && b.get(i + 3) == Some(&b'_')
            && b[i + 4..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                .count()
                >= 20
    })
}

/// Walk a decoded JSON document and return the dotted paths of every
/// forbidden key or value, sorted. Empty means clean. This is the whole-
/// document form of the scan, used by `receipt verify` and before any packet
/// is rendered from a document.
pub fn forbidden_paths(doc: &Value) -> Vec<String> {
    let mut found = BTreeSet::new();
    walk(&mut Vec::new(), doc, &mut found);
    found.into_iter().collect()
}

fn walk(path: &mut Vec<String>, node: &Value, found: &mut BTreeSet<String>) {
    if let Some(last) = path.last()
        && key_is_forbidden(last)
    {
        found.insert(path.join("."));
    }
    match node {
        Value::Object(map) => {
            let mut entries: Vec<(&str, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in entries {
                path.push(k.to_owned());
                walk(path, v, found);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(i.to_string());
                walk(path, item, found);
                path.pop();
            }
        }
        Value::String(s) if value_is_forbidden(s) => {
            found.insert(path.join("."));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_metadata_passes() {
        for s in [
            "nmap reported 22/tcp open",
            "evidence=ev_20261002T054004Z sha256=fa0def3c",
            "Open tcp/22 (ssh OpenSSH)",
            "profile=htb-starting-point notes=authorized metadata-only learning operation",
            "tokenizer settings",  // "token" alone is not a marker; "token=" is
            "bearers of bad news", // "bearer" without trailing space/tab
            "ghost_rider_123",     // not a gh[pousr]_ token shape (too short)
        ] {
            assert!(MetadataOnly::scan(s).is_ok(), "{s:?} should pass");
        }
    }

    #[test]
    fn credential_markers_fail() {
        for s in [
            "password=hunter2",
            "Authorization: Bearer abc",
            "set-cookie: sid=1",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "ghp_abcdefghijklmnopqrstuvwxyz0123",
            "GHS_ABCDEFGHIJKLMNOPQRSTUV",
            "token=deadbeef",
            "x bearer\ty",
        ] {
            assert_eq!(
                MetadataOnly::scan(s),
                Err(Forbidden::Value),
                "{s:?} should fail"
            );
        }
    }

    #[test]
    fn forbidden_keys_fail_exact_and_tokenised() {
        for k in [
            "password",
            "raw_body",
            "api_key",
            "github_token",
            "db-password",
            "session_cookie",
            "X_SECRET",
            "my-api_key-2",
        ] {
            assert!(
                matches!(MetadataOnly::scan_key(k), Err(Forbidden::Key(_))),
                "{k:?} should be forbidden"
            );
        }
        for k in [
            "sha256",
            "evidence_refs",
            "tokenizer",
            "sessions_dir",
            "secrets_manager",
            "apikey",
        ] {
            assert!(MetadataOnly::scan_key(k).is_ok(), "{k:?} should be allowed");
        }
    }

    #[test]
    fn document_scan_reports_sorted_paths() {
        let doc = Value::parse(
            r#"{"subject":{"ref":"operation://x","type":"atlas-operation"},"artifact_refs":["a.md=abc"],"notes":"Authorization: Bearer x","nested":{"api_key":"k"}}"#,
        )
        .unwrap();
        assert_eq!(forbidden_paths(&doc), vec!["nested.api_key", "notes"]);
        assert!(
            forbidden_paths(&Value::parse(r#"{"ok":"fine","refs":["x"]}"#).unwrap()).is_empty()
        );
    }

    #[test]
    fn golden_receipts_are_clean() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/golden/demo-site-receipts");
        for name in ["demo-site-boundary", "demo-site-packet", "demo-site-replay"] {
            let text = std::fs::read_to_string(dir.join(format!("{name}.json"))).unwrap();
            assert!(
                forbidden_paths(&Value::parse(&text).unwrap()).is_empty(),
                "{name}"
            );
        }
    }

    #[test]
    fn no_marker_slips_through_any_wrapping() {
        // Deterministic sweep standing in for a property test: a marker must
        // be caught wherever it sits and whatever surrounds it.
        let wraps = ["", "a", "note: ", "  ", "X-", "9"];
        for marker in [
            "password=",
            "API_KEY=",
            "Bearer ",
            "BEGIN PRIVATE KEY",
            "ghp_",
        ] {
            for pre in wraps {
                for post in wraps {
                    let s = if marker == "ghp_" {
                        format!("{pre}{marker}{}{post}", "a1".repeat(10))
                    } else {
                        format!("{pre}{marker}{post}")
                    };
                    assert!(MetadataOnly::scan(&s).is_err(), "{s:?}");
                }
            }
        }
    }
}
