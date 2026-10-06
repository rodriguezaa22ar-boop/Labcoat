//! Retention packets (handoff, closeout, audit, archive): the Markdown
//! documents that hold paths, hashes and counts, and the verifiers that
//! re-check them.
//!
//! Phase 1 ships the verifiers and the trust chain. Rendering the packets is
//! the phase 2 writer, whose text inputs will be [`crate::metadata::MetadataOnly`].

pub mod review;
pub mod trustchain;
pub mod verify;
pub mod write;

pub use trustchain::{TrustChain, collect_trust_chain};
pub use verify::{VerifyResult, archive_verify, audit_verify, closeout_verify};
pub use write::{Written, archive, audit, closeout, handoff, latest};

use std::path::Path;

use crate::error::Result;
use crate::ledger;
use crate::operation::{Operation, State};
use crate::{fail, root::file_exists};

/// The file's sha256, or `""` when the path is empty or missing
/// (`atlas_closeout_sha_for_file`).
pub(crate) fn sha_for_file(path: &str) -> String {
    if path.is_empty() || !file_exists(Path::new(path)) {
        return String::new();
    }
    lcoat_format::hash::Sha256Hex::of_file(Path::new(path))
        .map(|h| h.as_str().to_owned())
        .unwrap_or_default()
}

/// Number of ledger events, like `jq -s length`; 0 on error.
pub(crate) fn ledger_event_count(path: &str) -> usize {
    ledger::count(Path::new(path)).unwrap_or(0)
}

/// The first `- <label>: ` line of a Markdown packet.
pub fn anchor_line<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let prefix = format!("- {label}: ");
    text.split('\n').find(|l| l.starts_with(&prefix))
}

/// The backtick-wrapped path in an anchor line.
pub fn anchor_path(line: &str) -> &str {
    let Some(i) = line.find('`') else { return "" };
    let rest = &line[i + 1..];
    match rest.find('`') {
        Some(j) => &rest[..j],
        None => "",
    }
}

/// A `key=value` token that follows the path in an anchor line.
pub fn anchor_token<'a>(line: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(prefix.as_str()))
        .unwrap_or("")
}

/// A `Key: value` header line value.
pub fn field<'a>(text: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}: ");
    text.split('\n')
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or("")
}

/// A `- Key: value` bullet value.
pub fn bullet_value<'a>(text: &'a str, label: &str) -> &'a str {
    let prefix = format!("- {label}: ");
    text.split('\n')
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or("")
}

/// The path recorded by the latest ledger event for a packet kind
/// (`handoff`, `closeout`, `audit`, `archive`), or `""` when none exists.
pub fn latest_in_ledger<S: State>(op: &Operation<S>, subdir: &str) -> Result<String> {
    let event_name = match subdir {
        "handoff" => "handoff.generated",
        "closeout" => "closeout.manifest.generated",
        "audit" => "audit.packet.generated",
        "archive" => "archive.packet.generated",
        _ => fail!("unknown packet kind: {subdir}"),
    };
    let events = ledger::read(&op.dir)?;
    Ok(ledger::latest(&events, &[event_name])
        .map(|e| e.detail.clone())
        .unwrap_or_default())
}

/// The integrity of an operation's ledger as the trust chain and packet
/// writers see it: the format 1.1 chain walked event by event, or the reason
/// it could not be walked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerIntegrity {
    /// The ledger read; this is what its chain says.
    Chain(crate::chain::ChainStatus),
    /// No ledger file. Every operation has at least `op.started`.
    Missing,
    /// The ledger exists but does not parse (a torn or edited line).
    Unreadable(String),
}

impl LedgerIntegrity {
    /// Read and walk the operation's ledger.
    pub fn of<S: State>(op: &Operation<S>) -> Self {
        let path = ledger::file(&op.dir);
        if !file_exists(&path) {
            return Self::Missing;
        }
        match ledger::read_objects(&path) {
            Ok(objects) => Self::Chain(crate::chain::verify(&objects)),
            Err(e) => Self::Unreadable(e.to_string()),
        }
    }

    /// Whether a packet may anchor this ledger. A v1 (`Unchained`) or
    /// Lite-started (`Partial`) ledger may: the chain cannot say more about
    /// it than the whole-file hash the packet records anyway.
    pub fn is_sound(&self) -> bool {
        !matches!(
            self,
            Self::Missing
                | Self::Unreadable(_)
                | Self::Chain(crate::chain::ChainStatus::Broken { .. })
        )
    }

    /// One line for the operator: what is wrong. Empty when sound.
    pub fn problem(&self) -> String {
        match self {
            Self::Missing => "the operation ledger is missing".to_owned(),
            Self::Unreadable(e) => format!("the operation ledger does not parse ({e})"),
            Self::Chain(crate::chain::ChainStatus::Broken { index, reason }) => {
                format!(
                    "ledger event {} was altered after it was recorded ({reason})",
                    index + 1
                )
            }
            Self::Chain(_) => String::new(),
        }
    }
}

/// Refuse to write a packet that would anchor an altered ledger. Called by
/// every packet writer under the operation lock, before its ledger event is
/// appended: a packet's whole-file ledger hash would otherwise turn an
/// edited event into the verified record.
pub fn require_sound_ledger<S: State>(op: &Operation<S>, packet: &str) -> Result<()> {
    let li = LedgerIntegrity::of(op);
    if !li.is_sound() {
        fail!(
            "refusing to write the {packet}: {}; a packet would anchor it as the verified record. Investigate with: lcoat ledger chain-verify {}",
            li.problem(),
            op.slug
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_parsing() {
        let text = "# Packet\n\nOperation ID: op-1\n\n- Latest report: `/r/x.md` generated=2026 sha256=abc\n- Evidence manifest: none\n- Events: 18\n";
        let line = anchor_line(text, "Latest report").unwrap();
        assert_eq!(anchor_path(line), "/r/x.md");
        assert_eq!(anchor_token(line, "sha256"), "abc");
        assert_eq!(anchor_token(line, "events"), "");
        assert_eq!(
            anchor_path(anchor_line(text, "Evidence manifest").unwrap()),
            ""
        );
        assert!(anchor_line(text, "Missing").is_none());
        assert_eq!(field(text, "Operation ID"), "op-1");
        assert_eq!(bullet_value(text, "Events"), "18");
        assert_eq!(bullet_value(text, "Nope"), "");
    }
}
