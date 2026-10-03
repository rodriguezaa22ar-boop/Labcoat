//! `evidence.ndjson` and the artifacts it points at.
//!
//! The reading side: the index, per-target counts, the rows the brief and
//! report print, and [`verify_artifacts`], which re-hashes every stored
//! artifact against the sha256 recorded at capture time. Capturing evidence
//! (copy, hash, verify the copy, index, ledger) is the phase 2 writer.

use std::path::{Path, PathBuf};

use lcoat_format::hash::Sha256Hex;
use lcoat_format::json::Object;
use lcoat_format::ndjson;

use crate::error::Result;
use crate::root::file_exists;

/// The evidence kind recorded for output captured by `adapter run`.
pub const KIND_ADAPTER_OUTPUT: &str = "adapter-output";

/// `evidence.ndjson` for an operation directory.
pub fn index_file(op_dir: &Path) -> PathBuf {
    op_dir.join("evidence.ndjson")
}

/// `evidence/` for an operation directory.
pub fn dir(op_dir: &Path) -> PathBuf {
    op_dir.join("evidence")
}

/// One evidence index entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// `ev_<timestamp>`
    pub id: String,
    /// Operation slug.
    pub operation: String,
    /// Target the evidence concerns.
    pub target: String,
    /// `artifact`, `scan-output`, `adapter-output`, ...
    pub kind: String,
    /// Tool that captured it.
    pub source_tool: String,
    /// Where the artifact came from.
    pub source_path: String,
    /// Stored path relative to the operation directory.
    pub path: String,
    /// sha256 recorded at capture.
    pub sha256: String,
    /// Capture time.
    pub created_at: String,
    /// `internal`, `confidential`, ...
    pub classification: String,
    /// Whether a redaction was applied.
    pub redacted: bool,
}

impl Record {
    /// Decode from an index object.
    pub fn from_object(o: &Object) -> Self {
        Self {
            id: o.str("id").to_owned(),
            operation: o.str("operation").to_owned(),
            target: o.str("target").to_owned(),
            kind: o.str("kind").to_owned(),
            source_tool: o.str("source_tool").to_owned(),
            source_path: o.str("source_path").to_owned(),
            path: o.str("path").to_owned(),
            sha256: o.str("sha256").to_owned(),
            created_at: o.str("created_at").to_owned(),
            classification: o.str("classification").to_owned(),
            redacted: o.bool("redacted"),
        }
    }
}

/// The newest record per ID, filtered to `target` when non-empty, in
/// first-seen order (the shell build's jq reduce/select).
pub fn latest(op_dir: &Path, target: &str) -> Result<Vec<Record>> {
    let recs = ndjson::read_file(&index_file(op_dir))?;
    Ok(ndjson::latest(&recs)
        .iter()
        .map(Record::from_object)
        .filter(|r| target.is_empty() || r.target == target)
        .collect())
}

/// `atlas_evidence_count_for_target`.
pub fn count(op_dir: &Path, target: &str) -> Result<usize> {
    Ok(latest(op_dir, target)?.len())
}

/// Whether an evidence ID is recorded for the operation.
pub fn exists(op_dir: &Path, id: &str) -> Result<bool> {
    let recs = ndjson::read_file(&index_file(op_dir))?;
    Ok(recs.iter().any(|r| r.str("id") == id))
}

/// `atlas_evidence_rows_for_target`: newest first by `created_at` then
/// `id`, limited when `limit > 0`.
pub fn rows(op_dir: &Path, target: &str, limit: usize) -> Result<Vec<Record>> {
    let mut recs = latest(op_dir, target)?;
    recs.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    if limit > 0 {
        recs.truncate(limit);
    }
    Ok(recs)
}

/// The result of re-hashing one stored artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactCheck {
    /// Evidence ID.
    pub id: String,
    /// Stored path relative to the operation directory.
    pub path: String,
    /// `verified`, `changed` or `missing`.
    pub status: &'static str,
    /// Recorded sha256.
    pub expected: String,
    /// Current sha256 (empty when missing).
    pub actual: String,
}

/// Re-hash every stored evidence artifact and compare with the sha256
/// recorded at capture. The packet verifiers anchor the index file; this
/// anchors the bytes the index points at. Returns the checks and the
/// number of problems.
pub fn verify_artifacts(op_dir: &Path) -> Result<(Vec<ArtifactCheck>, usize)> {
    let mut out = Vec::new();
    let mut problems = 0;
    for r in latest(op_dir, "")? {
        let full = op_dir.join(&r.path);
        let mut c = ArtifactCheck {
            id: r.id,
            path: r.path.clone(),
            status: "missing",
            expected: r.sha256,
            actual: String::new(),
        };
        if Path::new(&r.path).is_absolute() || !file_exists(&full) {
            problems += 1;
            out.push(c);
            continue;
        }
        let sum = Sha256Hex::of_file(&full)?;
        c.actual = sum.as_str().to_owned();
        if c.actual == c.expected {
            c.status = "verified";
        } else {
            c.status = "changed";
            problems += 1;
        }
        out.push(c);
    }
    Ok((out, problems))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_sort_newest_first_and_verify_catches_edits() {
        let dir = std::env::temp_dir().join(format!("lcoat-ev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("evidence/ev_1")).unwrap();
        std::fs::write(dir.join("evidence/ev_1/a.txt"), b"hello\n").unwrap();
        let sum = Sha256Hex::of_bytes(b"hello\n");
        std::fs::write(
            index_file(&dir),
            format!(
                "{{\"id\":\"ev_1\",\"target\":\"t\",\"path\":\"evidence/ev_1/a.txt\",\"sha256\":\"{}\",\"created_at\":\"2026-01-01T00:00:00Z\",\"redacted\":false}}\n\
                 {{\"id\":\"ev_2\",\"target\":\"t\",\"path\":\"evidence/ev_2/b.txt\",\"sha256\":\"x\",\"created_at\":\"2026-01-02T00:00:00Z\",\"redacted\":true}}\n\
                 {{\"id\":\"ev_1\",\"target\":\"t\",\"path\":\"evidence/ev_1/a.txt\",\"sha256\":\"{}\",\"created_at\":\"2026-01-01T00:00:00Z\",\"redacted\":true}}\n",
                sum.as_str(),
                sum.as_str()
            ),
        )
        .unwrap();
        let l = latest(&dir, "t").unwrap();
        assert_eq!(l.len(), 2);
        assert!(l[0].redacted, "latest record wins");
        assert_eq!(count(&dir, "other").unwrap(), 0);
        assert!(exists(&dir, "ev_2").unwrap());
        assert!(!exists(&dir, "ev_9").unwrap());
        let r = rows(&dir, "", 1).unwrap();
        assert_eq!(r[0].id, "ev_2");

        let (checks, problems) = verify_artifacts(&dir).unwrap();
        assert_eq!(problems, 1);
        assert_eq!(checks[0].status, "verified");
        assert_eq!(checks[1].status, "missing");
        std::fs::write(dir.join("evidence/ev_1/a.txt"), b"edited\n").unwrap();
        let (checks, problems) = verify_artifacts(&dir).unwrap();
        assert_eq!(problems, 2);
        assert_eq!(checks[0].status, "changed");
        assert_ne!(checks[0].actual, checks[0].expected);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
