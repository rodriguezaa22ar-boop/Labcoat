//! `evidence.ndjson` and the artifacts it points at.
//!
//! Reading: the index, per-target counts, the rows the brief and report
//! print, and [`verify_artifacts`], which re-hashes every stored artifact
//! against the sha256 recorded at capture time.
//!
//! Writing ([`add`]): copy the artifact into `evidence/<id>/`, hash both
//! copies, append the index record, append the format 1.1 manifest, append
//! the ledger event, in that order (`docs/BLUEPRINT.md`, "Transaction
//! order"). Only an [`Operation<Active>`] can add evidence. The artifact
//! itself may be raw tool output (that is what evidence is); what must stay
//! metadata-only is everything *about* it, so the kind, classification and
//! target labels are [`MetadataOnly`].

use std::path::{Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::fsutil::{copy_private_new, mkdir_private};
use lcoat_format::hash::Sha256Hex;
use lcoat_format::ids::{next_id, slugify};
use lcoat_format::json::{Object, Value};
use lcoat_format::ndjson;

use crate::error::Result;
use crate::fail;
use crate::lock::Lock;
use crate::metadata::MetadataOnly;
use crate::operation::{Active, Operation};
use crate::root::{TOOL_NAME, file_exists};
use crate::tier::Tier;

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

/// `evidence/manifest.ndjson`: the format 1.1 manifest of stored artifacts,
/// whose hash the closeout and archive packets anchor.
pub fn manifest_file(op_dir: &Path) -> PathBuf {
    dir(op_dir).join("manifest.ndjson")
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
    /// Format 1.1: hostname the capture ran from (adapter runs).
    pub vantage: String,
    /// Format 1.1: source address the capture ran from (adapter runs).
    pub vantage_addr: String,
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
            vantage: o.str("vantage").to_owned(),
            vantage_addr: o.str("vantage_addr").to_owned(),
        }
    }
}

impl Record {
    /// Encode in the shell build's field order.
    pub fn to_object(&self) -> Object {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("id", s(&self.id));
        o.insert("operation", s(&self.operation));
        o.insert("target", s(&self.target));
        o.insert("kind", s(&self.kind));
        o.insert("source_tool", s(&self.source_tool));
        o.insert("source_path", s(&self.source_path));
        o.insert("path", s(&self.path));
        o.insert("sha256", s(&self.sha256));
        o.insert("created_at", s(&self.created_at));
        o.insert("classification", s(&self.classification));
        o.insert("redacted", Value::Bool(self.redacted));
        if !self.vantage.is_empty() {
            o.insert("vantage", s(&self.vantage));
        }
        if !self.vantage_addr.is_empty() {
            o.insert("vantage_addr", s(&self.vantage_addr));
        }
        o
    }
}

/// Inputs to [`add`].
#[derive(Clone, Debug)]
pub struct AddParams {
    /// The file to capture.
    pub source: PathBuf,
    /// `artifact` when empty.
    pub kind: Option<MetadataOnly>,
    /// The operation's target when `None`.
    pub target: Option<MetadataOnly>,
    /// `internal` when empty.
    pub classification: Option<MetadataOnly>,
    /// Whether a redaction was applied to the source.
    pub redacted: bool,
    /// Ledger tool name; `atlas` when empty (adapters pass their name).
    pub tool: String,
    /// Format 1.1 vantage (hostname, source address) for adapter captures.
    pub vantage: Option<(MetadataOnly, MetadataOnly)>,
}

/// One format 1.1 manifest line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Evidence ID.
    pub id: String,
    /// Stored path relative to the operation directory.
    pub path: String,
    /// sha256 of the stored copy.
    pub sha256: String,
    /// Size in bytes.
    pub bytes: u64,
    /// When the manifest line was written.
    pub recorded_at: String,
}

impl ManifestEntry {
    /// Decode from a manifest object.
    pub fn from_object(o: &Object) -> Self {
        Self {
            id: o.str("id").to_owned(),
            path: o.str("path").to_owned(),
            sha256: o.str("sha256").to_owned(),
            bytes: match o.get("bytes") {
                Some(Value::Number(n)) => n.parse().unwrap_or(0),
                _ => 0,
            },
            recorded_at: o.str("recorded_at").to_owned(),
        }
    }

    fn to_object(&self) -> Object {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("id", s(&self.id));
        o.insert("path", s(&self.path));
        o.insert("sha256", s(&self.sha256));
        o.insert("bytes", Value::Number(self.bytes.to_string()));
        o.insert("recorded_at", s(&self.recorded_at));
        o
    }
}

/// Every manifest line, in order; a missing manifest is empty.
pub fn manifest(op_dir: &Path) -> Result<Vec<ManifestEntry>> {
    Ok(ndjson::read_file(&manifest_file(op_dir))?
        .iter()
        .map(ManifestEntry::from_object)
        .collect())
}

/// `cmd_evidence_add`: preflight (read-only), claim an ID, copy, hash,
/// verify the copy, append the index record, append the manifest, append
/// the ledger event. Returns the index record.
pub fn add(op: &Operation<Active>, p: &AddParams) -> Result<Record> {
    let lock = op.lock()?;
    add_locked(op, p, &lock)
}

/// [`add`] for a caller that already holds the operation lock (the adapter
/// runner holds it for the whole run, so a second lock here would wait on
/// itself).
pub fn add_locked(op: &Operation<Active>, p: &AddParams, _held: &Lock) -> Result<Record> {
    if !file_exists(&p.source) {
        fail!("evidence path is not a file: {}", p.source.display());
    }
    let kind = p.kind.as_ref().map_or("artifact", MetadataOnly::as_str);
    let classification = p
        .classification
        .as_ref()
        .map_or("internal", MetadataOnly::as_str);
    // Any identifier of the operation's target (name, address, label) is
    // recorded as the canonical name, so every reader finds the record.
    let target = p
        .target
        .as_ref()
        .map_or(op.target.as_str(), MetadataOnly::as_str);
    let target = if op.matches_identifier(target) {
        op.target.as_str()
    } else {
        target
    };
    let tool = if p.tool.is_empty() {
        TOOL_NAME
    } else {
        p.tool.as_str()
    };

    op.preflight(Tier::ReadOnly, tool, target, "add evidence artifact")?
        .into_result()?;

    let root = dir(&op.dir);
    mkdir_private(&root)?;
    let id = next_id(&root, "ev");
    let id_dir = root.join(&id);
    mkdir_private(&id_dir)?;
    let base = p
        .source
        .file_name()
        .map(|n| {
            slugify(&n.to_string_lossy())
                .trim_start_matches('.')
                .to_owned()
        })
        .unwrap_or_default();
    let name = if base.is_empty() {
        "artifact".to_owned()
    } else {
        base
    };
    let relative = format!("evidence/{id}/{name}");
    let destination = op.dir.join(&relative);

    let sum = Sha256Hex::of_file(&p.source)?;
    let bytes = copy_private_new(&p.source, &destination)?;
    crate::crash::point("evidence.copied");
    let copied = Sha256Hex::of_file(&destination)?;
    if copied != sum {
        fail!("evidence copy integrity check failed");
    }
    let rec = Record {
        id: id.clone(),
        operation: op.slug.clone(),
        target: target.to_owned(),
        kind: kind.to_owned(),
        source_tool: TOOL_NAME.into(),
        source_path: p.source.display().to_string(),
        path: relative.clone(),
        sha256: sum.as_str().to_owned(),
        created_at: clock::timestamp(),
        classification: classification.to_owned(),
        redacted: p.redacted,
        vantage: p
            .vantage
            .as_ref()
            .map(|(h, _)| h.as_str().to_owned())
            .unwrap_or_default(),
        vantage_addr: p
            .vantage
            .as_ref()
            .map(|(_, a)| a.as_str().to_owned())
            .unwrap_or_default(),
    };
    ndjson::append(&index_file(&op.dir), &rec.to_object())?;
    crate::crash::point("evidence.indexed");
    ndjson::append(
        &manifest_file(&op.dir),
        &ManifestEntry {
            id: id.clone(),
            path: relative.clone(),
            sha256: rec.sha256.clone(),
            bytes,
            recorded_at: rec.created_at.clone(),
        }
        .to_object(),
    )?;
    let detail = format!(
        "evidence={id} kind={kind} sha256={} path={relative}",
        rec.sha256
    );
    op.append_ledger(
        "artifact.created",
        Tier::ReadOnly.capability(),
        tool,
        "ok",
        &detail,
    )?;
    Ok(rec)
}

/// The newest record per ID, filtered to `target` when non-empty, in
/// first-seen order (the shell build's jq reduce/select).
pub fn latest(op_dir: &Path, target: &str) -> Result<Vec<Record>> {
    let recs = ndjson::read_file(&index_file(op_dir))?;
    let ids = crate::scope::identifiers(op_dir, target);
    Ok(ndjson::latest(&recs)
        .iter()
        .map(Record::from_object)
        .filter(|r| target.is_empty() || ids.contains(&r.target))
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
    /// `verified`, `changed`, `missing`, or one of the cross-check
    /// verdicts: `unindexed` (the manifest or ledger records an artifact
    /// the index no longer lists), `conflict` (the index's hash or path
    /// disagrees with the manifest, the ledger or an earlier index record
    /// for the same ID), `unsafe` (a stored path outside the operation).
    pub status: &'static str,
    /// Recorded sha256.
    pub expected: String,
    /// Current sha256 (empty when missing).
    pub actual: String,
    /// What disagrees with what, for the cross-check verdicts.
    pub detail: String,
}

/// A stored path is relative and has no `..`, so it stays inside the
/// operation directory.
fn safe_relative(path: &str) -> bool {
    let p = Path::new(path);
    !path.is_empty()
        && !p.is_absolute()
        && p.components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

/// `evidence=<id> ... sha256=<hash>` from an `artifact.created` detail
/// (the same in the shell, Lite and Lab Coat).
fn created_event(detail: &str) -> Option<(String, String, String)> {
    let mut id = None;
    let mut sha = None;
    let mut path = String::new();
    for tok in detail.split_whitespace() {
        if let Some(v) = tok.strip_prefix("evidence=") {
            id = Some(v.to_owned());
        } else if let Some(v) = tok.strip_prefix("sha256=") {
            sha = Some(v.to_owned());
        } else if let Some(v) = tok.strip_prefix("path=") {
            v.clone_into(&mut path);
        }
    }
    Some((id?, sha?, path))
}

/// Re-hash every stored evidence artifact and compare with the sha256
/// recorded at capture, then cross-check the three places a capture is
/// recorded: the index (`evidence.ndjson`), the format 1.1 manifest and the
/// ledger's `artifact.created` events. The index alone used to be trusted,
/// so emptying it gave `verified, checked 0`, and appending a newer record
/// for an ID with a new hash re-blessed an edited artifact (review
/// 2026-10-05). Shell- and Lite-written operations have no manifest; their
/// ledger still names every capture. Returns the checks and the number of
/// problems.
pub fn verify_artifacts(op_dir: &Path) -> Result<(Vec<ArtifactCheck>, usize)> {
    let mut out = Vec::new();
    let all = ndjson::read_file(&index_file(op_dir))?;
    let latest_recs = latest(op_dir, "")?;
    let check = |id: &str, path: &str, status, expected: &str, detail: String| ArtifactCheck {
        id: id.to_owned(),
        path: path.to_owned(),
        status,
        expected: expected.to_owned(),
        actual: String::new(),
        detail,
    };

    for r in &latest_recs {
        let full = op_dir.join(&r.path);
        if !safe_relative(&r.path) {
            out.push(check(
                &r.id,
                &r.path,
                "unsafe",
                &r.sha256,
                "stored path leaves the operation directory".to_owned(),
            ));
            continue;
        }
        // Every record for this ID must name the same bytes; a redaction
        // adds `redacted_*` fields and keeps `path` and `sha256`.
        if let Some(prev) = all.iter().find(|o| {
            o.str("id") == r.id && (o.str("sha256") != r.sha256 || o.str("path") != r.path)
        }) {
            out.push(check(
                &r.id,
                &r.path,
                "conflict",
                &r.sha256,
                format!(
                    "an earlier index record has sha256={} path={}",
                    prev.str("sha256"),
                    prev.str("path")
                ),
            ));
            continue;
        }
        let mut c = check(&r.id, &r.path, "missing", &r.sha256, String::new());
        if !file_exists(&full) {
            out.push(c);
            continue;
        }
        let sum = Sha256Hex::of_file(&full)?;
        c.actual = sum.as_str().to_owned();
        c.status = if c.actual == c.expected {
            "verified"
        } else {
            "changed"
        };
        out.push(c);
    }

    let indexed = |id: &str| latest_recs.iter().find(|r| r.id == id);
    let mut cross = |id: &str, path: &str, sha: &str, source: &str| {
        if out.iter().any(|c| c.id == id && c.status != "verified") {
            return;
        }
        match indexed(id) {
            None => out.push(check(
                id,
                path,
                "unindexed",
                sha,
                format!("recorded by the {source}, absent from the index"),
            )),
            Some(r) if r.sha256 != sha => {
                out.retain(|c| c.id != id);
                out.push(check(
                    id,
                    &r.path,
                    "conflict",
                    &r.sha256,
                    format!("the {source} recorded sha256={sha}"),
                ));
            }
            Some(_) => {}
        }
    };
    for m in manifest(op_dir)? {
        cross(&m.id, &m.path, &m.sha256, "manifest");
    }
    for e in crate::ledger::read(op_dir)? {
        if e.event == "artifact.created"
            && let Some((id, sha, path)) = created_event(&e.detail)
        {
            cross(&id, &path, &sha, "ledger");
        }
    }

    let problems = out.iter().filter(|c| c.status != "verified").count();
    Ok((out, problems))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_paths_stay_inside_and_created_events_parse() {
        assert!(safe_relative("evidence/ev_1/a.txt"));
        assert!(safe_relative("./evidence/a"));
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "evidence/../../x",
            "evidence/ev_1/..",
        ] {
            assert!(!safe_relative(bad), "{bad}");
        }
        assert_eq!(
            created_event("evidence=ev_1 kind=scan-output sha256=ab path=evidence/ev_1/r.txt"),
            Some(("ev_1".into(), "ab".into(), "evidence/ev_1/r.txt".into()))
        );
        assert_eq!(created_event("kind=x sha256=ab"), None);
    }

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
