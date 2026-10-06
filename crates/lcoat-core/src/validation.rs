//! `validation-plans.ndjson`. Lab Coat phase 1 does not plan or run
//! validation; it reports plans the shell build recorded so packets and
//! readiness agree on sessions the shell build wrote.

use std::path::{Path, PathBuf};

use lcoat_format::json::Object;
use lcoat_format::ndjson;

use crate::error::Result;

/// `validation-plans.ndjson` for an operation directory.
pub fn index_file(op_dir: &Path) -> PathBuf {
    op_dir.join("validation-plans.ndjson")
}

/// The latest state of one validation plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Plan ID.
    pub id: String,
    /// Target.
    pub target: String,
    /// Validation lane.
    pub lane: String,
    /// Capability the plan needs.
    pub capability: String,
    /// `planned`, `approved`, `executed`, `retested`, `superseded`, ...
    pub status: String,
    /// Finding the plan validates.
    pub finding: String,
    /// Why.
    pub reason: String,
    /// Evidence IDs.
    pub evidence: Vec<String>,
    /// Execution result.
    pub result_status: String,
    /// Retest result.
    pub retest_result: String,
    /// Retest note.
    pub retest_note: String,
    /// `superseded_by_plan`
    pub superseded_by: String,
    /// `superseded_reason`
    pub superseded_reason: String,
    /// Created at.
    pub created_at: String,
    /// Updated at.
    pub updated_at: String,
}

fn or<'a>(v: &'a str, fallback: &'a str) -> &'a str {
    if v.is_empty() { fallback } else { v }
}

impl Plan {
    /// Decode from an index object.
    pub fn from_object(o: &Object) -> Self {
        Self {
            id: o.str("id").to_owned(),
            target: o.str("target").to_owned(),
            lane: o.str("lane").to_owned(),
            capability: o.str("capability").to_owned(),
            status: o.str("status").to_owned(),
            finding: o.str("finding").to_owned(),
            reason: o.str("reason").to_owned(),
            evidence: o.strs("evidence"),
            result_status: o.str("result_status").to_owned(),
            retest_result: o.str("retest_result").to_owned(),
            retest_note: o.str("retest_note").to_owned(),
            superseded_by: o.str("superseded_by_plan").to_owned(),
            superseded_reason: o.str("superseded_reason").to_owned(),
            created_at: o.str("created_at").to_owned(),
            updated_at: o.str("updated_at").to_owned(),
        }
    }

    /// The brief's result column.
    pub fn result(&self) -> String {
        if self.status == "superseded" {
            return format!("superseded-by={}", or(&self.superseded_by, "?"));
        }
        or(or(&self.retest_result, &self.result_status), "-").to_owned()
    }

    /// `.updated_at // .created_at`
    pub fn updated_or_created(&self) -> &str {
        or(&self.updated_at, &self.created_at)
    }
}

/// The newest record per ID, filtered to `target` when non-empty.
pub fn latest(op_dir: &Path, target: &str) -> Result<Vec<Plan>> {
    let recs = ndjson::read_file(&index_file(op_dir))?;
    let ids = crate::scope::identifiers(op_dir, target);
    Ok(ndjson::latest(&recs)
        .iter()
        .map(Plan::from_object)
        .filter(|p| target.is_empty() || ids.contains(&p.target))
        .collect())
}

/// `atlas_validation_count_for_target`.
pub fn count(op_dir: &Path, target: &str) -> Result<usize> {
    Ok(latest(op_dir, target)?.len())
}

/// `atlas_brief_validation_status_count`.
pub fn status_count(op_dir: &Path, target: &str, status: &str) -> Result<usize> {
    Ok(latest(op_dir, target)?
        .iter()
        .filter(|p| p.status == status)
        .count())
}

/// `atlas_cycle_validation_queue_rows`: planned or approved, newest first
/// by updated/created then id.
pub fn pending(op_dir: &Path, target: &str) -> Result<Vec<Plan>> {
    let mut out: Vec<Plan> = latest(op_dir, target)?
        .into_iter()
        .filter(|p| matches!(p.status.as_str(), "planned" | "approved"))
        .collect();
    out.sort_by(|a, b| {
        b.updated_or_created()
            .cmp(a.updated_or_created())
            .then_with(|| b.id.cmp(&a.id))
    });
    Ok(out)
}

/// `atlas_brief_latest_validation`: by `updated_at` then id, last.
pub fn latest_plan(op_dir: &Path, target: &str) -> Result<Option<Plan>> {
    let mut ps = latest(op_dir, target)?;
    ps.sort_by(|a, b| {
        a.updated_at
            .cmp(&b.updated_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(ps.pop())
}

/// `atlas_validation_report_markdown`: ascending by created then id.
pub fn report_markdown(op_dir: &Path) -> Result<Vec<String>> {
    let mut ps = latest(op_dir, "")?;
    if ps.is_empty() {
        return Ok(vec!["- No validation plans recorded yet.".into()]);
    }
    ps.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(ps
        .iter()
        .map(|p| {
            let mut b = format!(
                "- {} / {} / {} / {}",
                or(&p.id, "?"),
                or(&p.lane, "?"),
                or(&p.capability, "?"),
                or(&p.status, "?")
            );
            if !p.finding.is_empty() {
                b.push_str(&format!(" Finding: {}.", p.finding));
            }
            if !p.evidence.is_empty() {
                b.push_str(&format!(" Evidence: {}.", p.evidence.join(", ")));
            }
            for (label, v) in [
                ("Result", &p.result_status),
                ("Retest", &p.retest_result),
                ("Retest note", &p.retest_note),
                ("Superseded by", &p.superseded_by),
                ("Superseded reason", &p.superseded_reason),
            ] {
                if !v.is_empty() {
                    b.push_str(&format!(" {label}: {v}."));
                }
            }
            b
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_and_report() {
        let dir = lcoat_format::fsutil::private_temp_dir("lcoat-val").unwrap();
        assert_eq!(
            report_markdown(&dir).unwrap(),
            ["- No validation plans recorded yet."]
        );
        std::fs::write(
            index_file(&dir),
            concat!(
                "{\"id\":\"vp_1\",\"target\":\"t\",\"lane\":\"http\",\"capability\":\"safe-validation\",\"status\":\"planned\",\"finding\":\"finding_1\",\"reason\":\"check\",\"created_at\":\"2026-01-01T00:00:00Z\"}\n",
                "{\"id\":\"vp_2\",\"target\":\"t\",\"lane\":\"tls\",\"capability\":\"safe-validation\",\"status\":\"executed\",\"result_status\":\"confirmed\",\"created_at\":\"2026-01-02T00:00:00Z\",\"updated_at\":\"2026-01-03T00:00:00Z\"}\n",
                "{\"id\":\"vp_3\",\"target\":\"t\",\"status\":\"superseded\",\"superseded_by_plan\":\"vp_2\",\"created_at\":\"2026-01-02T00:00:00Z\"}\n",
            ),
        )
        .unwrap();
        assert_eq!(count(&dir, "t").unwrap(), 3);
        assert_eq!(status_count(&dir, "t", "planned").unwrap(), 1);
        let p = pending(&dir, "t").unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].id, "vp_1");
        assert_eq!(latest_plan(&dir, "t").unwrap().unwrap().id, "vp_2");
        let md = report_markdown(&dir).unwrap();
        assert_eq!(
            md[0],
            "- vp_1 / http / safe-validation / planned Finding: finding_1."
        );
        assert_eq!(
            md[1],
            "- vp_2 / tls / safe-validation / executed Result: confirmed."
        );
        assert_eq!(md[2], "- vp_3 / ? / ? / superseded Superseded by: vp_2.");
        let plans = latest(&dir, "").unwrap();
        assert_eq!(plans[2].result(), "superseded-by=vp_2");
        assert_eq!(plans[1].result(), "confirmed");
        assert_eq!(plans[0].result(), "-");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
