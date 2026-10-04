//! The operation report (`reports/<slug>.md`) and the operator brief it
//! embeds, byte for byte as the shell build's `write_operation_report`
//! renders them for a session Lab Coat can drive.
//!
//! The report holds counts, hashes, IDs, titles and the scope text. It never
//! holds tool output: adapter runs appear as `Recon artifact:` lines with a
//! path and a hash. Any state may write a report (the shell allows a report
//! on a closed operation; readiness then calls it stale or current).

use std::path::PathBuf;

use lcoat_format::clock;
use lcoat_format::fsutil::{mkdir_private, write_private};
use lcoat_format::ids::slugify;

use crate::error::Result;
use crate::evidence;
use crate::fail;
use crate::findings::{self, Finding};
use crate::history;
use crate::operation::{Operation, State};
use crate::root::TOOL_NAME;
use crate::tier::Tier;
use crate::validation::{self, Plan};

/// The operator brief: the intel-graph surface counts are always zero here,
/// which matches a session with no wiremap recon runs (`host=unknown`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Brief {
    pub host_state: String,
    pub service_count: usize,
    pub web_count: usize,
    pub lateral_count: usize,
    pub posture_count: usize,
    pub evidence_count: usize,
    pub finding_count: usize,
    pub validation_count: usize,
    pub planned_count: usize,
    pub approved_count: usize,
    pub executed_count: usize,
    pub latest_finding: Option<Finding>,
    pub latest_validation: Option<Plan>,
    pub next_step: &'static str,
}

impl Brief {
    /// Gather the brief for an operation.
    pub fn collect<S: State>(op: &Operation<S>) -> Result<Self> {
        let (dir, target) = (op.dir.as_path(), op.target.as_str());
        let mut b = Self {
            host_state: "unknown".into(),
            evidence_count: evidence::count(dir, target)?,
            finding_count: findings::count(dir, target)?,
            validation_count: validation::count(dir, target)?,
            planned_count: validation::status_count(dir, target, "planned")?,
            approved_count: validation::status_count(dir, target, "approved")?,
            executed_count: validation::status_count(dir, target, "executed")?,
            latest_finding: findings::latest_finding(dir, target)?,
            latest_validation: validation::latest_plan(dir, target)?,
            ..Default::default()
        };
        b.next_step = b.next_step();
        Ok(b)
    }

    fn next_step(&self) -> &'static str {
        if self.approved_count > 0 {
            "Run the approved validation plan and record the resulting evidence."
        } else if self.planned_count > 0 {
            "Approve, revise, or retire the planned validation before execution."
        } else if self.finding_count > 0 && self.validation_count == 0 {
            "Create a validation plan for the highest-value finding."
        } else if self.executed_count > 0 {
            "Review validation output, update finding status, and refresh the report."
        } else if self.service_count > 0 || self.web_count > 0 {
            "Review candidate lanes and record findings for material issues."
        } else {
            "Run operation-aware recon to build evidence for this target."
        }
    }

    fn q(v: &str) -> &str {
        if v.is_empty() { "?" } else { v }
    }

    /// `atlas_brief_report_markdown`.
    pub fn report_markdown(&self) -> Vec<String> {
        let mut out = vec![
            format!(
                "- Surface: host={}, services={}, web={}, lateral={}, posture_findings={}.",
                self.host_state,
                self.service_count,
                self.web_count,
                self.lateral_count,
                self.posture_count
            ),
            format!(
                "- Operation state: evidence={}, findings={}, validation_plans={}.",
                self.evidence_count, self.finding_count, self.validation_count
            ),
            format!(
                "- Validation: planned={}, approved={}, executed={}.",
                self.planned_count, self.approved_count, self.executed_count
            ),
        ];
        if let Some(f) = &self.latest_finding {
            out.push(format!(
                "- Latest finding: {} {}/{}/{} {}.",
                f.id_or(),
                f.severity_or(),
                f.level_or(),
                f.status_or(),
                f.title_or()
            ));
        }
        if let Some(p) = &self.latest_validation {
            out.push(format!(
                "- Latest validation: {} {} {} result={}.",
                Self::q(&p.id),
                Self::q(&p.lane),
                Self::q(&p.status),
                p.result()
            ));
        }
        out.push(format!("- Next step: {}", self.next_step));
        out
    }

    /// `atlas_brief_print_lines` (the `op brief` form).
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![
            format!(
                "Surface: host={}, services={}, web={}, lateral={}, posture_findings={}",
                self.host_state,
                self.service_count,
                self.web_count,
                self.lateral_count,
                self.posture_count
            ),
            format!(
                "Operation State: evidence={}, findings={}, validation_plans={}",
                self.evidence_count, self.finding_count, self.validation_count
            ),
            format!(
                "Validation: planned={}, approved={}, executed={}",
                self.planned_count, self.approved_count, self.executed_count
            ),
        ];
        if let Some(f) = &self.latest_finding {
            out.push(format!(
                "Latest Finding: {} {}/{}/{} {}",
                f.id_or(),
                f.severity_or(),
                f.level_or(),
                f.status_or(),
                f.title_or()
            ));
        }
        if let Some(p) = &self.latest_validation {
            out.push(format!(
                "Latest Validation: {} {} {} result={}",
                Self::q(&p.id),
                Self::q(&p.lane),
                Self::q(&p.status),
                p.result()
            ));
        }
        out.push(format!("Next Step: {}", self.next_step));
        out
    }
}

/// Write the report and append `report.generated`; returns the path.
pub fn write<S: State>(op: &Operation<S>, report_name: &str) -> Result<PathBuf> {
    let name = if report_name.is_empty() {
        format!("{}-report", op.slug)
    } else {
        report_name.to_owned()
    };
    let slug = slugify(&name);
    if slug.is_empty() {
        fail!("report name produced an empty slug");
    }
    let _lock = op.lock()?;
    mkdir_private(&op.root.reports_dir)?;
    let path = op.root.reports_dir.join(format!("{slug}.md"));
    let body = render(op)?;
    write_private(&path, body.as_bytes())?;
    op.append_ledger(
        "report.generated",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &path.display().to_string(),
    )?;
    Ok(path)
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

/// Render the report markdown.
pub fn render<S: State>(op: &Operation<S>) -> Result<String> {
    let snap = op.snapshot()?;
    let (dir, target) = (op.dir.as_path(), op.target.as_str());
    let mut b = String::new();
    b.push_str("# Atlas Operation Report\n\n");
    b.push_str(&format!("Generated: {}\n", clock::timestamp()));
    b.push_str(&format!("Operation: {}\n", op.name));
    b.push_str(&format!("Operation ID: {}\n", op.slug));
    b.push_str(&format!("Target: {}\n", op.target));
    if !op.target_address.is_empty() && op.target_address != op.target {
        b.push_str(&format!("Address: {}\n", op.target_address));
    }
    b.push_str(&format!(
        "Target Scope Status: {}\n",
        or_unknown(&op.scope_status)
    ));
    b.push_str(&format!(
        "Target Criticality: {}\n",
        or_unknown(&op.criticality)
    ));
    if !op.owner.is_empty() {
        b.push_str(&format!("Target Owner: {}\n", op.owner));
    }
    if !op.tags.is_empty() {
        b.push_str(&format!("Target Tags: {}\n", op.tags));
    }
    b.push_str(&format!("Status: {}\n", op.status));
    b.push_str(&format!("Created: {}\n", op.created_at));
    if !op.closed_at.is_empty() {
        b.push_str(&format!("Closed: {}\n", op.closed_at));
    }
    if !op.notes.is_empty() {
        b.push_str(&format!("Notes: {}\n", op.notes));
    }

    b.push_str("\n## Executive Summary\n\n");
    let ev_count = evidence::count(dir, target)?;
    let all = findings::latest(dir, target)?;
    let level_count = |l: &str| all.iter().filter(|f| f.level == l).count();
    let brief = Brief::collect(op)?;
    b.push_str(&format!(
        "This report summarizes the authorized Atlas operation \"{}\" for \"{}\".\n\n",
        op.name, op.target
    ));
    b.push_str(&format!("- Evidence records: {ev_count}\n"));
    b.push_str(&format!(
        "- Findings: {} total, {} observed, {} inferred, {} validated\n",
        all.len(),
        level_count("observed"),
        level_count("inferred"),
        level_count("validated")
    ));
    b.push_str(&format!("- Validation plans: {}\n", brief.validation_count));
    b.push_str(&format!(
        "- Highest recorded severity: {}\n",
        findings::highest_severity(dir, target)?
    ));
    b.push_str(&format!("- Recommended next step: {}\n", brief.next_step));

    b.push_str("\n## Operator Brief\n\n");
    b.push_str(&brief.report_markdown().join("\n"));
    b.push('\n');

    b.push_str("\n## Finding Review\n\n");
    for (level, title) in [
        ("observed", "Observed"),
        ("inferred", "Inferred"),
        ("validated", "Validated"),
    ] {
        b.push_str(&format!("### {title}\n\n"));
        let rows = findings::by_level(dir, target, level)?;
        if rows.is_empty() {
            b.push_str(&format!("- No {level} findings recorded.\n"));
        } else {
            for f in &rows {
                b.push_str(&f.review_line());
                b.push('\n');
            }
        }
        b.push('\n');
    }

    b.push_str("\n## Remediation Priorities\n\n");
    let mut with_rec: Vec<&Finding> = all
        .iter()
        .filter(|f| !f.recommendation.is_empty())
        .collect();
    if with_rec.is_empty() {
        b.push_str("- No remediation priorities recorded yet.\n");
    } else {
        // jq sort_by([severity_weight, updated/created]) | reverse
        with_rec.sort_by(|x, y| {
            findings::severity_weight(x.severity_or())
                .cmp(&findings::severity_weight(y.severity_or()))
                .then_with(|| x.updated_or_created().cmp(y.updated_or_created()))
        });
        with_rec.reverse();
        for f in with_rec {
            b.push_str(&format!(
                "- [{}] {}: {}",
                f.severity_or(),
                f.title_or(),
                f.recommendation
            ));
            if !f.evidence.is_empty() {
                b.push_str(&format!(" Evidence: {}.", f.evidence.join(", ")));
            }
            b.push('\n');
        }
    }

    b.push_str("\n## Scope\n\n");
    b.push_str(&snap.text);
    b.push_str("\n\n## Allowed Actions\n\n");
    for l in snap.allowed_action_lines() {
        b.push_str(&format!("- {l}\n"));
    }
    b.push_str("\n## Explicitly Out Of Scope\n\n");
    for l in snap.out_of_scope_lines() {
        b.push_str(&format!("- {l}\n"));
    }
    b.push_str("\n## Commands Run\n\n");
    for l in commands_run(op) {
        b.push_str(&format!("- `{l}`\n"));
    }
    b.push_str("\n## Artifacts\n\n");
    b.push_str(&format!("- Operation directory: `{}`\n", op.dir.display()));
    let recon: Vec<String> = evidence::latest(dir, target)?
        .iter()
        .filter(|r| r.kind == evidence::KIND_ADAPTER_OUTPUT)
        .map(|r| {
            format!(
                "- Recon artifact: {} `{}` sha256={}\n",
                r.id, r.path, r.sha256
            )
        })
        .collect();
    if recon.is_empty() {
        b.push_str("- No recon or action artifacts tracked yet.\n");
    } else {
        for l in recon {
            b.push_str(&l);
        }
    }
    b.push_str("\n## Validation Plans\n\n");
    b.push_str("- No validation plans recorded yet.\n");
    b.push_str("\n## Notes\n\n");
    b.push_str("- Add operator notes here.\n");
    Ok(b)
}

/// The "Commands Run" lines, reconstructed from `notes/history.log` as the
/// shell build does (it prints `atlas ...` whichever build ran them).
fn commands_run<S: State>(op: &Operation<S>) -> Vec<String> {
    let entries = history::read(&op.dir);
    if entries.is_empty() {
        return vec![format!("atlas op start {} {}", op.slug, op.target)];
    }
    entries
        .iter()
        .map(|e| match e.event.as_str() {
            "start" if !op.notes.is_empty() => {
                format!("atlas op start {} {} {}", op.slug, op.target, op.notes)
            }
            "start" => format!("atlas op start {} {}", op.slug, op.target),
            "resume" => format!("atlas op resume {}", op.slug),
            "close" => format!("atlas op close {}", op.slug),
            ev @ ("handoff" | "closeout" | "audit-packet" | "archive-packet") => {
                let base = std::path::Path::new(&e.detail)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if let Some(stem) = base.strip_suffix(".json") {
                    format!("atlas op {ev} --json {} {stem}", op.slug)
                } else {
                    format!(
                        "atlas op {ev} {} {}",
                        op.slug,
                        base.strip_suffix(".md").unwrap_or(&base)
                    )
                }
            }
            other => format!("atlas op {other}"),
        })
        .collect()
}
