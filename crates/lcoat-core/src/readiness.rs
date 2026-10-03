//! Close readiness and packet freshness, derived from the ledger by the
//! rules in the shell build's `readiness.sh`.
//!
//! Everything is computed from events and indexes already on disk; nothing
//! here writes. The `op close` writer (phase 2) records
//! [`State::ledger_detail`] as the `op.close.readiness` event.

use lcoat_format::clock;

use crate::error::Result;
use crate::evidence;
use crate::findings::{self, Finding};
use crate::ledger::{self, Event};
use crate::operation::Operation;
use crate::validation::{self, Plan};

/// A ledger event of interest, or its absence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Marker {
    /// Timestamp (empty when absent).
    pub at: String,
    /// 1-based ledger line.
    pub line: usize,
    /// Event name.
    pub event: String,
    /// Event detail (a path, for packet events).
    pub detail: String,
}

impl Marker {
    /// Whether the event exists in the ledger.
    pub fn present(&self) -> bool {
        !self.at.is_empty()
    }

    fn of(e: Option<&Event>) -> Self {
        match e {
            None => Self::default(),
            Some(e) => Self {
                at: e.ts.clone(),
                line: e.line,
                event: e.event.clone(),
                detail: e.detail.clone(),
            },
        }
    }

    /// The detail (a path) or `fallback`.
    pub fn path_or<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.detail.is_empty() {
            fallback
        } else {
            &self.detail
        }
    }
}

fn after(candidate: &Marker, baseline: &Marker) -> bool {
    if !candidate.present() || !baseline.present() {
        return false;
    }
    candidate.at > baseline.at
        || (candidate.at == baseline.at
            && candidate.line > 0
            && baseline.line > 0
            && candidate.line > baseline.line)
}

/// `missing`, `stale` or `current`.
pub fn freshness(packet: &Marker, changes: &[&Marker]) -> &'static str {
    if !packet.present() {
        return "missing";
    }
    if changes.iter().any(|c| after(c, packet)) {
        return "stale";
    }
    "current"
}

/// Events that change the operation's material state.
pub const MATERIAL_EVENTS: &[&str] = &[
    "tool.completed",
    "artifact.created",
    "artifact.redacted",
    "finding.recorded",
    "finding.updated",
    "finding.accepted",
    "finding.reviewed",
    "approval.granted",
    "validation.planned",
    "validation.approved",
    "validation.executed",
    "validation.retested",
];

const REVIEW_CHANGE_EVENTS: &[&str] = &[
    "finding.recorded",
    "finding.updated",
    "finding.accepted",
    "finding.reviewed",
];

/// The collected readiness values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct State {
    pub evidence_count: usize,
    pub finding_count: usize,
    pub validation_count: usize,
    pub open_count: usize,
    pub accepted_count: usize,
    pub expired_accepted: usize,
    pub pending_count: usize,
    pub report: Marker,
    pub bundle: Marker,
    pub handoff: Marker,
    pub closeout: Marker,
    pub audit_packet: Marker,
    pub archive_packet: Marker,
    pub review_packet: Marker,
    pub latest_ledger: Marker,
    pub latest_change: Marker,
    pub latest_evidence: Marker,
    pub latest_review_change: Marker,
    pub report_fresh: &'static str,
    pub bundle_fresh: &'static str,
    pub handoff_fresh: &'static str,
    pub closeout_fresh: &'static str,
    pub audit_fresh: &'static str,
    pub archive_fresh: &'static str,
    pub review_fresh: &'static str,
    /// `ready` or `attention-required`.
    pub status: &'static str,
    pub next_step: &'static str,
    pub open_findings: Vec<Finding>,
    pub expired: Vec<Finding>,
    pub pending: Vec<Plan>,
}

/// Compute readiness for the operation's own target.
pub fn collect(op: &Operation) -> Result<State> {
    let target = op.target.as_str();
    let dir = op.dir.as_path();
    let mut s = State {
        evidence_count: evidence::count(dir, target)?,
        finding_count: findings::count(dir, target)?,
        validation_count: validation::count(dir, target)?,
        open_findings: findings::open(dir, target)?,
        accepted_count: findings::accepted(dir, target)?.len(),
        expired: findings::expired_accepted(dir, target, &clock::today())?,
        pending: validation::pending(dir, target)?,
        ..Default::default()
    };
    s.open_count = s.open_findings.len();
    s.expired_accepted = s.expired.len();
    s.pending_count = s.pending.len();

    let events = ledger::read(dir)?;
    let latest = |names: &[&str]| Marker::of(ledger::latest(&events, names));
    s.report = latest(&["report.generated"]);
    s.bundle = latest(&["evidence.bundle.generated"]);
    s.handoff = latest(&["handoff.generated"]);
    s.closeout = latest(&["closeout.manifest.generated"]);
    s.audit_packet = latest(&["audit.packet.generated"]);
    s.archive_packet = latest(&["archive.packet.generated"]);
    s.review_packet = latest(&["finding.review_packet.generated"]);
    s.latest_ledger = Marker::of(events.last());
    s.latest_change = latest(MATERIAL_EVENTS);
    s.latest_evidence = latest(&["artifact.created", "artifact.redacted"]);
    s.latest_review_change = latest(REVIEW_CHANGE_EVENTS);
    let audit_change = Marker::of(ledger::latest_except(
        &events,
        &["archive.packet.generated"],
    ));

    s.report_fresh = freshness(&s.report, &[&s.latest_change]);
    s.bundle_fresh = freshness(&s.bundle, &[&s.latest_evidence]);
    s.handoff_fresh = freshness(&s.handoff, &[&s.latest_change, &s.report, &s.bundle]);
    s.closeout_fresh = freshness(
        &s.closeout,
        &[&s.latest_change, &s.report, &s.bundle, &s.handoff],
    );
    s.audit_fresh = freshness(&s.audit_packet, &[&audit_change]);
    s.archive_fresh = freshness(&s.archive_packet, &[&s.latest_ledger]);
    s.review_fresh = freshness(&s.review_packet, &[&s.latest_review_change]);

    s.status = if s.pending_count > 0
        || s.open_count > 0
        || s.expired_accepted > 0
        || s.evidence_count == 0
        || !s.report.present()
        || s.report_fresh == "stale"
    {
        "attention-required"
    } else {
        "ready"
    };
    s.next_step = s.next_step();
    Ok(s)
}

impl State {
    fn next_step(&self) -> &'static str {
        if self.pending_count > 0 {
            "Run or retire pending validation before closure."
        } else if self.open_count > 0 {
            "Resolve, accept, or retest unresolved findings before closure."
        } else if self.expired_accepted > 0 {
            "Review expired accepted risks before closure."
        } else if self.evidence_count == 0 {
            "Add at least one evidence record before closure."
        } else if !self.report.present() {
            "Generate an operation report before closure."
        } else if self.report_fresh == "stale" {
            "Refresh the operation report before closure."
        } else if !self.bundle.present() {
            "Operation is ready to close; generate an evidence bundle if handoff is required."
        } else if self.bundle_fresh == "stale" {
            "Operation is ready to close; regenerate the evidence bundle if handoff is required."
        } else if !self.handoff.present() {
            "Operation is ready to close; generate a handoff packet if handoff is required."
        } else if self.handoff_fresh == "stale" {
            "Operation is ready to close; regenerate the handoff packet if handoff is required."
        } else if !self.closeout.present() {
            "Operation is ready to close; generate a closeout manifest after closure if final audit is required."
        } else if self.closeout_fresh == "stale" {
            "Operation is ready to close; regenerate the closeout manifest if final audit is required."
        } else if !self.audit_packet.present() {
            "Operation is ready to close; generate an audit packet if final audit is required."
        } else if self.audit_fresh == "stale" {
            "Operation is ready to close; regenerate the audit packet if final audit is required."
        } else if !self.archive_packet.present() {
            "Operation is ready to close; generate an archive packet if final retention is required."
        } else if self.archive_fresh == "stale" {
            "Operation is ready to close; regenerate the archive packet if final retention is required."
        } else {
            "Operation is ready to close."
        }
    }

    /// `atlas_readiness_ledger_detail`: the `op.close.readiness` detail.
    pub fn ledger_detail(&self, force: bool) -> String {
        let none = |v: &str| {
            if v.is_empty() {
                "none".to_owned()
            } else {
                v.to_owned()
            }
        };
        format!(
            "readiness={} evidence={} open_findings={} accepted_risks={} expired_accepted_risks={} pending_validation={} report_freshness={} bundle_freshness={} handoff_freshness={} closeout_freshness={} review_packet_freshness={} audit_packet_freshness={} archive_packet_freshness={} latest_report={} latest_change={} evidence_bundle={} handoff={} closeout={} review_packet={} audit_packet={} archive_packet={} force={}",
            self.status,
            self.evidence_count,
            self.open_count,
            self.accepted_count,
            self.expired_accepted,
            self.pending_count,
            self.report_fresh,
            self.bundle_fresh,
            self.handoff_fresh,
            self.closeout_fresh,
            self.review_fresh,
            self.audit_fresh,
            self.archive_fresh,
            self.report.path_or("none"),
            none(&self.latest_change.event),
            self.bundle.path_or("none"),
            self.handoff.path_or("none"),
            self.closeout.path_or("none"),
            self.review_packet.path_or("none"),
            self.audit_packet.path_or("none"),
            self.archive_packet.path_or("none"),
            u8::from(force)
        )
    }

    /// The "Operation Readiness" block the shell build prints.
    pub fn lines(&self, op: &Operation) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let marker_or = |m: &Marker| {
            if m.present() {
                format!("{} {}", m.at, m.detail)
            } else {
                "none generated yet".to_owned()
            }
        };
        let change_or = |m: &Marker| {
            if m.present() {
                format!("{} {}", m.at, m.event)
            } else {
                "none".to_owned()
            }
        };
        out.push("Operation Readiness".into());
        out.push(RULE.into());
        let mut add = |k: &str, v: String| out.push(format!("{k}: {v}"));
        add("Operation", op.name.clone());
        add("Operation Status", op.status.clone());
        add("Target", op.target.clone());
        add("Evidence Records", self.evidence_count.to_string());
        add("Findings", self.finding_count.to_string());
        add("Open Findings", self.open_count.to_string());
        add("Accepted Risks", self.accepted_count.to_string());
        add("Expired Accepted Risks", self.expired_accepted.to_string());
        add("Validation Plans", self.validation_count.to_string());
        add("Pending Validation", self.pending_count.to_string());
        add("Latest Report", marker_or(&self.report));
        add("Report Freshness", self.report_fresh.into());
        add("Latest State Change", change_or(&self.latest_change));
        add("Evidence Bundle", marker_or(&self.bundle));
        add("Bundle Freshness", self.bundle_fresh.into());
        add("Latest Evidence Change", change_or(&self.latest_evidence));
        add("Latest Handoff", marker_or(&self.handoff));
        add("Handoff Freshness", self.handoff_fresh.into());
        add("Latest Closeout", marker_or(&self.closeout));
        add("Closeout Freshness", self.closeout_fresh.into());
        add(
            "Latest Accepted Risk Review Packet",
            marker_or(&self.review_packet),
        );
        add(
            "Accepted Risk Review Packet Freshness",
            self.review_fresh.into(),
        );
        add(
            "Latest Accepted Risk Change",
            change_or(&self.latest_review_change),
        );
        add("Latest Audit Packet", marker_or(&self.audit_packet));
        add("Audit Packet Freshness", self.audit_fresh.into());
        add("Latest Archive Packet", marker_or(&self.archive_packet));
        add("Archive Packet Freshness", self.archive_fresh.into());
        add(
            "Latest Ledger Event",
            if self.latest_ledger.present() {
                format!("{} {}", self.latest_ledger.at, self.latest_ledger.event)
            } else {
                "none".into()
            },
        );
        add("Close Readiness", self.status.into());
        add("Next Step", self.next_step.into());
        out.push(RULE.into());
        out.push("Open Findings".into());
        if self.open_findings.is_empty() {
            out.push("note: no unresolved findings remain".into());
        }
        for f in self.open_findings.iter().take(8) {
            out.push(format!(
                "{:<24} {:<8} {:<10} {:<10} {}",
                f.id_or(),
                f.severity_or(),
                f.level_or(),
                f.status_or(),
                f.title_or()
            ));
        }
        out.push(RULE.into());
        out.push("Expired Accepted Risks".into());
        if self.expired.is_empty() {
            out.push("note: no expired accepted risks detected".into());
        }
        for f in self.expired.iter().take(8) {
            let owner = if f.accepted_owner.is_empty() {
                "-"
            } else {
                &f.accepted_owner
            };
            let reason = if f.accepted_reason.is_empty() {
                "-"
            } else {
                &f.accepted_reason
            };
            out.push(format!(
                "{:<24} {:<8} {:<10} expires={:<10} owner={:<12} {} reason={}",
                f.id_or(),
                f.severity_or(),
                f.level_or(),
                f.accepted_date(),
                owner,
                f.title_or(),
                reason
            ));
        }
        out.push(RULE.into());
        out.push("Pending Validation".into());
        if self.pending.is_empty() {
            out.push("note: no planned or approved validation is waiting".into());
        }
        for p in self.pending.iter().take(8) {
            let finding = if p.finding.is_empty() {
                "-"
            } else {
                &p.finding
            };
            let q = |v: &str| {
                if v.is_empty() {
                    "?".to_owned()
                } else {
                    v.to_owned()
                }
            };
            out.push(format!(
                "{:<24} {:<12} {:<10} {:<24} {}",
                q(&p.id),
                q(&p.lane),
                q(&p.status),
                finding,
                p.reason
            ));
        }
        out
    }
}

/// The 60-dash rule the shell build prints.
pub const RULE: &str = "------------------------------------------------------------";

/// Lines joined with newlines, trailing newline included.
pub fn join(lines: &[String]) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(at: &str, line: usize) -> Marker {
        Marker {
            at: at.into(),
            line,
            event: "e".into(),
            detail: String::new(),
        }
    }

    #[test]
    fn freshness_rules() {
        let none = Marker::default();
        assert_eq!(freshness(&none, &[]), "missing");
        let packet = m("2026-01-02T00:00:00Z", 5);
        assert_eq!(
            freshness(&packet, &[&m("2026-01-01T00:00:00Z", 1)]),
            "current"
        );
        assert_eq!(
            freshness(&packet, &[&m("2026-01-03T00:00:00Z", 1)]),
            "stale"
        );
        // Same second: the later line wins.
        assert_eq!(
            freshness(&packet, &[&m("2026-01-02T00:00:00Z", 6)]),
            "stale"
        );
        assert_eq!(
            freshness(&packet, &[&m("2026-01-02T00:00:00Z", 4)]),
            "current"
        );
        assert_eq!(freshness(&packet, &[&none]), "current");
    }

    #[test]
    fn next_step_order() {
        let mut s = State {
            evidence_count: 1,
            report: m("t", 1),
            ..Default::default()
        };
        s.report_fresh = "current";
        assert_eq!(
            s.next_step(),
            "Operation is ready to close; generate an evidence bundle if handoff is required."
        );
        s.open_count = 1;
        assert_eq!(
            s.next_step(),
            "Resolve, accept, or retest unresolved findings before closure."
        );
        s.pending_count = 1;
        assert_eq!(
            s.next_step(),
            "Run or retire pending validation before closure."
        );
        let s = State::default();
        assert_eq!(
            s.next_step(),
            "Add at least one evidence record before closure."
        );
    }
}
