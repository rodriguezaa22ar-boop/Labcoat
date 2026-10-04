//! `findings.ndjson`: the count, sort and render questions the packets and
//! readiness ask about findings.
//!
//! Every ordering here reproduces a jq expression from the shell build
//! (`sort_by(...) | reverse` is a stable ascending sort followed by a
//! reverse, ties included), so three implementations print the same rows.
//! Writing: [`add`] records a finding; [`update`] appends a full record with
//! the same id (the readers take the latest), which is how `resolve`,
//! `accept`, `reopen` and `note` work, as in the shell build. Only an
//! [`Operation<Active>`] can write, and every free-text field arrives as
//! [`MetadataOnly`].

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::fsutil::mkdir_private;
use lcoat_format::ids::next_id;
use lcoat_format::json::{Object, Value};
use lcoat_format::ndjson;

use crate::error::Result;
use crate::fail;
use crate::metadata::MetadataOnly;
use crate::operation::{Active, Operation};
use crate::root::TOOL_NAME;
use crate::tier::Tier;

/// `findings.ndjson` for an operation directory.
pub fn index_file(op_dir: &Path) -> PathBuf {
    op_dir.join("findings.ndjson")
}

/// `findings/`, used only to claim IDs.
pub fn dir(op_dir: &Path) -> PathBuf {
    op_dir.join("findings")
}

/// The latest state of one finding. Optional fields written by the shell
/// build's lifecycle commands (update, accept, review) are kept so packets
/// render those sessions faithfully.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Finding {
    /// `finding_<timestamp>`
    pub id: String,
    /// Operation slug.
    pub operation: String,
    /// Target.
    pub target: String,
    /// Title.
    pub title: String,
    /// `observed`, `inferred`, `validated`.
    pub level: String,
    /// `info`, `low`, `medium`, `high`, `critical`.
    pub severity: String,
    /// `low`, `medium`, `high`.
    pub confidence: String,
    /// `open`, `accepted`, `resolved`, `validated`.
    pub status: String,
    /// Recording tool.
    pub source: String,
    /// Impact statement.
    pub impact: String,
    /// Recommendation.
    pub recommendation: String,
    /// Evidence IDs.
    pub evidence: Vec<String>,
    /// Validation plan IDs.
    pub validations: Vec<String>,
    /// Recorded at.
    pub created_at: String,
    /// Last update.
    pub updated_at: String,
    /// Accepted-risk reason.
    pub accepted_reason: String,
    /// Accepted-risk owner.
    pub accepted_owner: String,
    /// Accepted-risk expiry (`YYYY-MM-DD` or timestamp).
    pub accepted_until: String,
    /// When accepted.
    pub accepted_at: String,
    /// Who accepted.
    pub accepted_by: String,
    /// Review reason.
    pub review_reason: String,
    /// When reviewed.
    pub reviewed_at: String,
    /// Reviewer.
    pub reviewed_by: String,
    /// Latest note.
    pub note: String,
}

/// Valid finding levels.
pub fn valid_level(s: &str) -> bool {
    matches!(s, "observed" | "inferred" | "validated")
}

/// Valid severities.
pub fn valid_severity(s: &str) -> bool {
    matches!(s, "info" | "low" | "medium" | "high" | "critical")
}

/// Valid confidences.
pub fn valid_confidence(s: &str) -> bool {
    matches!(s, "low" | "medium" | "high")
}

/// Valid statuses.
pub fn valid_status(s: &str) -> bool {
    matches!(s, "open" | "accepted" | "resolved" | "validated")
}

/// The jq `severity_weight` helper.
pub fn severity_weight(s: &str) -> i32 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn or<'a>(v: &'a str, fallback: &'a str) -> &'a str {
    if v.is_empty() { fallback } else { v }
}

impl Finding {
    /// Decode from an index object.
    pub fn from_object(o: &Object) -> Self {
        Self {
            id: o.str("id").to_owned(),
            operation: o.str("operation").to_owned(),
            target: o.str("target").to_owned(),
            title: o.str("title").to_owned(),
            level: o.str("level").to_owned(),
            severity: o.str("severity").to_owned(),
            confidence: o.str("confidence").to_owned(),
            status: o.str("status").to_owned(),
            source: o.str("source").to_owned(),
            impact: o.str("impact").to_owned(),
            recommendation: o.str("recommendation").to_owned(),
            evidence: o.strs("evidence"),
            validations: o.strs("validations"),
            created_at: o.str("created_at").to_owned(),
            updated_at: o.str("updated_at").to_owned(),
            accepted_reason: o.str("accepted_reason").to_owned(),
            accepted_owner: o.str("accepted_owner").to_owned(),
            accepted_until: o.str("accepted_until").to_owned(),
            accepted_at: o.str("accepted_at").to_owned(),
            accepted_by: o.str("accepted_by").to_owned(),
            review_reason: o.str("review_reason").to_owned(),
            reviewed_at: o.str("reviewed_at").to_owned(),
            reviewed_by: o.str("reviewed_by").to_owned(),
            note: o.str("note").to_owned(),
        }
    }

    /// `.severity // "info"`
    pub fn severity_or(&self) -> &str {
        or(&self.severity, "info")
    }
    /// `.level // "inferred"`
    pub fn level_or(&self) -> &str {
        or(&self.level, "inferred")
    }
    /// `.status // "open"`
    pub fn status_or(&self) -> &str {
        or(&self.status, "open")
    }
    /// `.confidence // "medium"`
    pub fn confidence_or(&self) -> &str {
        or(&self.confidence, "medium")
    }
    /// `.title // "untitled finding"`
    pub fn title_or(&self) -> &str {
        or(&self.title, "untitled finding")
    }
    /// `.id // "?"`
    pub fn id_or(&self) -> &str {
        or(&self.id, "?")
    }
    /// `.updated_at // .created_at // ""`
    pub fn updated_or_created(&self) -> &str {
        or(&self.updated_at, &self.created_at)
    }
    /// The first ten characters of `accepted_until` (the date part).
    pub fn accepted_date(&self) -> &str {
        if self.accepted_until.len() >= 10 {
            &self.accepted_until[..10]
        } else {
            &self.accepted_until
        }
    }

    /// The jq rendering in `atlas_findings_report_markdown`.
    pub fn report_line(&self) -> String {
        let mut b = format!(
            "- {} / {} / {}: {}",
            self.severity_or(),
            self.level_or(),
            self.status_or(),
            self.title_or()
        );
        self.push_common(&mut b);
        if !self.accepted_reason.is_empty() {
            b.push_str(&format!(" Accepted risk: {}.", self.accepted_reason));
            if !self.accepted_owner.is_empty() {
                b.push_str(&format!(" Owner: {}.", self.accepted_owner));
            }
            if !self.accepted_until.is_empty() {
                b.push_str(&format!(" Accepted until: {}.", self.accepted_until));
            }
            if !self.accepted_by.is_empty() {
                b.push_str(&format!(" Accepted by: {}.", self.accepted_by));
            }
            if !self.review_reason.is_empty() {
                b.push_str(&format!(" Risk review: {}.", self.review_reason));
            }
            if !self.reviewed_by.is_empty() {
                b.push_str(&format!(" Reviewed by: {}.", self.reviewed_by));
            }
        }
        if !self.note.is_empty() {
            b.push_str(&format!(" Latest note: {}.", self.note));
        }
        b
    }

    /// The awk rendering in `atlas_report_print_finding_level`.
    pub fn review_line(&self) -> String {
        let mut b = format!(
            "- {} / {} / {}: {}",
            self.severity_or(),
            self.confidence_or(),
            self.status_or(),
            self.title_or()
        );
        self.push_common(&mut b);
        for (label, v) in [
            ("Accepted risk", &self.accepted_reason),
            ("Owner", &self.accepted_owner),
            ("Accepted until", &self.accepted_until),
            ("Accepted by", &self.accepted_by),
            ("Risk review", &self.review_reason),
            ("Reviewed by", &self.reviewed_by),
            ("Latest note", &self.note),
        ] {
            if !v.is_empty() {
                b.push_str(&format!(" {label}: {v}."));
            }
        }
        b
    }

    fn push_common(&self, b: &mut String) {
        if !self.impact.is_empty() {
            b.push_str(&format!(" Impact: {}.", self.impact));
        }
        if !self.recommendation.is_empty() {
            b.push_str(&format!(" Recommendation: {}.", self.recommendation));
        }
        if !self.evidence.is_empty() {
            b.push_str(&format!(" Evidence: {}.", self.evidence.join(", ")));
        }
        if !self.validations.is_empty() {
            b.push_str(&format!(
                " Validation plans: {}.",
                self.validations.join(", ")
            ));
        }
    }
}

/// The newest record per ID, filtered to `target` when non-empty, in
/// first-seen order.
pub fn latest(op_dir: &Path, target: &str) -> Result<Vec<Finding>> {
    let recs = ndjson::read_file(&index_file(op_dir))?;
    Ok(ndjson::latest(&recs)
        .iter()
        .map(Finding::from_object)
        .filter(|f| target.is_empty() || f.target == target)
        .collect())
}

/// `atlas_findings_count_for_target`.
pub fn count(op_dir: &Path, target: &str) -> Result<usize> {
    Ok(latest(op_dir, target)?.len())
}

/// jq `sort_by(...) | reverse`: stable ascending sort, then reverse.
fn sort_reverse(fs: &mut [Finding], cmp: impl Fn(&Finding, &Finding) -> Ordering) {
    fs.sort_by(|a, b| cmp(a, b));
    fs.reverse();
}

fn by_updated_then_id(a: &Finding, b: &Finding) -> Ordering {
    a.updated_or_created()
        .cmp(b.updated_or_created())
        .then_with(|| a.id.cmp(&b.id))
}

fn by_weight(a: &Finding, b: &Finding) -> Ordering {
    severity_weight(a.severity_or()).cmp(&severity_weight(b.severity_or()))
}

/// `atlas_readiness_open_findings_rows`: not resolved, not accepted; by
/// severity weight, updated/created, id; reversed.
pub fn open(op_dir: &Path, target: &str) -> Result<Vec<Finding>> {
    let mut out: Vec<Finding> = latest(op_dir, target)?
        .into_iter()
        .filter(|f| !matches!(f.status_or(), "resolved" | "accepted"))
        .collect();
    sort_reverse(&mut out, |a, b| {
        by_weight(a, b).then_with(|| by_updated_then_id(a, b))
    });
    Ok(out)
}

/// Findings whose status is `accepted`.
pub fn accepted(op_dir: &Path, target: &str) -> Result<Vec<Finding>> {
    Ok(latest(op_dir, target)?
        .into_iter()
        .filter(|f| f.status_or() == "accepted")
        .collect())
}

/// `atlas_readiness_expired_accepted_risk_rows`: accepted findings whose
/// `accepted_until` date is before `today`.
pub fn expired_accepted(op_dir: &Path, target: &str, today: &str) -> Result<Vec<Finding>> {
    let mut out: Vec<Finding> = accepted(op_dir, target)?
        .into_iter()
        .filter(|f| {
            let until = f.accepted_date();
            !until.is_empty() && until < today
        })
        .collect();
    sort_reverse(&mut out, |a, b| {
        a.accepted_date()
            .cmp(b.accepted_date())
            .then_with(|| by_weight(a, b))
            .then_with(|| by_updated_then_id(a, b))
    });
    Ok(out)
}

/// `atlas_findings_rows_for_target`: updated/created then id, reversed,
/// limited when `limit > 0`.
pub fn rows(op_dir: &Path, target: &str, limit: usize) -> Result<Vec<Finding>> {
    let mut fs = latest(op_dir, target)?;
    sort_reverse(&mut fs, by_updated_then_id);
    if limit > 0 {
        fs.truncate(limit);
    }
    Ok(fs)
}

/// `atlas_report_finding_rows_by_level`: severity weight then
/// updated/created, reversed.
pub fn by_level(op_dir: &Path, target: &str, level: &str) -> Result<Vec<Finding>> {
    let mut out: Vec<Finding> = latest(op_dir, target)?
        .into_iter()
        .filter(|f| f.level == level)
        .collect();
    sort_reverse(&mut out, |a, b| {
        by_weight(a, b).then_with(|| a.updated_or_created().cmp(b.updated_or_created()))
    });
    Ok(out)
}

/// `atlas_brief_latest_finding`: by updated/created then id, last.
pub fn latest_finding(op_dir: &Path, target: &str) -> Result<Option<Finding>> {
    let mut fs = latest(op_dir, target)?;
    fs.sort_by(by_updated_then_id);
    Ok(fs.pop())
}

/// `atlas_report_highest_severity`: `none` without findings, else the
/// heaviest severity (last among equals).
pub fn highest_severity(op_dir: &Path, target: &str) -> Result<String> {
    let fs = latest(op_dir, target)?;
    if fs.is_empty() {
        return Ok("none".into());
    }
    let mut best = "";
    let mut best_w = -1;
    for f in &fs {
        let w = severity_weight(f.severity_or());
        if w >= best_w {
            best_w = w;
            best = f.severity_or();
        }
    }
    Ok(best.to_owned())
}

/// `atlas_findings_report_markdown`: ascending by updated/created then id,
/// no target filter.
pub fn report_markdown(op_dir: &Path) -> Result<Vec<String>> {
    let mut fs = latest(op_dir, "")?;
    if fs.is_empty() {
        return Ok(vec!["- No reviewed findings recorded yet.".into()]);
    }
    fs.sort_by(by_updated_then_id);
    Ok(fs.iter().map(Finding::report_line).collect())
}

// --- writers ----------------------------------------------------------------

fn strs(items: &[String]) -> Value {
    Value::Array(items.iter().map(|x| Value::String(x.clone())).collect())
}

impl Finding {
    /// The `finding add` record, in the shell build's field order.
    fn to_add_object(&self) -> Object {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("id", s(&self.id));
        o.insert("operation", s(&self.operation));
        o.insert("target", s(&self.target));
        o.insert("title", s(&self.title));
        o.insert("level", s(&self.level));
        o.insert("severity", s(&self.severity));
        o.insert("confidence", s(&self.confidence));
        o.insert("status", s(&self.status));
        o.insert("source", s(&self.source));
        o.insert("impact", s(&self.impact));
        o.insert("recommendation", s(&self.recommendation));
        o.insert("evidence", strs(&self.evidence));
        o.insert("created_at", s(&self.created_at));
        o
    }

    /// The `finding update` record (`atlas_findings_append_update_record`):
    /// every field, `event: updated`, then the accepted/review fields that
    /// are non-empty, in the shell's order.
    fn to_update_object(&self) -> Object {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("id", s(&self.id));
        o.insert("operation", s(&self.operation));
        o.insert("target", s(&self.target));
        o.insert("title", s(&self.title));
        o.insert("level", s(&self.level));
        o.insert("severity", s(&self.severity));
        o.insert("confidence", s(&self.confidence));
        o.insert("status", s(&self.status));
        o.insert("source", s(&self.source));
        o.insert("impact", s(&self.impact));
        o.insert("recommendation", s(&self.recommendation));
        o.insert("evidence", strs(&self.evidence));
        o.insert("validations", strs(&self.validations));
        o.insert("created_at", s(&self.created_at));
        o.insert("updated_at", s(&self.updated_at));
        o.insert("event", s("updated"));
        o.insert("note", s(&self.note));
        for (k, v) in [
            ("accepted_reason", &self.accepted_reason),
            ("accepted_owner", &self.accepted_owner),
            ("accepted_until", &self.accepted_until),
            ("accepted_at", &self.accepted_at),
            ("accepted_by", &self.accepted_by),
            ("review_reason", &self.review_reason),
            ("reviewed_at", &self.reviewed_at),
            ("reviewed_by", &self.reviewed_by),
        ] {
            if !v.is_empty() {
                o.insert(k, s(v));
            }
        }
        o
    }
}

/// Inputs to [`add`]. Empty optional fields take the shell build's
/// defaults (`inferred`, `info`, `medium`, `atlas`; status `open`, or
/// `validated` when the level is `validated`).
#[derive(Clone, Debug, Default)]
pub struct AddParams {
    /// Required.
    pub title: Option<MetadataOnly>,
    /// The operation's target when `None`.
    pub target: Option<MetadataOnly>,
    /// `observed`, `inferred`, `validated`.
    pub level: String,
    /// `info`, `low`, `medium`, `high`, `critical`.
    pub severity: String,
    /// `low`, `medium`, `high`.
    pub confidence: String,
    /// `open`, `accepted`, `resolved`, `validated`.
    pub status: String,
    /// Recording tool.
    pub source: String,
    /// Impact statement.
    pub impact: Option<MetadataOnly>,
    /// Recommendation.
    pub recommendation: Option<MetadataOnly>,
    /// Evidence IDs that must exist in the operation.
    pub evidence: Vec<String>,
}

fn text(v: &Option<MetadataOnly>) -> String {
    v.as_ref()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default()
}

/// `cmd_finding_add`: validate, preflight (read-only), check the evidence
/// IDs, claim an ID, append the record, append `finding.recorded`.
pub fn add(op: &Operation<Active>, p: &AddParams) -> Result<Finding> {
    let title = text(&p.title);
    if title.is_empty() {
        fail!("finding title is required");
    }
    let level = or(&p.level, "inferred");
    let severity = or(&p.severity, "info");
    let confidence = or(&p.confidence, "medium");
    let source = or(&p.source, TOOL_NAME);
    if !valid_level(level) {
        fail!("expected finding level observed, inferred, or validated; got: {level}");
    }
    if !valid_severity(severity) {
        fail!("expected severity info, low, medium, high, or critical; got: {severity}");
    }
    if !valid_confidence(confidence) {
        fail!("expected confidence low, medium, or high; got: {confidence}");
    }
    let status = if p.status.is_empty() {
        if level == "validated" {
            "validated"
        } else {
            "open"
        }
    } else {
        p.status.as_str()
    };
    if !valid_status(status) {
        fail!("expected status open, accepted, resolved, or validated; got: {status}");
    }
    let target = p
        .target
        .as_ref()
        .map_or(op.target.as_str(), MetadataOnly::as_str)
        .to_owned();

    let _lock = op.lock()?;
    op.preflight(Tier::ReadOnly, TOOL_NAME, &target, "record finding")?
        .into_result()?;
    let mut evidence_ids = Vec::new();
    for id in p.evidence.iter().filter(|id| !id.is_empty()) {
        if !crate::evidence::exists(&op.dir, id)? {
            fail!("unknown evidence id for active operation: {id}");
        }
        evidence_ids.push(id.clone());
    }
    let root = dir(&op.dir);
    mkdir_private(&root)?;
    let id = next_id(&root, "finding");
    mkdir_private(&root.join(&id))?;
    crate::crash::point("finding.claimed");
    let f = Finding {
        id: id.clone(),
        operation: op.slug.clone(),
        target,
        title,
        level: level.to_owned(),
        severity: severity.to_owned(),
        confidence: confidence.to_owned(),
        status: status.to_owned(),
        source: source.to_owned(),
        impact: text(&p.impact),
        recommendation: text(&p.recommendation),
        evidence: evidence_ids,
        created_at: clock::timestamp(),
        ..Default::default()
    };
    ndjson::append(&index_file(&op.dir), &f.to_add_object())?;
    crate::crash::point("finding.indexed");
    op.append_ledger(
        "finding.recorded",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &format!("finding={id} level={level} severity={severity} status={status}"),
    )?;
    Ok(f)
}

/// Changes for [`update`]; `None` keeps the current value.
#[derive(Clone, Debug, Default)]
pub struct Update {
    /// New title.
    pub title: Option<MetadataOnly>,
    /// New level.
    pub level: Option<String>,
    /// New severity.
    pub severity: Option<String>,
    /// New confidence.
    pub confidence: Option<String>,
    /// New status.
    pub status: Option<String>,
    /// New impact.
    pub impact: Option<MetadataOnly>,
    /// New recommendation.
    pub recommendation: Option<MetadataOnly>,
    /// Evidence IDs to merge in.
    pub evidence: Vec<String>,
    /// Validation plan IDs to merge in.
    pub validations: Vec<String>,
    /// Latest note.
    pub note: Option<MetadataOnly>,
    /// Accepted-risk fields.
    pub accepted_reason: Option<MetadataOnly>,
    /// Accepted-risk owner.
    pub accepted_owner: Option<MetadataOnly>,
    /// Accepted-risk expiry.
    pub accepted_until: Option<String>,
    /// Accepted at.
    pub accepted_at: Option<String>,
    /// Accepted by.
    pub accepted_by: Option<String>,
    /// Review reason.
    pub review_reason: Option<MetadataOnly>,
    /// Reviewed at.
    pub reviewed_at: Option<String>,
    /// Reviewed by.
    pub reviewed_by: Option<String>,
}

fn merge_unique(current: &[String], extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = current.to_vec();
    for e in extra {
        if !e.is_empty() && !out.contains(e) {
            out.push(e.clone());
        }
    }
    out
}

/// The latest record for `id`, or a refusal naming it.
pub fn latest_record(op_dir: &Path, id: &str) -> Result<Finding> {
    match latest(op_dir, "")?.into_iter().find(|f| f.id == id) {
        Some(f) => Ok(f),
        None => fail!("unknown finding: {id}"),
    }
}

/// `cmd_finding_update`: merge `u` into the latest record, validate,
/// preflight, check new evidence IDs exist, append the record and
/// `finding.updated`. Returns the new record.
pub fn update(op: &Operation<Active>, id: &str, u: &Update) -> Result<Finding> {
    let _lock = op.lock()?;
    let cur = latest_record(&op.dir, id)?;
    if cur.operation != op.slug {
        fail!(
            "finding '{id}' does not belong to active operation '{}'",
            op.slug
        );
    }
    let pick = |new: &Option<String>, cur: &str, fallback: &str| -> String {
        match new.as_deref() {
            Some(v) if !v.is_empty() => v.to_owned(),
            _ => or(cur, fallback).to_owned(),
        }
    };
    let pick_m = |new: &Option<MetadataOnly>, cur: &str| -> String {
        match new {
            Some(v) if !v.as_str().is_empty() => v.as_str().to_owned(),
            _ => cur.to_owned(),
        }
    };
    let f = Finding {
        id: cur.id.clone(),
        operation: cur.operation.clone(),
        target: cur.target.clone(),
        title: pick_m(&u.title, &cur.title),
        level: pick(&u.level, &cur.level, "inferred"),
        severity: pick(&u.severity, &cur.severity, "info"),
        confidence: pick(&u.confidence, &cur.confidence, "medium"),
        status: pick(&u.status, &cur.status, "open"),
        source: or(&cur.source, TOOL_NAME).to_owned(),
        impact: pick_m(&u.impact, &cur.impact),
        recommendation: pick_m(&u.recommendation, &cur.recommendation),
        evidence: merge_unique(&cur.evidence, &u.evidence),
        validations: merge_unique(&cur.validations, &u.validations),
        created_at: or(&cur.created_at, &clock::timestamp()).to_owned(),
        updated_at: clock::timestamp(),
        accepted_reason: pick_m(&u.accepted_reason, &cur.accepted_reason),
        accepted_owner: pick_m(&u.accepted_owner, &cur.accepted_owner),
        accepted_until: pick(&u.accepted_until, &cur.accepted_until, ""),
        accepted_at: pick(&u.accepted_at, &cur.accepted_at, ""),
        accepted_by: pick(&u.accepted_by, &cur.accepted_by, ""),
        review_reason: pick_m(&u.review_reason, &cur.review_reason),
        reviewed_at: pick(&u.reviewed_at, &cur.reviewed_at, ""),
        reviewed_by: pick(&u.reviewed_by, &cur.reviewed_by, ""),
        note: text(&u.note),
    };
    if !valid_level(&f.level) {
        fail!(
            "expected finding level observed, inferred, or validated; got: {}",
            f.level
        );
    }
    if !valid_severity(&f.severity) {
        fail!(
            "expected severity info, low, medium, high, or critical; got: {}",
            f.severity
        );
    }
    if !valid_confidence(&f.confidence) {
        fail!(
            "expected confidence low, medium, or high; got: {}",
            f.confidence
        );
    }
    if !valid_status(&f.status) {
        fail!(
            "expected status open, accepted, resolved, or validated; got: {}",
            f.status
        );
    }
    op.preflight(Tier::ReadOnly, TOOL_NAME, &f.target, "update finding")?
        .into_result()?;
    for e in u.evidence.iter().filter(|e| !e.is_empty()) {
        if !crate::evidence::exists(&op.dir, e)? {
            fail!("unknown evidence id for active operation: {e}");
        }
    }
    ndjson::append(&index_file(&op.dir), &f.to_update_object())?;
    op.append_ledger(
        "finding.updated",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &format!(
            "finding={id} level={} severity={} status={} validations={}",
            f.level,
            f.severity,
            f.status,
            f.validations.join(" ")
        ),
    )?;
    Ok(f)
}

/// `cmd_finding_resolve`: status `resolved`, with optional evidence and note.
pub fn resolve(
    op: &Operation<Active>,
    id: &str,
    evidence: &[String],
    note: Option<MetadataOnly>,
) -> Result<Finding> {
    update(
        op,
        id,
        &Update {
            status: Some("resolved".into()),
            evidence: evidence.to_vec(),
            note,
            ..Default::default()
        },
    )
}

/// Reopen a resolved or accepted finding (`open`), with a note saying why.
pub fn reopen(op: &Operation<Active>, id: &str, note: Option<MetadataOnly>) -> Result<Finding> {
    update(
        op,
        id,
        &Update {
            status: Some("open".into()),
            note,
            ..Default::default()
        },
    )
}

/// Inputs to [`accept`].
#[derive(Clone, Debug)]
pub struct AcceptParams {
    /// Required.
    pub reason: MetadataOnly,
    /// Risk owner.
    pub owner: Option<MetadataOnly>,
    /// `YYYY-MM-DD` (or a timestamp) when the acceptance lapses.
    pub expires: Option<String>,
    /// Evidence IDs to merge in.
    pub evidence: Vec<String>,
}

/// `cmd_finding_accept`: an update to `accepted` carrying the acceptance
/// fields and the shell's note form, then `finding.accepted`.
pub fn accept(op: &Operation<Active>, id: &str, p: &AcceptParams) -> Result<Finding> {
    let accepted_at = clock::timestamp();
    let accepted_by = crate::approval::operator();
    let owner = text(&p.owner);
    let expires = p.expires.clone().unwrap_or_default();
    let mut note = format!("accepted risk: {}", p.reason.as_str());
    if !owner.is_empty() {
        note.push_str(&format!(" owner={owner}"));
    }
    if !expires.is_empty() {
        note.push_str(&format!(" expires={expires}"));
    }
    let f = update(
        op,
        id,
        &Update {
            status: Some("accepted".into()),
            note: Some(
                MetadataOnly::scan(&note).map_err(|e| crate::error::Error::user(e.to_string()))?,
            ),
            accepted_reason: Some(p.reason.clone()),
            accepted_owner: p.owner.clone(),
            accepted_until: p.expires.clone(),
            accepted_at: Some(accepted_at),
            accepted_by: Some(accepted_by),
            evidence: p.evidence.clone(),
            ..Default::default()
        },
    )?;
    op.append_ledger(
        "finding.accepted",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "accepted",
        &format!(
            "finding={id} owner={owner} expires={expires} reason={}",
            p.reason.as_str()
        ),
    )?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lcoat-findings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            index_file(&dir),
            concat!(
                "{\"id\":\"finding_1\",\"target\":\"t\",\"title\":\"A\",\"severity\":\"low\",\"status\":\"open\",\"created_at\":\"2026-01-01T00:00:00Z\",\"evidence\":[\"ev_1\"]}\n",
                "{\"id\":\"finding_2\",\"target\":\"t\",\"title\":\"B\",\"severity\":\"high\",\"status\":\"open\",\"created_at\":\"2026-01-02T00:00:00Z\",\"evidence\":[]}\n",
                "{\"id\":\"finding_3\",\"target\":\"t\",\"title\":\"C\",\"severity\":\"medium\",\"status\":\"accepted\",\"accepted_until\":\"2026-01-10\",\"accepted_reason\":\"r\",\"created_at\":\"2026-01-03T00:00:00Z\",\"evidence\":[]}\n",
                "{\"id\":\"finding_1\",\"target\":\"t\",\"title\":\"A\",\"severity\":\"low\",\"status\":\"resolved\",\"created_at\":\"2026-01-01T00:00:00Z\",\"updated_at\":\"2026-01-04T00:00:00Z\",\"evidence\":[\"ev_1\"],\"note\":\"fixed\"}\n",
            ),
        )
        .unwrap();
        dir
    }

    #[test]
    fn orders_match_jq() {
        let dir = fixture();
        assert_eq!(count(&dir, "t").unwrap(), 3);
        let o = open(&dir, "t").unwrap();
        assert_eq!(
            o.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            ["finding_2"]
        );
        assert_eq!(accepted(&dir, "t").unwrap().len(), 1);
        assert_eq!(expired_accepted(&dir, "t", "2026-02-01").unwrap().len(), 1);
        assert!(
            expired_accepted(&dir, "t", "2026-01-05")
                .unwrap()
                .is_empty()
        );
        let r = rows(&dir, "t", 0).unwrap();
        assert_eq!(
            r.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            ["finding_1", "finding_3", "finding_2"]
        );
        assert_eq!(rows(&dir, "t", 1).unwrap().len(), 1);
        assert_eq!(latest_finding(&dir, "t").unwrap().unwrap().id, "finding_1");
        assert_eq!(highest_severity(&dir, "t").unwrap(), "high");
        assert_eq!(highest_severity(&dir, "nope").unwrap(), "none");
        let md = report_markdown(&dir).unwrap();
        assert_eq!(md[0], "- high / inferred / open: B");
        assert_eq!(
            md[2],
            "- low / inferred / resolved: A Evidence: ev_1. Latest note: fixed."
        );
        assert_eq!(
            report_markdown(&dir.join("missing")).unwrap(),
            ["- No reviewed findings recorded yet."]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lines_render_optional_fields() {
        let f = Finding {
            title: "T".into(),
            severity: "medium".into(),
            impact: "i".into(),
            recommendation: "r".into(),
            accepted_reason: "ar".into(),
            accepted_owner: "o".into(),
            note: "n".into(),
            ..Default::default()
        };
        assert_eq!(
            f.report_line(),
            "- medium / inferred / open: T Impact: i. Recommendation: r. Accepted risk: ar. Owner: o. Latest note: n."
        );
        assert_eq!(
            f.review_line(),
            "- medium / medium / open: T Impact: i. Recommendation: r. Accepted risk: ar. Owner: o. Latest note: n."
        );
        // Report line hides owner without a reason; review line does not.
        let g = Finding {
            accepted_owner: "o".into(),
            ..Default::default()
        };
        assert_eq!(
            g.report_line(),
            "- info / inferred / open: untitled finding"
        );
        assert_eq!(
            g.review_line(),
            "- info / medium / open: untitled finding Owner: o."
        );
        assert_eq!(severity_weight("critical"), 5);
        assert_eq!(severity_weight("?"), 0);
    }
}
