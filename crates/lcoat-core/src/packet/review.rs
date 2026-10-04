//! Accepted-risk review: the queue, the review packet, and its verifier,
//! in the shell build's layout (`lib/findings.sh`, `cmd_finding_review_*`).
//!
//! An operation with accepted risks needs a current, verified review packet
//! before its trust chain is `current` (field run 1: `local-baseline` closed
//! `ready` with every other packet verified, and stayed `incomplete`).
//!
//! The packet holds ids, review states, owner and severity labels, the
//! acceptance reason the operator recorded (already scanned as metadata),
//! and two anchors: the finding index hash and the ledger prefix. The ledger
//! event is appended before the packet is rendered, so the anchor includes
//! it; afterwards only another review packet, an audit packet or an archive
//! packet may follow without the verifier calling the ledger changed.
//!
//! Lab Coat difference: the shell writes the packet for the active operation
//! only; here any operation can be named, so a closed one is reviewed
//! without resuming it. Format 1.1 `rel=` tokens are added to both anchors.

use std::path::Path;

use lcoat_format::clock::{self, Utc};
use lcoat_format::fsutil::file_exists;
use lcoat_format::json::{Object, Value};

use crate::error::Result;
use crate::fail;
use crate::findings::{self, Finding};
use crate::history;
use crate::ledger;
use crate::operation::{Operation, State};
use crate::root::TOOL_NAME;
use crate::tier::Tier;

use super::verify::{disallowed_later, parse_count, prefix_matches};
use super::write::{Written, finish, packet_path, rel_token};
use super::{anchor_line, anchor_path, anchor_token, field, ledger_event_count, sha_for_file};

/// The ledger event a review packet is recorded under.
pub const EVENT: &str = "finding.review_packet.generated";
/// Sub-directory of the operation that holds review packets.
pub const DIR: &str = "findings/review-packets";
/// Default review window, in days.
pub const DEFAULT_WINDOW: u32 = 30;
/// Events allowed after a review packet's anchored ledger prefix.
pub const ALLOW_LATER: &[&str] = &[EVENT, "audit.packet.generated", "archive.packet.generated"];

/// One accepted risk in the review queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueRow {
    /// Finding id.
    pub id: String,
    /// `expired`, `due-soon`, `no-expiry` or `current`.
    pub state: &'static str,
    /// `accepted_until` date part, or empty.
    pub expires: String,
    /// Risk owner, or empty.
    pub owner: String,
    /// Severity label.
    pub severity: String,
    /// Finding level.
    pub level: String,
    /// Title.
    pub title: String,
    /// Review reason, else the acceptance reason.
    pub reason: String,
}

/// The queue for a window: today, the due-by date and the rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queue {
    /// `YYYY-MM-DD`.
    pub today: String,
    /// Window in days.
    pub window: u32,
    /// `today + window` as `YYYY-MM-DD`.
    pub due_by: String,
    /// Rows, most urgent first.
    pub rows: Vec<QueueRow>,
}

impl Queue {
    /// Rows in `state`.
    pub fn count(&self, state: &str) -> usize {
        self.rows.iter().filter(|r| r.state == state).count()
    }

    /// The table the shell prints (`atlas_findings_review_queue_print_table`).
    pub fn table(&self) -> Vec<String> {
        let mut out = vec![format!(
            "{:<24} {:<10} {:<10} {:<12} {:<8} {:<10} {}",
            "ID", "STATE", "EXPIRES", "OWNER", "SEVERITY", "LEVEL", "TITLE"
        )];
        for r in &self.rows {
            let dash = |s: &str| {
                if s.is_empty() {
                    "-".to_owned()
                } else {
                    s.to_owned()
                }
            };
            let mut line = format!(
                "{:<24} {:<10} {:<10} {:<12} {:<8} {:<10} {}",
                r.id,
                r.state,
                dash(&r.expires),
                dash(&r.owner),
                r.severity,
                r.level,
                r.title
            );
            if !r.reason.is_empty() {
                line.push_str(&format!(" reason={}", r.reason));
            }
            out.push(line);
        }
        out
    }
}

/// `today + window days`, or an error past year 9999.
pub fn due_by(today: &str, window: u32) -> Result<String> {
    let Some(start) = Utc::parse(&format!("{today}T00:00:00Z")) else {
        fail!("could not calculate accepted-risk review window from date '{today}'");
    };
    let secs = start
        .unix()
        .checked_add(i64::from(window) * 86_400)
        .filter(|s| *s <= clock::MAX_EXPIRY_SECS);
    match secs {
        Some(s) => Ok(Utc::from_unix(s).date()),
        None => fail!("could not calculate accepted-risk review window from date '{today}'"),
    }
}

/// Parse `--within <days>`: a non-negative integer.
pub fn parse_window(v: &str) -> Result<u32> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        fail!("review window must be a non-negative integer number of days");
    }
    match v.parse::<u32>() {
        Ok(n) if n <= 3_650_000 => Ok(n),
        _ => fail!("review window must be a non-negative integer number of days"),
    }
}

fn state_of(f: &Finding, today: &str, due_by: &str) -> &'static str {
    let until = f.accepted_date();
    if until.is_empty() {
        "no-expiry"
    } else if until < today {
        "expired"
    } else if until <= due_by {
        "due-soon"
    } else {
        "current"
    }
}

fn weight(state: &str) -> u8 {
    match state {
        "expired" => 0,
        "due-soon" => 1,
        "no-expiry" => 2,
        _ => 3,
    }
}

fn or<'a>(v: &'a str, fallback: &'a str) -> &'a str {
    if v.is_empty() { fallback } else { v }
}

/// `atlas_findings_review_queue_rows`: accepted findings for the
/// operation's target, most urgent first (state, then date, then id).
pub fn queue<S: State>(op: &Operation<S>, window: u32) -> Result<Queue> {
    let today = clock::today();
    let due = due_by(&today, window)?;
    let mut rows: Vec<QueueRow> = findings::latest(&op.dir, &op.target)?
        .into_iter()
        .filter(|f| or(&f.status, "open") == "accepted")
        .map(|f| QueueRow {
            state: state_of(&f, &today, &due),
            expires: f.accepted_date().to_owned(),
            owner: f.accepted_owner.clone(),
            severity: or(&f.severity, "info").to_owned(),
            level: or(&f.level, "inferred").to_owned(),
            title: or(&f.title, "untitled finding").to_owned(),
            reason: or(&f.review_reason, &f.accepted_reason).to_owned(),
            id: or(&f.id, "?").to_owned(),
        })
        .collect();
    rows.sort_by(|a, b| {
        weight(a.state)
            .cmp(&weight(b.state))
            .then_with(|| a.expires.cmp(&b.expires))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(Queue {
        today,
        window,
        due_by: due,
        rows,
    })
}

/// `cmd_finding_review_packet`: append the ledger event, then render the
/// packet (so its ledger anchor includes the event), then record history.
pub fn write<S: State>(op: &Operation<S>, packet_name: &str, window: u32) -> Result<Written> {
    let q = queue(op, window)?;
    let _lock = op.lock()?;
    let path = packet_path(
        op,
        DIR,
        packet_name,
        "accepted-risk-review",
        "accepted-risk review packet",
    )?;
    op.append_ledger(
        EVENT,
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &path.display().to_string(),
    )?;
    let body = render(op, &q);
    let w = finish(&path, &body)?;
    history::record(
        &op.dir,
        "finding-review-packet",
        &path.display().to_string(),
    )?;
    Ok(w)
}

fn render<S: State>(op: &Operation<S>, q: &Queue) -> String {
    let root = op.root.root.as_path();
    let findings_file = findings::index_file(&op.dir).display().to_string();
    let ledger_file = ledger::file(&op.dir).display().to_string();
    let findings_sha = or(&sha_for_file(&findings_file), "none").to_owned();
    let (ledger_events, ledger_sha) = if file_exists(Path::new(&ledger_file)) {
        (
            ledger_event_count(&ledger_file),
            or(&sha_for_file(&ledger_file), "none").to_owned(),
        )
    } else {
        (0, "none".to_owned())
    };

    let mut b = String::new();
    b.push_str("# Atlas Accepted Risk Review Packet\n\n");
    b.push_str(&format!("Generated: {}\n", clock::timestamp()));
    b.push_str(&format!("Operation: {}\n", op.name));
    b.push_str(&format!("Operation ID: {}\n", op.slug));
    b.push_str(&format!("Operation Status: {}\n", op.status));
    b.push_str(&format!("Target: {}\n", op.target));
    if !op.target_address.is_empty() && op.target_address != op.target {
        b.push_str(&format!("Address: {}\n", op.target_address));
    }
    b.push_str("\nNo raw artifact contents are included in this accepted-risk review packet.\n");

    b.push_str("\n## Review Window\n\n");
    b.push_str(&format!("- Today: {}\n", q.today));
    b.push_str(&format!("- Review window: {} days\n", q.window));
    b.push_str(&format!("- Due by: {}\n", q.due_by));

    b.push_str("\n## Queue Counts\n\n");
    b.push_str(&format!("- Expired: {}\n", q.count("expired")));
    b.push_str(&format!("- Due soon: {}\n", q.count("due-soon")));
    b.push_str(&format!("- No expiry: {}\n", q.count("no-expiry")));
    b.push_str(&format!("- Current: {}\n", q.count("current")));

    b.push_str("\n## Anchors\n\n");
    b.push_str(&format!(
        "- Finding index: `{findings_file}` sha256={findings_sha}{}\n",
        rel_token(root, &findings_file)
    ));
    b.push_str(&format!(
        "- Operation ledger: `{ledger_file}` events={ledger_events} sha256={ledger_sha}{}\n",
        rel_token(root, &ledger_file)
    ));

    b.push_str("\n## Review Queue\n\n");
    b.push_str("```text\n");
    if q.rows.is_empty() {
        b.push_str("no accepted risks recorded\n");
    } else {
        for line in q.table() {
            b.push_str(&line);
            b.push('\n');
        }
    }
    b.push_str("```\n");
    b
}

// --- verification ------------------------------------------------------------

/// The verdict on one review packet, with the two rows the shell prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewVerify {
    /// The packet verified.
    pub packet: String,
    /// `verified` or `attention-required`.
    pub status: &'static str,
    /// Number of problems.
    pub problems: usize,
    /// Rows: (artifact, status, detail).
    pub rows: Vec<(&'static str, &'static str, String)>,
}

fn unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

/// Resolve a root-relative fallback the way the other verifiers do: the
/// absolute path when it exists, else `rel=` under this lab root.
fn resolve<S: State>(op: &Operation<S>, path: &str, line: &str) -> String {
    if path.is_empty() || file_exists(Path::new(path)) {
        return path.to_owned();
    }
    let rel = anchor_token(line, "rel");
    if !rel.is_empty() && !rel.contains("..") {
        let p = op.root.root.join(rel);
        if file_exists(&p) {
            return p.display().to_string();
        }
    }
    path.to_owned()
}

/// Index and ledger anchors, whichever form they came from.
struct Anchors {
    findings_path: String,
    findings_sha: String,
    ledger_path: String,
    ledger_events: String,
    ledger_sha: String,
}

/// `atlas_findings_verify_review_packet` (Markdown) and
/// `atlas_findings_verify_json_review_packet` (the shell's `--json` form).
pub fn verify<S: State>(op: &Operation<S>, packet: &str) -> Result<ReviewVerify> {
    if !file_exists(Path::new(packet)) {
        fail!("accepted-risk review packet is not a file: {packet}");
    }
    let text = std::fs::read_to_string(packet)?;
    let mut problems = 0usize;
    let mut extra_rows: Vec<(&'static str, &'static str, String)> = Vec::new();

    let anchors = if let Ok(Value::Object(doc)) = Value::parse(&text)
        && doc.get("schema_version").and_then(Value::as_str)
            == Some("atlas.accepted_risk_review_packet.v1")
    {
        json_anchors(op, &doc, packet, &text, &mut problems, &mut extra_rows)?
    } else {
        let id = field(&text, "Operation ID");
        if id.is_empty() {
            fail!("accepted-risk review packet is missing Operation ID: {packet}");
        }
        if id != op.slug {
            fail!(
                "accepted-risk review packet belongs to '{id}', not '{}'",
                op.slug
            );
        }
        let fline = anchor_line(&text, "Finding index").unwrap_or("");
        let lline = anchor_line(&text, "Operation ledger").unwrap_or("");
        Anchors {
            findings_path: resolve(op, anchor_path(fline), fline),
            findings_sha: anchor_token(fline, "sha256").to_owned(),
            ledger_path: resolve(op, anchor_path(lline), lline),
            ledger_events: anchor_token(lline, "events").to_owned(),
            ledger_sha: anchor_token(lline, "sha256").to_owned(),
        }
    };

    // Finding index.
    let a = &anchors;
    let mut actual_f = String::new();
    let f_status = if a.findings_path.is_empty() || a.findings_sha.is_empty() {
        problems += 1;
        "unverifiable"
    } else if !file_exists(Path::new(&a.findings_path)) && a.findings_sha == "none" {
        actual_f = "none".into();
        "verified"
    } else if !file_exists(Path::new(&a.findings_path)) {
        problems += 1;
        "missing"
    } else {
        actual_f = sha_for_file(&a.findings_path);
        if actual_f == a.findings_sha {
            "verified"
        } else {
            problems += 1;
            "changed"
        }
    };
    let f_detail = format!(
        "expected_sha={} actual_sha={} path={}",
        unknown(&a.findings_sha),
        unknown(&actual_f),
        unknown(&a.findings_path)
    );

    // Operation ledger.
    let mut actual_events = String::new();
    let mut actual_sha = String::new();
    let mut l_detail = String::new();
    let l_status = if a.ledger_path.is_empty()
        || a.ledger_events.is_empty()
        || a.ledger_sha.is_empty()
    {
        problems += 1;
        "unverifiable"
    } else if !file_exists(Path::new(&a.ledger_path)) {
        problems += 1;
        "missing"
    } else {
        let n = ledger_event_count(&a.ledger_path);
        actual_events = n.to_string();
        actual_sha = sha_for_file(&a.ledger_path);
        let expected = parse_count(&a.ledger_events);
        if actual_events == a.ledger_events && actual_sha == a.ledger_sha {
            l_detail = format!("events={n}");
            "verified"
        } else if let Some(e) = expected.filter(|e| {
            n > *e
                && prefix_matches(&a.ledger_path, *e, &a.ledger_sha)
                && disallowed_later(&a.ledger_path, *e, ALLOW_LATER).is_empty()
        }) {
            l_detail = format!(
                "events={n} anchored_events={e} later_allowed_events={}",
                n - e
            );
            "verified"
        } else {
            problems += 1;
            let disallowed = match expected {
                Some(e) => disallowed_later(&a.ledger_path, e, ALLOW_LATER).join(","),
                None => String::new(),
            };
            l_detail = format!(
                "expected_events={} actual_events={} expected_sha={} actual_sha={} disallowed_later_events={}",
                a.ledger_events,
                actual_events,
                a.ledger_sha,
                actual_sha,
                if disallowed.is_empty() {
                    "none"
                } else {
                    &disallowed
                }
            );
            "changed"
        }
    };
    if l_detail.is_empty() {
        l_detail = format!(
            "expected_events={} actual_events={} expected_sha={} actual_sha={}",
            unknown(&a.ledger_events),
            unknown(&actual_events),
            unknown(&a.ledger_sha),
            unknown(&actual_sha)
        );
    }

    let mut rows = extra_rows;
    rows.push(("Finding Index", f_status, f_detail));
    rows.push((
        "Operation Ledger",
        l_status,
        format!("ledger={} {l_detail}", unknown(&a.ledger_path)),
    ));
    Ok(ReviewVerify {
        packet: packet.to_owned(),
        status: if problems > 0 {
            "attention-required"
        } else {
            "verified"
        },
        problems,
        rows,
    })
}

/// The JSON form's metadata flags, forbidden-content scan and anchors.
fn json_anchors<S: State>(
    op: &Operation<S>,
    doc: &Object,
    packet: &str,
    text: &str,
    problems: &mut usize,
    rows: &mut Vec<(&'static str, &'static str, String)>,
) -> Result<Anchors> {
    let get = |path: &[&str]| -> Option<Value> {
        let mut cur = Value::Object(doc.clone());
        for k in path {
            cur = cur.as_object()?.get(k)?.clone();
        }
        Some(cur)
    };
    let s = |path: &[&str]| -> String {
        match get(path) {
            Some(Value::String(v)) => v,
            Some(Value::Number(n)) => n,
            _ => String::new(),
        }
    };
    let id = s(&["operation", "id"]);
    if id.is_empty() {
        fail!("accepted-risk review JSON packet is missing operation.id: {packet}");
    }
    if id != op.slug {
        fail!(
            "accepted-risk review packet belongs to '{id}', not '{}'",
            op.slug
        );
    }
    let flag = |name: &'static str, ok: bool, problems: &mut usize, rows: &mut Vec<_>| {
        if !ok {
            *problems += 1;
            rows.push((name, "blocked", String::new()));
        }
    };
    flag(
        "Metadata Only",
        matches!(get(&["metadata_only"]), Some(Value::Bool(true))),
        problems,
        rows,
    );
    flag(
        "Raw Artifacts",
        matches!(get(&["raw_artifacts_embedded"]), Some(Value::Bool(false))),
        problems,
        rows,
    );
    flag(
        "Forbidden Content",
        crate::metadata::forbidden_paths(&Value::Object(doc.clone())).is_empty()
            && !crate::metadata::value_is_forbidden(text),
        problems,
        rows,
    );
    Ok(Anchors {
        findings_path: s(&["anchors", "finding_index", "path"]),
        findings_sha: s(&["anchors", "finding_index", "sha256"]),
        ledger_path: s(&["anchors", "operation_ledger", "path"]),
        ledger_events: s(&["anchors", "operation_ledger", "events"]),
        ledger_sha: s(&["anchors", "operation_ledger", "sha256"]),
    })
}

/// `atlas_findings_resolve_review_packet`: the latest recorded packet, or a
/// path, a file name in the review directory, or a packet name.
pub fn resolve_packet<S: State>(op: &Operation<S>, arg: &str) -> Result<String> {
    let dir = op.dir.join(DIR);
    if arg.is_empty() {
        let events = ledger::read(&op.dir)?;
        let Some(e) = ledger::latest(&events, &[EVENT]) else {
            fail!(
                "no accepted-risk review packet recorded for operation '{}'",
                op.slug
            );
        };
        if !file_exists(Path::new(&e.detail)) {
            fail!(
                "recorded accepted-risk review packet is missing: {}",
                e.detail
            );
        }
        return Ok(e.detail.clone());
    }
    if file_exists(Path::new(arg)) {
        return Ok(arg.to_owned());
    }
    let direct = dir.join(arg);
    if !arg.contains('/') && file_exists(&direct) {
        return Ok(direct.display().to_string());
    }
    let stem = arg.trim_end_matches(".md").trim_end_matches(".json");
    let slug = lcoat_format::ids::slugify(stem);
    if lcoat_format::ids::is_safe_slug(&slug) {
        for ext in ["md", "json"] {
            let p = dir.join(format!("{slug}.{ext}"));
            if file_exists(&p) {
                return Ok(p.display().to_string());
            }
        }
    }
    fail!(
        "unknown accepted-risk review packet for operation '{}': {arg}",
        op.slug
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_and_due_date() {
        assert_eq!(due_by("2026-10-04", 30).unwrap(), "2026-11-03");
        assert_eq!(due_by("2026-12-31", 1).unwrap(), "2027-01-01");
        assert_eq!(due_by("2026-10-04", 0).unwrap(), "2026-10-04");
        assert!(due_by("9999-12-31", 1).is_err());
        assert!(due_by("not-a-date", 1).is_err());
        assert_eq!(parse_window("30").unwrap(), 30);
        for bad in ["", "-1", "3.5", "x", "99999999999"] {
            assert!(parse_window(bad).is_err(), "{bad}");
        }
    }
}
