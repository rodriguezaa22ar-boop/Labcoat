//! Packet renderers: handoff, closeout manifest, audit packet, archive
//! packet, in the shell build's Markdown layout and generation order.
//!
//! The order is enforced by types: [`handoff`] takes any state, the other
//! three take [`Operation<Closed>`], and [`audit`] and [`archive`] take the
//! previous packet by reference. The ledger event is appended *before* the
//! closeout, audit and archive packets are rendered (so their own ledger
//! anchor includes it) and *after* the handoff, exactly as the shell does;
//! an interruption between the two leaves an event whose packet the
//! verifiers report as `missing`.
//!
//! Format 1.1: every anchor line that names a file under the lab root also
//! carries `rel=<root-relative path>`, and the `Evidence manifest:` slot the
//! shell left as `none` is filled when the operation has a manifest. v1
//! verifiers ignore both; Lab Coat's use `rel=` only when the absolute path
//! is gone.

use std::path::{Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::fsutil::{mkdir_private, write_private};
use lcoat_format::ids::{is_safe_slug, slugify};

use crate::error::Result;
use crate::evidence;
use crate::fail;
use crate::findings;
use crate::history;
use crate::ledger;
use crate::operation::{Closed, Operation, State};
use crate::readiness::{self, Marker};
use crate::root::TOOL_NAME;
use crate::scope;
use crate::tier::Tier;
use crate::validation;

use super::trustchain::{
    archive_next_step, archive_status, audit_verification_status, closeout_verification_status,
    review_verification_status,
};
use super::{ledger_event_count, sha_for_file};

/// A packet that exists on disk: its path and the hash of its bytes. The
/// fields are private: a `Written` comes from writing a packet here or from
/// [`latest`], which looks the latest recorded packet up in the ledger, so
/// `audit(&closed, &closeout, ..)` cannot be satisfied with a made-up path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    path: PathBuf,
    sha256: String,
}

impl Written {
    /// Absolute path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// sha256 of the file.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// The latest packet of `kind` (`handoff`, `closeout`, `audit`, `archive`)
/// recorded in the ledger, re-hashed from disk. Refuses when none was
/// recorded or the file is gone, naming the command that makes one.
pub fn latest<S: State>(op: &Operation<S>, kind: &str) -> Result<Written> {
    let path = super::latest_in_ledger(op, kind)?;
    if path.is_empty() {
        let verb = match kind {
            "closeout" => "op closeout",
            "audit" => "op audit-packet",
            "archive" => "op archive-packet",
            _ => "op handoff",
        };
        fail!(
            "no {kind} packet recorded for operation '{}'; run 'lcoat {verb}' first",
            op.slug
        );
    }
    if !lcoat_format::fsutil::file_exists(Path::new(&path)) {
        fail!("recorded {kind} packet is missing: {path}");
    }
    Ok(Written {
        path: PathBuf::from(&path),
        sha256: sha_for_file(&path),
    })
}

fn count_line(label: &str, n: usize) -> String {
    format!("- {label}: {n}\n")
}

fn change_line(label: &str, m: &Marker) -> String {
    if m.present() {
        format!("- {label}: {} {}\n", m.at, m.event)
    } else {
        format!("- {label}: none\n")
    }
}

/// `rel=<path>` for a file under the lab root, else nothing.
pub(super) fn rel_token(root: &Path, path: &str) -> String {
    match Path::new(path).strip_prefix(root) {
        Ok(rel) if !rel.as_os_str().is_empty() => {
            let r = rel.display().to_string();
            if r.contains(' ') {
                String::new()
            } else {
                format!(" rel={r}")
            }
        }
        _ => String::new(),
    }
}

/// `atlas_closeout_print_hash_line`: a bullet with the path and its sha,
/// or `- Label: none` when the file is absent.
fn hash_line(root: &Path, label: &str, path: &str) -> String {
    if !path.is_empty() && lcoat_format::fsutil::file_exists(Path::new(path)) {
        let sha = sha_for_file(path);
        let mut line = format!("- {label}: `{path}`");
        if !sha.is_empty() {
            line.push_str(&format!(" sha256={sha}"));
        }
        line.push_str(&rel_token(root, path));
        return line;
    }
    format!("- {label}: none")
}

fn backtick_sha_line(root: &Path, label: &str, path: &str, sha: &str) -> String {
    let mut line = format!("- {label}: `{path}`");
    if !sha.is_empty() {
        line.push_str(&format!(" sha256={sha}"));
    }
    if path != "none" {
        line.push_str(&rel_token(root, path));
    }
    line.push('\n');
    line
}

fn marker_fields(m: &Marker) -> (String, String, String) {
    if !m.present() {
        return (String::new(), String::new(), String::new());
    }
    (m.at.clone(), m.detail.clone(), sha_for_file(&m.detail))
}

/// The `Evidence manifest:` line: the format 1.1 manifest when present,
/// else the shell's `none`.
fn manifest_line<S: State>(op: &Operation<S>) -> String {
    let path = evidence::manifest_file(&op.dir);
    if lcoat_format::fsutil::file_exists(&path) {
        hash_line(
            &op.root.root,
            "Evidence manifest",
            &path.display().to_string(),
        )
    } else {
        "- Evidence manifest: none".to_owned()
    }
}

pub(super) fn packet_path<S: State>(
    op: &Operation<S>,
    subdir: &str,
    name: &str,
    default_suffix: &str,
    kind: &str,
) -> Result<PathBuf> {
    let name = if name.is_empty() {
        format!("{}-{default_suffix}", op.slug)
    } else {
        name.to_owned()
    };
    let slug = slugify(&name);
    if !is_safe_slug(&slug) {
        fail!("{kind} name {name:?} does not make a usable file name (slug {slug:?})");
    }
    let dir = op.dir.join(subdir);
    mkdir_private(&dir)?;
    Ok(dir.join(format!("{slug}.md")))
}

pub(super) fn finish(path: &Path, body: &str) -> Result<Written> {
    write_private(path, body.as_bytes())?;
    Ok(Written {
        path: path.to_path_buf(),
        sha256: sha_for_file(&path.display().to_string()),
    })
}

// --- handoff --------------------------------------------------------------

/// `cmd_op_handoff`: render, write, then append `handoff.generated`.
pub fn handoff<S: State>(op: &Operation<S>, packet_name: &str) -> Result<Written> {
    let _lock = op.lock()?;
    let path = packet_path(op, "handoff", packet_name, "handoff", "handoff packet")?;
    let body = render_handoff(op)?;
    let w = finish(&path, &body)?;
    op.append_ledger(
        "handoff.generated",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &path.display().to_string(),
    )?;
    history::record(&op.dir, "handoff", &path.display().to_string())?;
    Ok(w)
}

fn render_handoff<S: State>(op: &Operation<S>) -> Result<String> {
    let st = readiness::collect(op)?;
    let root = op.root.root.as_path();
    let (report_at, report_path, report_sha) = marker_fields(&st.report);
    let mut b = String::new();
    b.push_str("# Atlas Operation Handoff\n\n");
    b.push_str(&format!("Generated: {}\n", clock::timestamp()));
    b.push_str(&format!("Operation: {}\n", op.name));
    b.push_str(&format!("Operation ID: {}\n", op.slug));
    b.push_str(&format!("Operation Status: {}\n", op.status));
    b.push_str(&format!("Target: {}\n", op.target));
    if !op.target_address.is_empty() && op.target_address != op.target {
        b.push_str(&format!("Address: {}\n", op.target_address));
    }
    b.push_str("\nNo raw artifact contents are included in this handoff packet.\n");

    b.push_str("\n## Close Readiness\n\n");
    b.push_str(&format!("- Close readiness: {}\n", st.status));
    b.push_str(&format!("- Next step: {}\n", st.next_step));
    b.push_str(&count_line("Evidence records", st.evidence_count));
    b.push_str(&count_line("Findings", st.finding_count));
    b.push_str(&count_line("Open findings", st.open_count));
    b.push_str(&count_line("Expired accepted risks", st.expired_accepted));
    b.push_str(&count_line("Validation plans", st.validation_count));
    b.push_str(&count_line("Pending validation", st.pending_count));
    b.push_str(&format!("- Report freshness: {}\n", st.report_fresh));
    b.push_str(&format!("- Bundle freshness: {}\n", st.bundle_fresh));
    b.push_str(&format!(
        "- Handoff freshness before this packet: {}\n",
        st.handoff_fresh
    ));
    b.push_str(&change_line("Latest state change", &st.latest_change));
    b.push_str(&change_line("Latest evidence change", &st.latest_evidence));

    b.push_str("\n## Primary Artifacts\n\n");
    if report_path.is_empty() {
        b.push_str("- Latest report: none generated yet\n");
    } else {
        let mut line = format!("- Latest report: `{report_path}`");
        if !report_at.is_empty() {
            line.push_str(&format!(" generated={report_at}"));
        }
        if !report_sha.is_empty() {
            line.push_str(&format!(" sha256={report_sha}"));
        }
        line.push_str(&rel_token(root, &report_path));
        b.push_str(&line);
        b.push('\n');
    }
    b.push_str("- Evidence bundle: none generated yet\n");
    let ledger_path = ledger::file(&op.dir).display().to_string();
    b.push_str(&format!(
        "- Operation ledger: `{ledger_path}`{}\n",
        rel_token(root, &ledger_path)
    ));
    b.push_str(&format!("- Operation directory: `{}`\n", op.dir.display()));

    b.push_str("\n## Finding Index\n\n");
    let rows = findings::rows(&op.dir, &op.target, 1_000_000)?;
    if rows.is_empty() {
        b.push_str("- No findings recorded.\n");
    } else {
        for f in &rows {
            let ev = if f.evidence.is_empty() {
                "-".to_owned()
            } else {
                f.evidence.join(",")
            };
            b.push_str(&format!(
                "- {} / {} / {} / {}: {} Evidence: {ev}.\n",
                f.id_or(),
                f.severity_or(),
                f.level_or(),
                f.status_or(),
                f.title_or()
            ));
        }
    }

    b.push_str("\n## Findings\n\n");
    b.push_str(&findings::report_markdown(&op.dir)?.join("\n"));
    b.push('\n');
    b.push_str("\n## Validation Plans\n\n");
    b.push_str(&validation::report_markdown(&op.dir)?.join("\n"));
    b.push('\n');
    b.push_str("\n## Handoff Notes\n\n");
    b.push_str("- Validate recipient and handling requirements before sharing any bundle path.\n");
    b.push_str("- Use manifest hashes to verify copied evidence bundle files.\n");
    Ok(b)
}

// --- closeout -------------------------------------------------------------

/// `cmd_op_closeout`: append `closeout.manifest.generated`, then render
/// and write, so the manifest's ledger anchor includes its own event.
pub fn closeout(op: &Operation<Closed>, manifest_name: &str) -> Result<Written> {
    let _lock = op.lock()?;
    let path = packet_path(
        op,
        "closeout",
        manifest_name,
        "closeout",
        "closeout manifest",
    )?;
    op.append_ledger(
        "closeout.manifest.generated",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &path.display().to_string(),
    )?;
    crate::crash::point("closeout.event");
    let body = render_closeout(op)?;
    let w = finish(&path, &body)?;
    history::record(&op.dir, "closeout", &path.display().to_string())?;
    Ok(w)
}

fn render_closeout(op: &Operation<Closed>) -> Result<String> {
    let snap = op.snapshot()?;
    let st = readiness::collect(op)?;
    let root = op.root.root.as_path();
    let (report_at, report_path, report_sha) = marker_fields(&st.report);
    let (handoff_at, handoff_path, handoff_sha) = marker_fields(&st.handoff);
    let ledger_path = ledger::file(&op.dir).display().to_string();
    let ledger_events = ledger_event_count(&ledger_path);
    let ledger_sha = sha_for_file(&ledger_path);

    let mut b = String::new();
    b.push_str("# Atlas Closeout Manifest\n\n");
    b.push_str(&format!("Generated: {}\n", clock::timestamp()));
    b.push_str(&format!("Operation: {}\n", op.name));
    b.push_str(&format!("Operation ID: {}\n", op.slug));
    b.push_str(&format!("Operation Status: {}\n", op.status));
    if op.closed_at.is_empty() {
        b.push_str("Closed At: not closed\n");
    } else {
        b.push_str(&format!("Closed At: {}\n", op.closed_at));
    }
    b.push_str(&format!("Target: {}\n", op.target));
    if !op.target_address.is_empty() && op.target_address != op.target {
        b.push_str(&format!("Address: {}\n", op.target_address));
    }
    b.push_str(&format!("Profile: {}\n", snap.profile));
    b.push_str("\nNo raw artifact contents are included in this closeout manifest.\n");

    b.push_str("\n## Readiness Snapshot\n\n");
    b.push_str(&format!("- Close readiness: {}\n", st.status));
    b.push_str(&format!("- Next step: {}\n", st.next_step));
    b.push_str(&count_line("Evidence records", st.evidence_count));
    b.push_str(&count_line("Findings", st.finding_count));
    b.push_str(&count_line("Open findings", st.open_count));
    b.push_str(&count_line("Expired accepted risks", st.expired_accepted));
    b.push_str(&count_line("Validation plans", st.validation_count));
    b.push_str(&count_line("Pending validation", st.pending_count));
    b.push_str(&format!("- Report freshness: {}\n", st.report_fresh));
    b.push_str(&format!("- Bundle freshness: {}\n", st.bundle_fresh));
    b.push_str(&format!("- Handoff freshness: {}\n", st.handoff_fresh));
    b.push_str(&format!("- Closeout freshness: {}\n", st.closeout_fresh));

    b.push_str("\n## Primary Artifacts\n\n");
    if report_path.is_empty() {
        b.push_str("- Latest report: none generated yet\n");
    } else {
        b.push_str(&format!(
            "- Latest report: `{report_path}` generated={report_at} sha256={report_sha}{}\n",
            rel_token(root, &report_path)
        ));
    }
    b.push_str("- Evidence bundle: none generated yet\n");
    b.push_str(&manifest_line(op));
    b.push('\n');
    if handoff_path.is_empty() {
        b.push_str("- Latest handoff: none generated yet\n");
    } else {
        b.push_str(&format!(
            "- Latest handoff: `{handoff_path}` generated={handoff_at} sha256={handoff_sha}{}\n",
            rel_token(root, &handoff_path)
        ));
    }

    b.push_str("\n## Integrity Anchors\n\n");
    b.push_str(&format!(
        "- Operation ledger: `{ledger_path}` events={ledger_events} sha256={ledger_sha}{}\n",
        rel_token(root, &ledger_path)
    ));
    b.push_str(&hash_line(
        root,
        "Operation env",
        &op.file.display().to_string(),
    ));
    b.push('\n');
    b.push_str(&hash_line(
        root,
        "Scope snapshot",
        &scope::snapshot_file(&op.dir).display().to_string(),
    ));
    b.push('\n');
    b.push_str(&hash_line(
        root,
        "Evidence index",
        &evidence::index_file(&op.dir).display().to_string(),
    ));
    b.push('\n');
    b.push_str(&hash_line(
        root,
        "Finding index",
        &findings::index_file(&op.dir).display().to_string(),
    ));
    b.push('\n');
    b.push_str(&hash_line(
        root,
        "Validation index",
        &validation::index_file(&op.dir).display().to_string(),
    ));
    b.push('\n');

    b.push_str("\n## Closeout Notes\n\n");
    b.push_str(
        "- Verify copied report, handoff, and evidence bundle files against the hashes above.\n",
    );
    b.push_str("- Treat paths as local references; validate recipient and handling requirements before sharing artifacts.\n");
    Ok(b)
}

// --- audit ----------------------------------------------------------------

/// `cmd_op_audit_packet`: requires the closeout manifest (by reference, so
/// the order is in the signature); appends `audit.packet.generated`, then
/// renders and writes.
pub fn audit(op: &Operation<Closed>, _closeout: &Written, packet_name: &str) -> Result<Written> {
    let _lock = op.lock()?;
    let ledger_file = ledger::file(&op.dir);
    if !lcoat_format::fsutil::file_exists(&ledger_file) {
        fail!(
            "operation ledger is empty or missing: {}",
            ledger_file.display()
        );
    }
    let path = packet_path(op, "audit", packet_name, "audit", "audit packet")?;
    op.append_ledger(
        "audit.packet.generated",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &path.display().to_string(),
    )?;
    let body = render_audit(op)?;
    let w = finish(&path, &body)?;
    history::record(&op.dir, "audit-packet", &path.display().to_string())?;
    Ok(w)
}

/// `atlas_audit_flags`: the audit packet's flag block.
fn audit_flags(
    st: &readiness::State,
    events: &[ledger::Event],
    ver_status: &str,
    ver_path: &str,
    ver_problems: usize,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    for e in events
        .iter()
        .filter(|e| e.event == "scope.preflight" && e.status == "denied")
    {
        lines.push(format!("denied preflight: {} {}", e.ts, e.detail));
    }
    for e in events
        .iter()
        .filter(|e| e.event == "op.close.readiness" && e.detail.contains("force=1"))
    {
        lines.push(format!(
            "forced close: {} readiness={} {}",
            e.ts, e.status, e.detail
        ));
    }
    let stale = |label: &str, fresh: &str, m: &Marker| -> Option<String> {
        (fresh == "stale").then(|| format!("stale {label}: {}", m.path_or("none")))
    };
    lines.extend(stale("report", st.report_fresh, &st.report));
    lines.extend(stale("handoff", st.handoff_fresh, &st.handoff));
    lines.extend(stale("closeout", st.closeout_fresh, &st.closeout));
    lines.extend(stale("audit packet", st.audit_fresh, &st.audit_packet));
    lines.extend(stale(
        "archive packet",
        st.archive_fresh,
        &st.archive_packet,
    ));
    let mut b = String::new();
    for l in lines {
        b.push_str(&l);
        b.push('\n');
    }
    if ver_status == "verified" {
        b.push_str(&format!(
            "note: closeout verification: verified manifest={ver_path}\n"
        ));
    } else {
        b.push_str(&format!(
            "closeout verification: {ver_status} manifest={ver_path} problems={ver_problems}\n"
        ));
    }
    b
}

fn render_audit(op: &Operation<Closed>) -> Result<String> {
    let st = readiness::collect(op)?;
    let root = op.root.root.as_path();
    let ledger_path = ledger::file(&op.dir).display().to_string();
    let ledger_sha = sha_for_file(&ledger_path);
    let events = ledger::read(&op.dir)?;
    let (ver_status, ver_path, ver_problems) = closeout_verification_status(op, &st);
    let closeout_sha = if ver_path != "-" && lcoat_format::fsutil::file_exists(Path::new(&ver_path))
    {
        sha_for_file(&ver_path)
    } else {
        String::new()
    };

    let mut b = String::new();
    b.push_str("# Atlas Operation Audit Packet\n\n");
    b.push_str(&format!("Generated: {}\n", clock::timestamp()));
    b.push_str(&format!("Operation: {}\n", op.name));
    b.push_str(&format!("Operation ID: {}\n", op.slug));
    b.push_str(&format!("Operation Status: {}\n", op.status));
    b.push_str(&format!("Target: {}\n", op.target));
    b.push_str("\nNo raw artifact contents are included in this audit packet.\n");

    b.push_str("\n## Ledger\n\n");
    b.push_str(&format!(
        "- Operation ledger: `{ledger_path}`{}\n",
        rel_token(root, &ledger_path)
    ));
    b.push_str(&format!("- Events: {}\n", events.len()));
    b.push_str(&format!("- Ledger SHA256: {ledger_sha}\n"));
    b.push_str(&format!("- Closeout verification: {ver_status}\n"));
    b.push_str(&format!("- Closeout manifest: {ver_path}\n"));
    b.push_str(&format!(
        "- Closeout manifest SHA256: {}\n",
        if closeout_sha.is_empty() {
            "none"
        } else {
            &closeout_sha
        }
    ));
    b.push_str(&format!(
        "- Closeout verification problems: {ver_problems}\n"
    ));
    b.push_str(&count_line("Accepted risks", st.accepted_count));
    b.push_str(&format!(
        "- Accepted-risk review packet: {}\n",
        st.review_packet.path_or("none")
    ));
    b.push_str(&format!(
        "- Accepted-risk review packet freshness: {}\n",
        st.review_fresh
    ));
    b.push_str(&format!("- Audit packet freshness: {}\n", st.audit_fresh));

    b.push_str("\n## Event Counts\n\n```text\n");
    for s in ledger::count_by_event(&events) {
        b.push_str(&format!("{:<32} {}\n", s.event, s.count));
    }
    b.push_str("```\n");

    b.push_str("\n## Audit Flags\n\n```text\n");
    b.push_str(&audit_flags(
        &st,
        &events,
        ver_status,
        &ver_path,
        ver_problems,
    ));
    b.push_str("```\n");

    b.push_str("\n## Timeline\n\n```text\n");
    b.push_str(&format!(
        "{:<20} {:<28} {:<12} {:<16} {:<10} DETAIL\n",
        "TS", "EVENT", "STATUS", "CAPABILITY", "TOOL"
    ));
    for e in &events {
        b.push_str(&e.describe());
        b.push('\n');
    }
    b.push_str("```\n");
    Ok(b)
}

// --- archive --------------------------------------------------------------

/// `cmd_op_archive_packet`: requires the audit packet; appends
/// `archive.packet.generated`, then renders and writes.
pub fn archive(op: &Operation<Closed>, _audit: &Written, packet_name: &str) -> Result<Written> {
    let _lock = op.lock()?;
    let path = packet_path(op, "archive", packet_name, "archive", "archive packet")?;
    op.append_ledger(
        "archive.packet.generated",
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &path.display().to_string(),
    )?;
    let body = render_archive(op)?;
    let w = finish(&path, &body)?;
    history::record(&op.dir, "archive-packet", &path.display().to_string())?;
    Ok(w)
}

fn render_archive(op: &Operation<Closed>) -> Result<String> {
    let st = readiness::collect(op)?;
    let root = op.root.root.as_path();
    let (report_at, report_path, report_sha) = marker_fields(&st.report);
    let (closeout_status, closeout_path, closeout_problems) = closeout_verification_status(op, &st);
    let (audit_status, audit_path) = audit_verification_status(op, &st);
    let (review_status, review_path) = review_verification_status(op, &st);
    let arch_status = archive_status(&st, closeout_status, audit_status, review_status);
    let arch_next = archive_next_step(&st, closeout_status, audit_status, review_status);

    let ledger_path = ledger::file(&op.dir).display().to_string();
    let ledger_events = ledger_event_count(&ledger_path);
    let ledger_sha = sha_for_file(&ledger_path);
    let handoff_sha = sha_for_file(st.handoff.path_or(""));
    let closeout_sha = sha_for_file(st.closeout.path_or(""));
    let audit_sha = sha_for_file(st.audit_packet.path_or(""));

    let mut b = String::new();
    b.push_str("# Atlas Operation Archive Packet\n\n");
    b.push_str(&format!("Generated: {}\n", clock::timestamp()));
    b.push_str(&format!("Operation: {}\n", op.name));
    b.push_str(&format!("Operation ID: {}\n", op.slug));
    b.push_str(&format!("Operation Status: {}\n", op.status));
    b.push_str(&format!("Target: {}\n", op.target));
    if !op.target_address.is_empty() && op.target_address != op.target {
        b.push_str(&format!("Address: {}\n", op.target_address));
    }
    b.push_str("\nNo raw artifact contents are included in this archive packet.\n");

    b.push_str("\n## Archive Status\n\n");
    b.push_str(&format!("- Archive status: {arch_status}\n"));
    b.push_str(&format!("- Next archive step: {arch_next}\n"));

    b.push_str("\n## Readiness\n\n");
    b.push_str(&format!("- Close readiness: {}\n", st.status));
    b.push_str(&count_line("Evidence records", st.evidence_count));
    b.push_str(&count_line("Open findings", st.open_count));
    b.push_str(&count_line("Accepted risks", st.accepted_count));
    b.push_str(&count_line("Expired accepted risks", st.expired_accepted));
    b.push_str(&count_line("Pending validation", st.pending_count));
    b.push_str(&format!("- Report freshness: {}\n", st.report_fresh));
    b.push_str(&format!("- Bundle freshness: {}\n", st.bundle_fresh));
    b.push_str(&format!("- Handoff freshness: {}\n", st.handoff_fresh));
    b.push_str(&format!("- Closeout freshness: {}\n", st.closeout_fresh));
    b.push_str(&format!(
        "- Accepted-risk review packet freshness: {}\n",
        st.review_fresh
    ));
    b.push_str(&format!("- Audit packet freshness: {}\n", st.audit_fresh));
    b.push_str(&format!(
        "- Archive packet freshness: {}\n",
        st.archive_fresh
    ));

    b.push_str("\n## Verification\n\n");
    b.push_str(&format!("- Closeout verification: {closeout_status} manifest={closeout_path} problems={closeout_problems}\n"));
    b.push_str(&format!(
        "- Accepted-risk review packet verification: {review_status} packet={review_path}\n"
    ));
    b.push_str(&format!(
        "- Audit packet verification: {audit_status} packet={audit_path}\n"
    ));

    b.push_str("\n## Archive Artifacts\n\n");
    if report_path.is_empty() {
        b.push_str("- Latest report: none generated yet\n");
    } else {
        b.push_str(&format!(
            "- Latest report: `{report_path}` generated={report_at} sha256={report_sha}{}\n",
            rel_token(root, &report_path)
        ));
    }
    b.push_str("- Evidence bundle: none generated yet\n");
    b.push_str(&manifest_line(op));
    b.push('\n');
    b.push_str(&backtick_sha_line(
        root,
        "Latest handoff",
        st.handoff.path_or("none"),
        &handoff_sha,
    ));
    b.push_str(&backtick_sha_line(
        root,
        "Latest closeout",
        st.closeout.path_or("none"),
        &closeout_sha,
    ));
    b.push_str(&backtick_sha_line(
        root,
        "Latest accepted-risk review packet",
        st.review_packet.path_or("none"),
        &sha_for_file(st.review_packet.path_or("")),
    ));
    b.push_str(&backtick_sha_line(
        root,
        "Latest audit packet",
        st.audit_packet.path_or("none"),
        &audit_sha,
    ));
    b.push_str(&format!(
        "- Latest archive packet: `{}`\n",
        st.archive_packet.path_or("none")
    ));
    b.push_str(&format!(
        "- Operation ledger: `{ledger_path}` events={ledger_events} sha256={ledger_sha}{}\n",
        rel_token(root, &ledger_path)
    ));
    b.push_str(&format!("- Operation directory: `{}`\n", op.dir.display()));

    b.push_str("\n## Retention Notes\n\n");
    b.push_str("- Treat paths as local references; verify copied files against the recorded hashes before retention or transfer.\n");
    b.push_str(
        "- Keep this packet with the closeout manifest and audit packet for final review.\n",
    );
    Ok(b)
}
