//! Packet verifiers: closeout manifest, audit packet, archive packet.
//!
//! Each reproduces the shell build's `atlas_*_verify_markdown_*` row by row,
//! so the three implementations print the same table and reach the same
//! verdict. The shell build is the oracle; where Lite had simplified a row
//! (the audit table's `ledger=` prefix, the `disallowed_later_events`
//! suffix, the archive table's 22-column label) the shell's form is used
//! here. The tamper harness (`conformance/tamper.sh`) and
//! `conformance/readonly_diff.sh` are the proof.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::fail;
use crate::ledger;
use crate::operation::{Operation, State};
use crate::root::file_exists;

use super::{
    anchor_line, anchor_path, anchor_token, bullet_value, field, ledger_event_count, sha_for_file,
};

/// Which packet a [`VerifyResult`] describes; decides the table layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Closeout manifest: `ARTIFACT STATUS PATH`, labels padded to 20.
    Closeout,
    /// Audit packet: `ARTIFACT STATUS DETAIL`, two fixed rows.
    Audit,
    /// Archive packet: `ARTIFACT STATUS PATH`, labels padded to 22.
    Archive,
}

impl Kind {
    /// The heading the shell build prints.
    pub fn title(self) -> &'static str {
        match self {
            Kind::Closeout => "Closeout Verification",
            Kind::Audit => "Audit Packet Verification",
            Kind::Archive => "Archive Packet Verification",
        }
    }

    /// The label of the path line under the heading.
    pub fn path_label(self) -> &'static str {
        match self {
            Kind::Closeout => "Manifest",
            Kind::Audit | Kind::Archive => "Packet",
        }
    }

    /// The column header line.
    pub fn column_header(self) -> String {
        match self {
            Kind::Closeout => format!("{:<20} {:<14} {}", "ARTIFACT", "STATUS", "PATH"),
            Kind::Audit => format!("{:<20} {:<14} {}", "ARTIFACT", "STATUS", "DETAIL"),
            Kind::Archive => format!("{:<22} {:<14} {}", "ARTIFACT", "STATUS", "PATH"),
        }
    }

    /// Whether the footer carries `Verified Anchors` and `Verification Gaps`
    /// (the audit verifier prints status and problems only).
    pub fn prints_counts(self) -> bool {
        !matches!(self, Kind::Audit)
    }

    fn label_width(self) -> usize {
        match self {
            Kind::Archive => 22,
            Kind::Closeout | Kind::Audit => 20,
        }
    }

    fn missing_anchor(self) -> &'static str {
        match self {
            Kind::Closeout => "anchor missing from manifest",
            Kind::Audit | Kind::Archive => "anchor missing from packet",
        }
    }
}

/// The outcome of verifying one packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    /// Which packet.
    pub kind: Kind,
    /// `verified` or `attention-required`.
    pub status: &'static str,
    /// Anchors that matched.
    pub verified: usize,
    /// Anchors that could not be checked for a benign reason (not recorded).
    pub gaps: usize,
    /// Anchors that failed.
    pub problems: usize,
    /// Table rows, formatted as the shell build prints them.
    pub rows: Vec<String>,
    /// The lab root, for the format 1.1 `rel=` fallback.
    root: PathBuf,
}

impl VerifyResult {
    fn new(kind: Kind, root: &Path) -> Self {
        Self {
            kind,
            status: "verified",
            verified: 0,
            gaps: 0,
            problems: 0,
            rows: Vec::new(),
            root: root.to_path_buf(),
        }
    }

    /// Format 1.1 relocation: when the anchor line carries `rel=`, the file
    /// under *this* lab root is checked, and the recorded absolute path only
    /// when that one is missing. Review 2026-10-05: preferring the absolute
    /// path made a copied or restored root verify against the original's
    /// files while the original still existed. A v1 line has no `rel=`, so
    /// v1 verdicts are unchanged; a `rel=` that is absolute or climbs out
    /// with `..` is ignored.
    fn resolve(&self, path: &str, line: &str) -> String {
        let rel = Path::new(anchor_token(line, "rel"));
        let inside = !rel.as_os_str().is_empty()
            && rel
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
        if inside {
            let candidate = self.root.join(rel);
            if file_exists(&candidate) {
                return candidate.display().to_string();
            }
        }
        path.to_owned()
    }

    fn row(&mut self, label: &str, status: &str, path: &str, detail: &str) {
        let w = self.kind.label_width();
        if detail.is_empty() {
            self.rows.push(format!("{label:<w$} {status:<14} {path}"));
        } else {
            self.rows
                .push(format!("{label:<w$} {status:<14} {path} ({detail})"));
        }
    }

    fn finish(&mut self) {
        self.status = if self.problems > 0 {
            "attention-required"
        } else {
            "verified"
        };
    }

    /// `atlas_closeout_verify_hash_anchor`: a missing path is a
    /// `not recorded` gap.
    fn hash_anchor(&mut self, text: &str, manifest_label: &str, display: &str) {
        let Some(line) = anchor_line(text, manifest_label) else {
            self.row(display, "unverifiable", "-", self.kind.missing_anchor());
            self.problems += 1;
            return;
        };
        let path = &self.resolve(anchor_path(line), line);
        if path.is_empty() {
            self.row(display, "unverifiable", "-", "not recorded");
            self.gaps += 1;
            return;
        }
        let expected = anchor_token(line, "sha256");
        if expected.is_empty() {
            if !file_exists(Path::new(path)) {
                self.row(display, "unverifiable", path, "not recorded");
                self.gaps += 1;
            } else {
                self.row(display, "unverifiable", path, "missing expected sha256");
                self.problems += 1;
            }
            return;
        }
        if !file_exists(Path::new(path)) {
            self.row(
                display,
                "missing",
                path,
                &format!("expected sha256={expected}"),
            );
            self.problems += 1;
            return;
        }
        let actual = sha_for_file(path);
        if actual == expected {
            self.row(display, "verified", path, "");
            self.verified += 1;
        } else {
            self.row(
                display,
                "changed",
                path,
                &format!("expected={expected} actual={actual}"),
            );
            self.problems += 1;
        }
    }

    /// `atlas_archive_verify_hash_anchor`: a `none` path is a
    /// `not-recorded` gap.
    fn hash_anchor_archive(&mut self, text: &str, manifest_label: &str, display: &str) {
        let Some(line) = anchor_line(text, manifest_label) else {
            self.row(display, "unverifiable", "-", self.kind.missing_anchor());
            self.problems += 1;
            return;
        };
        let path = &self.resolve(anchor_path(line), line);
        if path.is_empty() || path == "none" {
            self.row(
                display,
                "not-recorded",
                if path.is_empty() { "-" } else { path },
                "",
            );
            self.gaps += 1;
            return;
        }
        let expected = anchor_token(line, "sha256");
        if expected.is_empty() {
            self.row(display, "unverifiable", path, "missing expected sha256");
            self.problems += 1;
            return;
        }
        if !file_exists(Path::new(path)) {
            self.row(
                display,
                "missing",
                path,
                &format!("expected sha256={expected}"),
            );
            self.problems += 1;
            return;
        }
        let actual = sha_for_file(path);
        if actual == expected {
            self.row(display, "verified", path, "");
            self.verified += 1;
        } else {
            self.row(
                display,
                "changed",
                path,
                &format!("expected={expected} actual={actual}"),
            );
            self.problems += 1;
        }
    }

    /// `atlas_closeout_verify_ledger_anchor` / `atlas_archive_verify_ledger_anchor`.
    /// `allow_later` names the events that may follow the anchored prefix
    /// (`None` for the archive packet, which allows nothing after it).
    fn ledger_anchor(&mut self, text: &str, allow_later: Option<&[&str]>) {
        let Some(line) = anchor_line(text, "Operation ledger") else {
            self.row(
                "Operation Ledger",
                "unverifiable",
                "-",
                self.kind.missing_anchor(),
            );
            self.problems += 1;
            return;
        };
        let path = &self.resolve(anchor_path(line), line);
        let expected_events = anchor_token(line, "events");
        let expected_sha = anchor_token(line, "sha256");
        if path.is_empty() || expected_events.is_empty() || expected_sha.is_empty() {
            self.row(
                "Operation Ledger",
                "unverifiable",
                or_dash(path),
                "missing events or sha256",
            );
            self.problems += 1;
            return;
        }
        if !file_exists(Path::new(path)) {
            self.row(
                "Operation Ledger",
                "missing",
                path,
                &format!("expected events={expected_events} sha256={expected_sha}"),
            );
            self.problems += 1;
            return;
        }
        let actual_events = ledger_event_count(path);
        let actual_sha = sha_for_file(path);
        if actual_events.to_string() == expected_events && actual_sha == expected_sha {
            self.row(
                "Operation Ledger",
                "verified",
                path,
                &format!("events={actual_events}"),
            );
            self.verified += 1;
            return;
        }
        let plain_changed = format!(
            "expected_events={expected_events} actual_events={actual_events} expected_sha={expected_sha} actual_sha={actual_sha}"
        );
        if let Some(allow) = allow_later
            && let Some(exp) = parse_count(expected_events)
            && actual_events > exp
        {
            let disallowed = disallowed_later(path, exp, allow);
            if prefix_matches(path, exp, expected_sha) && disallowed.is_empty() {
                self.row(
                    "Operation Ledger",
                    "verified",
                    path,
                    &format!(
                        "events={actual_events} anchored_events={expected_events} later_allowed_events={}",
                        actual_events - exp
                    ),
                );
                self.verified += 1;
            } else {
                self.row(
                    "Operation Ledger",
                    "changed",
                    path,
                    &format!(
                        "{plain_changed} disallowed_later_events={}",
                        or_none(&disallowed)
                    ),
                );
                self.problems += 1;
            }
            return;
        }
        self.row("Operation Ledger", "changed", path, &plain_changed);
        self.problems += 1;
    }
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

fn or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(",")
    }
}

/// A non-negative decimal, or `None` (the shell's `atlas_closeout_numeric_token`).
pub(crate) fn parse_count(s: &str) -> Option<usize> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub(crate) fn prefix_matches(path: &str, n: usize, expected_sha: &str) -> bool {
    ledger::prefix_sha256(Path::new(path), n)
        .map(|h| h.as_str() == expected_sha)
        .unwrap_or(false)
}

/// Event names after the first `prefix` lines that are not in `allow`,
/// sorted and unique (`tail -n +N | jq ... | sort -u`). A line that is not
/// an object or has no `event` counts as `?`.
pub(crate) fn disallowed_later(path: &str, prefix: usize, allow: &[&str]) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return vec!["?".to_owned()];
    };
    let mut names: Vec<String> = text
        .lines()
        .skip(prefix)
        .filter(|l| !l.trim().is_empty())
        .map(|l| match lcoat_format::json::Value::parse(l) {
            Ok(lcoat_format::json::Value::Object(o)) if o.nonempty("event") => {
                o.str("event").to_owned()
            }
            _ => "?".to_owned(),
        })
        .filter(|e| !allow.contains(&e.as_str()))
        .collect();
    names.sort();
    names.dedup();
    names
}

fn read_packet(path: &str, kind: &str) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fail!("{kind} is not a file: {path}"),
        Err(e) => Err(e.into()),
    }
}

fn check_owner<S: State>(text: &str, kind: &str, path: &str, op: &Operation<S>) -> Result<()> {
    let id = field(text, "Operation ID");
    if id.is_empty() {
        fail!("{kind} is missing Operation ID: {path}");
    }
    if id != op.slug {
        fail!("{kind} belongs to '{id}', not '{}'", op.slug);
    }
    Ok(())
}

/// Events allowed after a closeout manifest's anchored ledger prefix.
pub const CLOSEOUT_ALLOW_LATER: &[&str] = &[
    "audit.packet.generated",
    "archive.packet.generated",
    "finding.review_packet.generated",
];
/// Events allowed after an audit packet's anchored ledger prefix.
pub const AUDIT_ALLOW_LATER: &[&str] = &["archive.packet.generated"];

/// `atlas_closeout_verify_markdown_manifest`.
pub fn closeout_verify<S: State>(op: &Operation<S>, manifest_path: &str) -> Result<VerifyResult> {
    let text = read_packet(manifest_path, "closeout manifest")?;
    check_owner(&text, "closeout manifest", manifest_path, op)?;
    let mut v = VerifyResult::new(Kind::Closeout, &op.root.root);
    v.hash_anchor(&text, "Latest report", "Latest Report");
    v.hash_anchor(&text, "Evidence manifest", "Evidence Manifest");
    v.hash_anchor(&text, "Latest handoff", "Latest Handoff");
    v.ledger_anchor(&text, Some(CLOSEOUT_ALLOW_LATER));
    v.hash_anchor(&text, "Operation env", "Operation Env");
    v.hash_anchor(&text, "Scope snapshot", "Scope Snapshot");
    v.hash_anchor(&text, "Evidence index", "Evidence Index");
    v.hash_anchor(&text, "Finding index", "Finding Index");
    v.hash_anchor(&text, "Validation index", "Validation Index");
    v.finish();
    Ok(v)
}

/// `atlas_audit_verify_markdown_packet`: two fixed rows, `ledger=` detail
/// form, and a footer without anchor counts.
pub fn audit_verify<S: State>(op: &Operation<S>, packet_path: &str) -> Result<VerifyResult> {
    let text = read_packet(packet_path, "audit packet")?;
    check_owner(&text, "audit packet", packet_path, op)?;
    let mut v = VerifyResult::new(Kind::Audit, &op.root.root);

    let ledger_line = anchor_line(&text, "Operation ledger").unwrap_or("");
    let ledger_file = &v.resolve(anchor_path(ledger_line), ledger_line);
    let expected_events = bullet_value(&text, "Events");
    let expected_sha = bullet_value(&text, "Ledger SHA256");
    let closeout_manifest = bullet_value(&text, "Closeout manifest");
    let expected_closeout_sha = bullet_value(&text, "Closeout manifest SHA256");

    let mut ledger_status = "verified";
    let mut ledger_detail = String::new();
    let mut actual_events = String::new();
    let mut actual_sha = String::new();
    if ledger_file.is_empty() || expected_events.is_empty() || expected_sha.is_empty() {
        ledger_status = "unverifiable";
        v.problems += 1;
    } else if !file_exists(Path::new(ledger_file)) {
        ledger_status = "missing";
        v.problems += 1;
    } else {
        let n = ledger_event_count(ledger_file);
        actual_events = n.to_string();
        actual_sha = sha_for_file(ledger_file);
        if actual_events == expected_events && actual_sha == expected_sha {
            ledger_detail = format!("events={actual_events}");
            v.verified += 1;
        } else if let Some(exp) = parse_count(expected_events)
            && n > exp
            && prefix_matches(ledger_file, exp, expected_sha)
            && disallowed_later(ledger_file, exp, AUDIT_ALLOW_LATER).is_empty()
        {
            ledger_detail = format!(
                "events={actual_events} anchored_events={expected_events} later_archive_events={}",
                n - exp
            );
            v.verified += 1;
        } else {
            ledger_status = "changed";
            let disallowed = match parse_count(expected_events) {
                Some(exp) => disallowed_later(ledger_file, exp, AUDIT_ALLOW_LATER),
                None => Vec::new(),
            };
            ledger_detail = format!(
                "expected_events={expected_events} actual_events={actual_events} expected_sha={expected_sha} actual_sha={actual_sha} disallowed_later_events={}",
                or_none(&disallowed)
            );
            v.problems += 1;
        }
    }

    let mut closeout_status = "not-recorded";
    let mut actual_closeout_sha = String::new();
    if !closeout_manifest.is_empty() && closeout_manifest != "-" && closeout_manifest != "none" {
        if expected_closeout_sha.is_empty() || expected_closeout_sha == "none" {
            closeout_status = "unverifiable";
            v.problems += 1;
        } else if !file_exists(Path::new(closeout_manifest)) {
            closeout_status = "missing";
            v.problems += 1;
        } else {
            actual_closeout_sha = sha_for_file(closeout_manifest);
            if actual_closeout_sha == expected_closeout_sha {
                closeout_status = "verified";
                v.verified += 1;
            } else {
                closeout_status = "changed";
                v.problems += 1;
            }
        }
    }

    if ledger_detail.is_empty() {
        ledger_detail = format!(
            "expected_events={} actual_events={} expected_sha={} actual_sha={}",
            or_unknown(expected_events),
            or_unknown(&actual_events),
            or_unknown(expected_sha),
            or_unknown(&actual_sha)
        );
    }
    v.rows.push(format!(
        "{:<20} {:<14} ledger={} {ledger_detail}",
        "Operation Ledger",
        ledger_status,
        or_unknown(ledger_file)
    ));
    v.rows.push(format!(
        "{:<20} {:<14} expected_sha={} actual_sha={} manifest={}",
        "Closeout Manifest",
        closeout_status,
        or_unknown(expected_closeout_sha),
        or_unknown(&actual_closeout_sha),
        or_unknown(closeout_manifest)
    ));
    v.finish();
    Ok(v)
}

/// `atlas_archive_verify_markdown_packet`.
pub fn archive_verify<S: State>(op: &Operation<S>, packet_path: &str) -> Result<VerifyResult> {
    let text = read_packet(packet_path, "archive packet")?;
    check_owner(&text, "archive packet", packet_path, op)?;
    let mut v = VerifyResult::new(Kind::Archive, &op.root.root);
    for (label, display) in [
        ("Latest report", "Latest Report"),
        ("Evidence manifest", "Evidence Manifest"),
        ("Latest handoff", "Latest Handoff"),
        ("Latest closeout", "Latest Closeout"),
        (
            "Latest accepted-risk review packet",
            "Accepted Risk Review Packet",
        ),
        ("Latest audit packet", "Latest Audit Packet"),
    ] {
        v.hash_anchor_archive(&text, label, display);
    }
    v.ledger_anchor(&text, None);
    v.finish();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_parse_like_the_shell() {
        assert_eq!(parse_count("18"), Some(18));
        assert_eq!(parse_count(""), None);
        assert_eq!(parse_count("1a"), None);
        assert_eq!(parse_count("-1"), None);
    }

    #[test]
    fn rows_pad_label_and_status_per_kind() {
        let mut v = VerifyResult::new(Kind::Closeout, Path::new("/"));
        v.row("Latest Report", "verified", "/p", "");
        v.row("Evidence Manifest", "unverifiable", "-", "not recorded");
        assert_eq!(v.rows[0], "Latest Report        verified       /p");
        assert_eq!(
            v.rows[1],
            "Evidence Manifest    unverifiable   - (not recorded)"
        );
        let mut a = VerifyResult::new(Kind::Archive, Path::new("/"));
        a.row("Accepted Risk Review Packet", "not-recorded", "none", "");
        assert_eq!(a.rows[0], "Accepted Risk Review Packet not-recorded   none");
        assert_eq!(
            Kind::Archive.column_header(),
            "ARTIFACT               STATUS         PATH"
        );
        assert_eq!(
            Kind::Audit.column_header(),
            "ARTIFACT             STATUS         DETAIL"
        );
        assert!(!Kind::Audit.prints_counts());
    }

    #[test]
    fn disallowed_later_lists_sorted_unique_events() {
        let dir = std::env::temp_dir().join(format!("lcoat-disallowed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ledger.ndjson");
        std::fs::write(
            &p,
            "{\"event\":\"op.started\"}\n{\"event\":\"archive.packet.generated\"}\n{\"event\":\"finding.recorded\"}\n{\"event\":\"finding.recorded\"}\n{\"x\":1}\n",
        )
        .unwrap();
        let path = p.display().to_string();
        assert_eq!(
            disallowed_later(&path, 1, AUDIT_ALLOW_LATER),
            ["?", "finding.recorded"]
        );
        assert!(disallowed_later(&path, 4, AUDIT_ALLOW_LATER) == ["?"]);
        assert!(disallowed_later(&path, 9, AUDIT_ALLOW_LATER).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
