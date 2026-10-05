//! The operation trust chain: readiness, archive status, the three packet
//! verifications and the evidence artifact re-hash, folded into one status
//! and one next step.

use std::path::Path;

use crate::bundle;
use crate::error::Result;
use crate::evidence;
use crate::operation::{Operation, State as OpState};
use crate::readiness::{self, State};
use crate::root::file_exists;

use super::verify::{archive_verify, audit_verify, closeout_verify};

/// The metadata-chain state of an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct TrustChain {
    /// `current`, `incomplete` or `attention-required`.
    pub status: &'static str,
    pub next_step: String,
    pub readiness: State,
    pub archive_status: &'static str,
    pub closeout_verification: &'static str,
    pub closeout_problems: usize,
    pub audit_verification: &'static str,
    pub archive_verification: &'static str,
    pub review_verification: &'static str,
    /// `-` when not required or missing.
    pub review_path: String,
    pub closeout_path: String,
    pub audit_path: String,
    pub archive_path: String,
    /// Re-hash of every stored evidence artifact.
    pub evidence_verification: &'static str,
    pub evidence_checked: usize,
    pub evidence_problems: usize,
    /// Format 1.1: the latest recorded evidence bundle, re-verified.
    /// `not-recorded` when there is none; otherwise the status of
    /// [`crate::bundle::verify_in_op`], or `missing` when its directory is gone.
    pub bundle_verification: &'static str,
    /// The bundle directory, `-` when none is recorded.
    pub bundle_path: String,
    pub bundle_problems: usize,
}

/// The next step when the chain is current.
pub const CURRENT_NEXT_STEP: &str = "Metadata trust chain is current.";

/// `atlas_audit_closeout_verification_status`: status, path, problems.
pub fn closeout_verification_status<S: OpState>(
    op: &Operation<S>,
    st: &State,
) -> (&'static str, String, usize) {
    if !st.closeout.present() {
        return ("missing", "-".into(), 0);
    }
    let path = st.closeout.detail.clone();
    if path.is_empty() || !file_exists(Path::new(&path)) {
        return (
            "missing",
            if path.is_empty() { "-".into() } else { path },
            1,
        );
    }
    match closeout_verify(op, &path) {
        Ok(res) => (res.status, path, res.problems),
        Err(_) => ("attention-required", path, 1),
    }
}

/// Verify the latest audit packet: status and path.
pub fn audit_verification_status<S: OpState>(
    op: &Operation<S>,
    st: &State,
) -> (&'static str, String) {
    if !st.audit_packet.present() {
        return ("missing", "-".into());
    }
    let path = st.audit_packet.detail.clone();
    if !file_exists(Path::new(&path)) {
        return ("missing", path);
    }
    match audit_verify(op, &path) {
        Ok(res) if res.status == "verified" => ("verified", path),
        _ => ("attention-required", path),
    }
}

/// `atlas_archive_review_packet_verification_status`: not required without
/// accepted risks; otherwise the latest recorded packet must exist and pass
/// [`super::review::verify`].
pub fn review_verification_status<S: OpState>(
    op: &Operation<S>,
    st: &State,
) -> (&'static str, String) {
    if st.accepted_count == 0 {
        return ("not-required", "-".into());
    }
    if !st.review_packet.present() {
        return ("missing", "-".into());
    }
    let path = st.review_packet.detail.clone();
    if !file_exists(Path::new(&path)) {
        return ("missing", path);
    }
    match super::review::verify(op, &path) {
        Ok(r) if r.problems == 0 => ("verified", path),
        _ => ("attention-required", path),
    }
}

/// `atlas_archive_status`.
pub fn archive_status(st: &State, closeout: &str, audit: &str, review: &str) -> &'static str {
    if st.status != "ready" || st.report_fresh != "current" {
        return "attention-required";
    }
    if st.bundle_fresh == "stale"
        || st.handoff_fresh == "stale"
        || st.closeout_fresh == "stale"
        || (st.accepted_count > 0 && st.review_fresh == "stale")
        || st.audit_fresh == "stale"
        || st.archive_fresh == "stale"
    {
        return "attention-required";
    }
    if !st.closeout.present()
        || (st.accepted_count > 0 && !st.review_packet.present())
        || !st.audit_packet.present()
        || !st.archive_packet.present()
    {
        return "incomplete";
    }
    if closeout != "verified"
        || (st.accepted_count > 0 && review != "verified")
        || audit != "verified"
    {
        return "attention-required";
    }
    "current"
}

/// `atlas_archive_next_step`.
pub fn archive_next_step(st: &State, closeout: &str, audit: &str, review: &str) -> String {
    let s = if st.status != "ready" {
        st.next_step
    } else if st.report_fresh != "current" {
        "Refresh the operation report before archiving."
    } else if st.bundle_fresh == "stale" {
        "Regenerate the evidence bundle if the archive includes handoff evidence."
    } else if st.handoff_fresh == "stale" {
        "Regenerate the handoff packet if the archive includes handoff materials."
    } else if !st.closeout.present() {
        "Generate a closeout manifest before final archive review."
    } else if st.closeout_fresh == "stale" {
        "Regenerate the closeout manifest before final archive review."
    } else if closeout != "verified" {
        "Resolve closeout verification issues before final archive review."
    } else if st.accepted_count > 0 && !st.review_packet.present() {
        "Generate an accepted-risk review packet before final archive review."
    } else if st.accepted_count > 0 && st.review_fresh == "stale" {
        "Regenerate the accepted-risk review packet before final archive review."
    } else if st.accepted_count > 0 && review != "verified" {
        "Resolve accepted-risk review packet verification issues before final archive review."
    } else if !st.audit_packet.present() {
        "Generate an audit packet before final archive review."
    } else if st.audit_fresh == "stale" {
        "Regenerate the audit packet before final archive review."
    } else if audit != "verified" {
        "Resolve audit packet verification issues before final archive review."
    } else if !st.archive_packet.present() {
        "Generate an archive packet before final archive review."
    } else if st.archive_fresh == "stale" {
        "Regenerate the archive packet before final archive review."
    } else {
        "Archive snapshot is current."
    };
    s.to_owned()
}

/// Gather the metadata-chain state for an operation.
pub fn collect_trust_chain<S: OpState>(op: &Operation<S>) -> Result<TrustChain> {
    let st = readiness::collect(op)?;
    let (closeout_verification, closeout_path, closeout_problems) =
        closeout_verification_status(op, &st);
    let (audit_verification, audit_path) = audit_verification_status(op, &st);
    let (review_verification, review_path) = review_verification_status(op, &st);
    let archive = archive_status(
        &st,
        closeout_verification,
        audit_verification,
        review_verification,
    );

    let mut archive_path = String::new();
    let mut archive_verification = "missing";
    if st.archive_packet.present() && file_exists(Path::new(&st.archive_packet.detail)) {
        archive_path = st.archive_packet.detail.clone();
        archive_verification = match archive_verify(op, &archive_path) {
            Ok(res) if res.status == "verified" => "verified",
            _ => "attention-required",
        };
    }

    let (checks, evidence_problems) = evidence::verify_artifacts(&op.dir)?;
    let evidence_verification = if evidence_problems > 0 {
        "attention-required"
    } else {
        "verified"
    };

    let (bundle_verification, bundle_path, bundle_problems) = bundle_status(op, &st)?;

    let (status, next_step) = if evidence_problems > 0 {
        (
            "attention-required",
            "Evidence artifacts changed or missing since capture; run 'lcoat evidence verify' and investigate before trusting this operation."
                .to_owned(),
        )
    } else if bundle_problems > 0 {
        (
            "attention-required",
            "Evidence bundle changed or incomplete since it was written; run 'lcoat evidence bundle-verify' and investigate before sharing it."
                .to_owned(),
        )
    } else if archive != "current" {
        (
            archive,
            archive_next_step(
                &st,
                closeout_verification,
                audit_verification,
                review_verification,
            ),
        )
    } else if archive_verification != "verified" {
        (
            "attention-required",
            "Resolve archive packet verification issues before trust-chain closeout.".to_owned(),
        )
    } else {
        ("current", CURRENT_NEXT_STEP.to_owned())
    };

    Ok(TrustChain {
        status,
        next_step,
        readiness: st,
        archive_status: archive,
        closeout_verification,
        closeout_problems,
        audit_verification,
        archive_verification,
        review_verification,
        review_path,
        closeout_path,
        audit_path,
        archive_path,
        evidence_verification,
        evidence_checked: checks.len(),
        evidence_problems,
        bundle_verification,
        bundle_path,
        bundle_problems,
    })
}

/// Re-verify the latest recorded bundle: status, directory, problems.
fn bundle_status<S: OpState>(
    op: &Operation<S>,
    st: &State,
) -> Result<(&'static str, String, usize)> {
    if !st.bundle.present() {
        return Ok(("not-recorded", "-".into(), 0));
    }
    let r = bundle::Recorded::parse(&st.bundle.at, &st.bundle.detail);
    let Some(dir) = r.dir(&op.dir) else {
        return Ok(("attention-required", "-".into(), 1));
    };
    let path = dir.display().to_string();
    if !dir.is_dir() {
        return Ok(("missing", path, 1));
    }
    Ok(match bundle::verify_in_op(op, &dir, "") {
        Ok(v) => (v.status, path, v.problems),
        Err(_) => ("attention-required", path, 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness::Marker;

    fn ready() -> State {
        let m = |d: &str| Marker {
            at: "t".into(),
            line: 1,
            event: "e".into(),
            detail: d.into(),
        };
        State {
            evidence_count: 1,
            status: "ready",
            next_step: "Operation is ready to close.",
            report: m("/r"),
            report_fresh: "current",
            bundle_fresh: "missing",
            handoff_fresh: "current",
            closeout: m("/c"),
            closeout_fresh: "current",
            audit_packet: m("/a"),
            audit_fresh: "current",
            archive_packet: m("/z"),
            archive_fresh: "current",
            review_fresh: "missing",
            ..Default::default()
        }
    }

    #[test]
    fn archive_status_ladder() {
        let st = ready();
        assert_eq!(
            archive_status(&st, "verified", "verified", "not-required"),
            "current"
        );
        assert_eq!(
            archive_next_step(&st, "verified", "verified", "not-required"),
            "Archive snapshot is current."
        );
        assert_eq!(
            archive_status(&st, "attention-required", "verified", "not-required"),
            "attention-required"
        );
        assert_eq!(
            archive_next_step(&st, "attention-required", "verified", "not-required"),
            "Resolve closeout verification issues before final archive review."
        );
        let mut s = ready();
        s.archive_packet = Marker::default();
        s.archive_fresh = "missing";
        assert_eq!(
            archive_status(&s, "verified", "verified", "not-required"),
            "incomplete"
        );
        assert_eq!(
            archive_next_step(&s, "verified", "verified", "not-required"),
            "Generate an archive packet before final archive review."
        );
        let mut s = ready();
        s.status = "attention-required";
        s.next_step = "Resolve, accept, or retest unresolved findings before closure.";
        assert_eq!(
            archive_status(&s, "verified", "verified", "not-required"),
            "attention-required"
        );
        assert_eq!(
            archive_next_step(&s, "verified", "verified", "not-required"),
            s.next_step
        );
        let mut s = ready();
        s.accepted_count = 1;
        assert_eq!(
            archive_status(&s, "verified", "verified", "missing"),
            "incomplete"
        );
    }
}
