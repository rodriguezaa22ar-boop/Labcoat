//! Core behaviour against the inherited golden fixtures (`fixtures/golden`,
//! written by the Atlas shell build at `23ba2d2`). Values pinned here were
//! computed independently with `jq -cS | sha256sum`.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use lcoat_core::ledger;
use lcoat_core::operation::{Operation, list_targets, resolve_target};
use lcoat_core::root::LabRoot;
use lcoat_core::scope::{self, load_profile};
use lcoat_core::tier::Tier;

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/golden")
}

/// A root whose sessions directory is the golden directory itself (the
/// fixture holds the operation directory directly, not under `sessions/`).
fn golden_root() -> LabRoot {
    let g = golden();
    LabRoot {
        root: g.clone(),
        state_dir: g.join("state"),
        targets_dir: g.join("targets"),
        sessions_dir: g.clone(),
        reports_dir: g.join("reports"),
        profiles_dir: g.join("profiles"),
        atlas_state: g.join("state/atlas"),
        active_file: g.join("state/atlas/active.env"),
    }
}

#[test]
fn ledger_verify_matches_shell_build() {
    let path = golden().join("learning-op-001/ledger.ndjson");
    let v = ledger::verify_operation_ledger(&path).unwrap();
    assert_eq!(v.event_count, 18);
    // tail -n1 ledger.ndjson | jq -cS . | sha256sum
    assert_eq!(
        v.head_event_hash.as_str(),
        "abd88a7fe5dbf8b017a73a9a8ae5e84a1afb396bde656f2d0d558eb2bc6a1b75"
    );
    // sha256sum ledger.ndjson (whole file) == prefix of all 18 lines
    assert_eq!(
        ledger::prefix_sha256(&path, 18).unwrap().as_str(),
        "ba36a56433f5a4153a1d430bb4632bfe7bdcc989adbf5438ba1ea667758f0c6f"
    );
    let events = ledger::read_path(&path).unwrap();
    assert_eq!(events.len(), 18);
    assert_eq!(events[0].event, "op.started");
    assert_eq!(events[0].line, 1);
    // Packets are generated after close, so the last event is the archive's.
    assert_eq!(events[17].event, "archive.packet.generated");
    assert_eq!(ledger::latest(&events, &["op.closed"]).unwrap().line, 15);
    assert_eq!(
        ledger::latest_except(
            &events,
            &[
                "archive.packet.generated",
                "audit.packet.generated",
                "closeout.manifest.generated"
            ]
        )
        .unwrap()
        .event,
        "op.closed"
    );
    let counts = ledger::count_by_event(&events);
    assert_eq!(counts.iter().map(|c| c.count).sum::<usize>(), 18);
}

#[test]
fn operation_loads_from_golden_state() {
    let root = golden_root();
    let op = Operation::load(&root, "learning-op-001").unwrap();
    assert_eq!(op.target, "demo-learning-node");
    assert_eq!(op.target_address, "192.168.100.50");
    assert_eq!(op.format_target(), "demo-learning-node -> 192.168.100.50");
    assert!(op.is_closed());
    assert_eq!(op.events().unwrap().len(), 18);
    let snap = op.snapshot().unwrap();
    assert_eq!(snap.profile, "htb-starting-point");
    assert_eq!(snap.target_scope_status, "in-scope");
    assert!(snap.blocked.contains("intrusive-validation"));
    // The snapshot governs: active-recon allowed, intrusive blocked.
    assert!(
        snap.preflight(Tier::ActiveRecon, "192.168.100.50", "nmap", |_| false)
            .allowed
    );
    let d = snap.preflight(Tier::IntrusiveValidation, "demo-learning-node", "x", |_| {
        true
    });
    assert_eq!(d.detail, "reason=x blocked-capability=intrusive-validation");
    assert_eq!(Operation::list(&root).unwrap().len(), 1);
    assert!(Operation::active_slug(&root).is_none());
}

#[test]
fn targets_and_profiles_from_golden_state() {
    let root = golden_root();
    let targets = list_targets(&root).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].slug, "demo-learning-node");
    let t = resolve_target(&root, "demo-learning-node").unwrap();
    assert_eq!(t.address, "192.168.100.50");
    assert_eq!(t.scope_status, "in-scope");
    let p = load_profile(&root.profiles_dir, "htb-starting-point").unwrap();
    assert_eq!(p.name, "htb-starting-point");
    assert!(p.blocked_capabilities.ends_with("intrusive-validation"));
    assert_eq!(
        scope::list_profile_files(&root.profiles_dir).unwrap().len(),
        1
    );
}

#[test]
fn readiness_matches_lite_byte_for_byte() {
    let root = golden_root();
    let op = Operation::load(&root, "learning-op-001").unwrap();
    let st = lcoat_core::readiness::collect(&op).unwrap();
    assert_eq!(st.status, "attention-required");
    assert_eq!(st.open_count, 2);
    assert_eq!(st.report_fresh, "current");
    assert_eq!(st.bundle_fresh, "missing");
    assert_eq!(st.archive_fresh, "current");
    let rendered = lcoat_core::readiness::join(&st.lines(&op));
    let expected =
        std::fs::read_to_string(golden().join("../expected/learning-op-001.readiness.txt"))
            .unwrap();
    assert_eq!(rendered, expected);
}

/// The golden packets record absolute paths into the shell checkout that
/// wrote them, so their verifiers can only be exercised where that checkout
/// exists (the conformance container). Elsewhere this test reports and
/// skips; `conformance/tamper.sh` is the portable gate.
fn shell_root_present() -> bool {
    Path::new("/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/ledger.ndjson").is_file()
}

/// The verifier rows between the second and third rule lines of a recorded
/// shell-build output (the column header line excluded).
fn expected_rows(name: &str) -> Vec<String> {
    let text =
        std::fs::read_to_string(golden().join(format!("../expected/learning-op-001.{name}.txt")))
            .unwrap();
    let rule = "------------------------------------------------------------";
    let mut rules = 0;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line == rule {
            rules += 1;
            continue;
        }
        if rules == 2 {
            rows.push(line.to_owned());
        }
    }
    rows.remove(0); // ARTIFACT STATUS PATH|DETAIL
    rows
}

#[test]
fn packet_verifiers_match_shell_rows_on_golden_state() {
    if !shell_root_present() {
        eprintln!("skipping: golden packets point at a shell checkout that is not present");
        return;
    }
    let root = golden_root();
    let op = Operation::load(&root, "learning-op-001").unwrap();
    let packet = |sub: &str| lcoat_core::packet::latest_in_ledger(&op, sub).unwrap();

    let v = lcoat_core::packet::closeout_verify(&op, &packet("closeout")).unwrap();
    assert_eq!(v.rows, expected_rows("op-verify"));
    assert_eq!(
        (v.status, v.verified, v.gaps, v.problems),
        ("verified", 7, 2, 0)
    );

    let v = lcoat_core::packet::audit_verify(&op, &packet("audit")).unwrap();
    assert_eq!(v.rows, expected_rows("audit-verify"));
    assert_eq!(
        (v.status, v.verified, v.gaps, v.problems),
        ("verified", 2, 0, 0)
    );

    let v = lcoat_core::packet::archive_verify(&op, &packet("archive")).unwrap();
    assert_eq!(v.rows, expected_rows("archive-verify"));
    assert_eq!(
        (v.status, v.verified, v.gaps, v.problems),
        ("verified", 5, 2, 0)
    );

    let tc = lcoat_core::packet::collect_trust_chain(&op).unwrap();
    assert_eq!(tc.status, "attention-required");
    assert_eq!(
        tc.next_step,
        "Resolve, accept, or retest unresolved findings before closure."
    );
    assert_eq!(tc.closeout_verification, "verified");
    assert_eq!(tc.audit_verification, "verified");
    assert_eq!(tc.archive_verification, "verified");
    assert_eq!(
        (
            tc.evidence_verification,
            tc.evidence_checked,
            tc.evidence_problems
        ),
        ("verified", 1, 0)
    );
}

#[test]
fn receipts_verify_and_replay_like_the_shell_build() {
    let dir = golden().join("demo-site-receipts");
    let names = ["demo-site-boundary", "demo-site-packet", "demo-site-replay"];
    for name in names {
        let v = lcoat_core::receipt::verify_file(
            &dir.join(format!("{name}.json")).display().to_string(),
        )
        .unwrap();
        let json =
            lcoat_format::canonical::compact(&lcoat_format::json::Value::Object(v.to_json()));
        let expected =
            std::fs::read(golden().join(format!("../expected/receipt-verify.{name}.json")))
                .unwrap();
        assert_eq!(
            String::from_utf8(json).unwrap() + "\n",
            String::from_utf8(expected).unwrap(),
            "{name}"
        );
    }
    let paths: Vec<String> = names
        .iter()
        .map(|n| dir.join(format!("{n}.json")).display().to_string())
        .collect();
    let r = lcoat_core::receipt::replay(&paths).unwrap();
    assert_eq!(r.receipt_count, 3);
    assert_eq!(
        r.first_event_hash,
        "80b04f94b1094430da9f24b7896f1dfdd0e9083fa7f98021d12c5529aa3a17fd"
    );
    let json = lcoat_format::canonical::compact(&lcoat_format::json::Value::Object(r.to_json()));
    let expected =
        std::fs::read_to_string(golden().join("../expected/receipt-replay.demo-site.json"))
            .unwrap();
    // The shell recorded the chain with bare file names; strip our directory.
    let rendered =
        (String::from_utf8(json).unwrap() + "\n").replace(&format!("{}/", dir.display()), "");
    assert_eq!(rendered, expected);
    // Wrong order breaks the chain.
    let reversed: Vec<String> = paths.iter().rev().cloned().collect();
    assert!(lcoat_core::receipt::replay(&reversed).is_err());
}
