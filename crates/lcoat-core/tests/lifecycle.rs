//! The full write-side lifecycle through the typestate, then every verifier
//! on the result, then tampering: a trust gate is only real if it can fail.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use lcoat_core::approval::{self, GrantParams};
use lcoat_core::evidence::{self, AddParams as EvidenceParams};
use lcoat_core::findings::{self, AcceptParams, AddParams as FindingParams};
use lcoat_core::metadata::MetadataOnly;
use lcoat_core::operation::{Loaded, NewTarget, Operation, StartParams, add_target};
use lcoat_core::packet;
use lcoat_core::readiness;
use lcoat_core::report;
use lcoat_core::root::LabRoot;
use lcoat_core::tier::Tier;
use lcoat_format::clock::Utc;

fn fresh_root(name: &str) -> (LabRoot, PathBuf) {
    let dir = std::env::temp_dir().join(format!("lcoat-lifecycle-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (LabRoot::at(&dir).unwrap(), dir)
}

fn m(s: &str) -> MetadataOnly {
    MetadataOnly::scan(s).unwrap()
}

#[test]
fn full_lifecycle_verifies_and_tampering_is_caught() {
    let (root, dir) = fresh_root("full");
    let recon = dir.join("recon.txt");
    std::fs::write(&recon, "PORT 22 open ssh\n").unwrap();
    add_target(
        &root,
        &NewTarget {
            name: "node".into(),
            address: "10.10.10.5".into(),
            scope_status: "in-scope".into(),
            criticality: "medium".into(),
            ..Default::default()
        },
    )
    .unwrap();

    let (op, _profile) = Operation::start(
        &root,
        &StartParams {
            name: "full-op".into(),
            target: "node".into(),
            profile: String::new(),
            notes: "authorized".into(),
        },
    )
    .unwrap();

    // Evidence: copy, hash, index, manifest, ledger.
    let ev = evidence::add(
        &op,
        &EvidenceParams {
            source: recon.clone(),
            kind: Some(m("scan-output")),
            target: None,
            classification: Some(m("public")),
            redacted: false,
            tool: String::new(),
        },
    )
    .unwrap();
    assert!(ev.id.starts_with("ev_"));
    assert!(dir.join("sessions/full-op").join(&ev.path).is_file());
    assert_eq!(evidence::manifest(&op.dir).unwrap().len(), 1);
    assert_eq!(evidence::manifest(&op.dir).unwrap()[0].bytes, 17);

    // Findings: add, then the lifecycle on a second one.
    let f = findings::add(
        &op,
        &FindingParams {
            title: Some(m("SSH exposed")),
            level: "observed".into(),
            severity: "low".into(),
            confidence: "high".into(),
            evidence: vec![ev.id.clone()],
            recommendation: Some(m("Restrict to the admin network")),
            ..Default::default()
        },
    )
    .unwrap();
    let unknown = findings::add(
        &op,
        &FindingParams {
            title: Some(m("x")),
            evidence: vec!["ev_missing".into()],
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(unknown.to_string().contains("unknown evidence id"));
    let g = findings::add(
        &op,
        &FindingParams {
            title: Some(m("Guest wifi")),
            severity: "medium".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let accepted = findings::accept(
        &op,
        &g.id,
        &AcceptParams {
            reason: m("isolated vlan"),
            owner: Some(m("netops")),
            expires: Some("2030-01-01".into()),
            evidence: vec![],
        },
    )
    .unwrap();
    assert_eq!(accepted.status, "accepted");
    assert_eq!(
        accepted.note,
        "accepted risk: isolated vlan owner=netops expires=2030-01-01"
    );
    let resolved = findings::resolve(&op, &f.id, &[], Some(m("firewalled"))).unwrap();
    assert_eq!(resolved.status, "resolved");
    assert_eq!(findings::latest(&op.dir, "").unwrap().len(), 2);
    assert!(findings::open(&op.dir, &op.target).unwrap().is_empty());
    // An accepted risk needs the shell's review packet before the archive
    // is complete; Lab Coat does not render that packet yet (phase 3), so
    // the chain honestly reports `incomplete` for it. Resolve it here so the
    // rest of the lifecycle can reach `current`.
    let st = readiness::collect(&op).unwrap();
    assert_eq!(st.accepted_count, 1);
    let reopened = findings::reopen(&op, &g.id, Some(m("vlan not isolated after all"))).unwrap();
    assert_eq!(reopened.status, "open");
    findings::resolve(&op, &g.id, &[ev.id.clone()], None).unwrap();
    assert_eq!(
        findings::latest(&op.dir, "")
            .unwrap()
            .iter()
            .filter(|f| f.status == "resolved")
            .count(),
        2
    );

    // Approvals: Tier 3 can be granted with reason + expiry; Tier 4 cannot.
    let expires = Utc::parse("2030-01-01T00:00:00Z").unwrap();
    assert!(!op.has_approval(Tier::SafeValidation, &op.target));
    approval::grant(
        &op,
        &GrantParams {
            capability: Tier::SafeValidation,
            reason: m("client ok"),
            expires_at: expires,
        },
    )
    .unwrap();
    assert!(op.has_approval(Tier::SafeValidation, &op.target));
    assert!(
        op.preflight(Tier::SafeValidation, "x", "node", "t")
            .unwrap()
            .allowed
    );
    let err = approval::grant(
        &op,
        &GrantParams {
            capability: Tier::IntrusiveValidation,
            reason: m("no"),
            expires_at: expires,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("above the Lab Coat ceiling"));
    assert!(
        !op.preflight(Tier::IntrusiveValidation, "x", "node", "t")
            .unwrap()
            .allowed
    );
    approval::revoke(&op, Tier::SafeValidation, &m("done")).unwrap();
    assert!(!op.has_approval(Tier::SafeValidation, &op.target));

    // Report and handoff, then close: ready, since nothing is open.
    let report_path = report::write(&op, "").unwrap();
    assert!(report_path.ends_with("reports/full-op-report.md"));
    let report_text = std::fs::read_to_string(&report_path).unwrap();
    assert!(report_text.contains("- Findings: 2 total, 1 observed, 1 inferred, 0 validated\n"));
    assert!(report_text.contains("- [low] SSH exposed: Restrict to the admin network Evidence: "));
    assert!(
        report_text.contains("## Commands Run\n\n- `atlas op start full-op node authorized`\n")
    );
    let handoff = packet::handoff(&op, "").unwrap();
    let st = readiness::collect(&op).unwrap();
    assert_eq!(st.status, "ready", "{}", st.next_step);
    let closed = op.close(st.status, &st.ledger_detail(false)).unwrap();

    // Packets in order; the signatures make the order a compile-time fact.
    let closeout = packet::closeout(&closed, "").unwrap();
    let audit = packet::audit(&closed, &closeout, "").unwrap();
    let archive = packet::archive(&closed, &audit, "").unwrap();
    let text = std::fs::read_to_string(&closeout.path).unwrap();
    assert!(
        text.contains("- Evidence manifest: `"),
        "manifest slot filled: {text}"
    );
    assert!(
        text.contains(" rel=sessions/full-op/ledger.ndjson"),
        "{text}"
    );
    assert!(text.contains("- Latest handoff: `"));
    assert!(text.contains(&format!(
        "sha256={} rel=sessions/full-op/handoff/full-op-handoff.md",
        handoff.sha256
    )));

    // Every verifier passes with zero problems.
    for (name, res) in [
        (
            "closeout",
            packet::closeout_verify(&closed, &closeout.path.display().to_string()).unwrap(),
        ),
        (
            "audit",
            packet::audit_verify(&closed, &audit.path.display().to_string()).unwrap(),
        ),
        (
            "archive",
            packet::archive_verify(&closed, &archive.path.display().to_string()).unwrap(),
        ),
    ] {
        assert_eq!(
            (name, res.status, res.problems),
            (name, "verified", 0),
            "{:?}",
            res.rows
        );
    }
    let (checks, problems) = evidence::verify_artifacts(&closed.dir).unwrap();
    assert_eq!((checks.len(), problems), (1, 0));
    let tc = packet::collect_trust_chain(&closed).unwrap();
    assert_eq!(tc.status, "current", "{}", tc.next_step);
    assert_eq!(
        lcoat_core::chain::verify(
            &lcoat_core::ledger::read_objects(&closed.ledger_file()).unwrap()
        ),
        lcoat_core::chain::ChainStatus::Verified
    );

    // The closeout verifies after a move of the whole root (format 1.1 rel=).
    let moved = dir.with_file_name(format!(
        "{}-moved",
        dir.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&moved);
    std::fs::rename(&dir, &moved).unwrap();
    let moved_root = LabRoot::at(&moved).unwrap();
    let moved_op = Operation::load(&moved_root, "full-op").unwrap();
    let res = packet::closeout_verify(
        &moved_op,
        &moved
            .join("sessions/full-op/closeout/full-op-closeout.md")
            .display()
            .to_string(),
    )
    .unwrap();
    assert_eq!(
        (res.status, res.problems),
        ("verified", 0),
        "{:?}",
        res.rows
    );
    std::fs::rename(&moved, &dir).unwrap();

    // Tamper 1: a disallowed event after closeout.
    let reloaded = match Operation::load(&root, "full-op")
        .unwrap()
        .classify()
        .unwrap()
    {
        Loaded::Closed(o) => o,
        Loaded::Active(_) => panic!("closed"),
    };
    lcoat_core::ledger::Ledger::of(&reloaded.dir)
        .append(lcoat_core::ledger::Event {
            event: "finding.recorded".into(),
            op: "full-op".into(),
            target: "node".into(),
            capability: "read-only".into(),
            tool: "atlas".into(),
            status: "ok".into(),
            detail: "tampered".into(),
            ..Default::default()
        })
        .unwrap();
    let res = packet::closeout_verify(&reloaded, &closeout.path.display().to_string()).unwrap();
    assert_eq!(res.status, "attention-required");
    assert!(
        res.rows
            .iter()
            .any(|r| r.contains("disallowed_later_events=finding.recorded")),
        "{:?}",
        res.rows
    );

    // Tamper 2: edit the artifact; the index-based re-hash and the manifest both disagree.
    std::fs::write(
        dir.join("sessions/full-op").join(&ev.path),
        "PORT 22 closed\n",
    )
    .unwrap();
    let (checks, problems) = evidence::verify_artifacts(&reloaded.dir).unwrap();
    assert_eq!((checks[0].status, problems), ("changed", 1));

    // Tamper 3: rewrite a middle ledger event; the chain names it.
    let ledger_path = reloaded.ledger_file();
    let text = std::fs::read_to_string(&ledger_path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines[1] = lines[1]
        .replace("\"status\":\"allowed\"", "\"status\":\"denied\"")
        .replace("\"status\":\"ok\"", "\"status\":\"tampered\"");
    std::fs::write(&ledger_path, lines.join("\n") + "\n").unwrap();
    let status =
        lcoat_core::chain::verify(&lcoat_core::ledger::read_objects(&ledger_path).unwrap());
    assert!(
        matches!(
            status,
            lcoat_core::chain::ChainStatus::Broken { index: 1, .. }
        ),
        "{status:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn closed_operations_refuse_writes_by_type_and_by_record() {
    let (root, dir) = fresh_root("closed");
    let (op, _) = Operation::start(
        &root,
        &StartParams {
            name: "c".into(),
            target: "10.0.0.1".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let closed = op
        .close("attention-required", "readiness=attention-required force=1")
        .unwrap();
    // The write-side functions take Operation<Active>; the only way to get
    // one from a closed record is a refusal.
    let err = Operation::load(&root, "c")
        .unwrap()
        .into_active()
        .unwrap_err();
    assert!(err.to_string().contains("is closed; resume it first"));
    // Packets want Operation<Closed>: an active record is refused the same way.
    let active = closed.resume().unwrap();
    let err = Operation::load(&root, "c")
        .unwrap()
        .into_closed()
        .unwrap_err();
    assert!(err.to_string().contains("is still active"));
    drop(active);
    let _ = std::fs::remove_dir_all(&dir);
}
