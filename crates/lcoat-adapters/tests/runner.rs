//! The runner against a real operation: the event order, the capture, the
//! refusals, and the approval gate for Tier 3.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use lcoat_adapters::{RunParams, run};
use lcoat_core::approval::{self, GrantParams};
use lcoat_core::ledger;
use lcoat_core::metadata::MetadataOnly;
use lcoat_core::operation::{NewTarget, Operation, StartParams, add_target};
use lcoat_core::root::LabRoot;
use lcoat_core::tier::Tier;
use lcoat_format::clock::Utc;

fn fresh(name: &str) -> (LabRoot, PathBuf) {
    let dir = std::env::temp_dir().join(format!("lcoat-runner-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = LabRoot::at(&dir).unwrap();
    declare(&root, "127.0.0.1", "in-scope");
    (root, dir)
}

/// `target add <name> <name>` with the given scope status.
fn declare(root: &LabRoot, name: &str, scope_status: &str) {
    root.ensure_layout().unwrap();
    add_target(
        root,
        &NewTarget {
            name: name.into(),
            address: name.into(),
            scope_status: scope_status.into(),
            criticality: "low".into(),
            ..Default::default()
        },
    )
    .unwrap();
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn script_run_records_events_and_captures_evidence() {
    let (root, dir) = fresh("script");
    let (op, _) = Operation::start(
        &root,
        &StartParams {
            name: "r".into(),
            target: "127.0.0.1".into(),
            ..Default::default()
        },
    )
    .unwrap();

    let out = run(
        &op,
        &RunParams {
            adapter: "script".into(),
            target: String::new(),
            args: args(&["--tier", "1", "--", "/bin/echo", "hello", "world"]),
            timeout: None,
        },
    )
    .unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.tier, Tier::PassiveRecon);
    assert!(out.evidence_id.starts_with("ev_"));
    assert!(!out.vantage.is_empty());
    let stored = std::fs::read_to_string(
        op.dir
            .join(format!("evidence/{}/script-output.txt", out.evidence_id)),
    )
    .unwrap();
    assert_eq!(stored, "hello world\n");
    assert!(
        std::fs::read_dir(op.dir.join("tmp"))
            .map(|mut d| d.next().is_none())
            .unwrap_or(true),
        "capture temp removed"
    );

    let names: Vec<String> = op
        .events()
        .unwrap()
        .iter()
        .map(|e| e.event.clone())
        .collect();
    assert_eq!(
        names,
        [
            "op.started",
            "scope.preflight",
            "adapter.started",
            "scope.preflight",
            "artifact.created",
            "adapter.finished"
        ]
    );
    let events = ledger::read(&op.dir).unwrap();
    assert!(
        events[2].detail.contains("vantage=") && events[2].detail.contains("vantage_addr="),
        "{}",
        events[2].detail
    );
    assert!(
        events[5]
            .detail
            .starts_with("adapter=script exit=0 duration_ms=")
    );
    assert_eq!(events[5].status, "ok");
    let ev = lcoat_core::evidence::latest(&op.dir, "").unwrap();
    assert_eq!(ev[0].kind, "adapter-output");
    assert_eq!(ev[0].vantage, out.vantage);

    // A failing tool is still captured, with status error.
    let out = run(
        &op,
        &RunParams {
            adapter: "script".into(),
            target: String::new(),
            args: args(&["--tier", "1", "/bin/sh", "-c", "echo oops >&2; exit 2"]),
            timeout: None,
        },
    )
    .unwrap();
    assert_eq!(out.exit_code, 2);
    let stored = std::fs::read_to_string(
        op.dir
            .join(format!("evidence/{}/script-output.txt", out.evidence_id)),
    )
    .unwrap();
    assert_eq!(stored, "\n--- stderr ---\noops\n");
    assert_eq!(op.events().unwrap().last().unwrap().status, "error");

    // Timeout: recorded, not fatal.
    let out = run(
        &op,
        &RunParams {
            adapter: "script".into(),
            target: String::new(),
            args: args(&["--tier", "1", "/bin/sleep", "5"]),
            timeout: Some(Duration::from_millis(200)),
        },
    )
    .unwrap();
    assert!(out.timed_out);
    assert!(
        op.events()
            .unwrap()
            .last()
            .unwrap()
            .detail
            .contains("timeout_s=0")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refusals_happen_before_anything_runs() {
    let (root, dir) = fresh("refuse");
    let (op, _) = Operation::start(
        &root,
        &StartParams {
            name: "r".into(),
            target: "127.0.0.1".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let before = op.events().unwrap().len();

    // Unknown adapter and metasploit: no event at all.
    assert!(
        run(
            &op,
            &RunParams {
                adapter: "metasploit".into(),
                target: String::new(),
                args: vec![],
                timeout: None
            }
        )
        .unwrap_err()
        .to_string()
        .contains("Tier 4 or above")
    );
    assert!(
        run(
            &op,
            &RunParams {
                adapter: "zzz".into(),
                target: String::new(),
                args: vec![],
                timeout: None
            }
        )
        .unwrap_err()
        .to_string()
        .contains("unknown adapter")
    );
    // nmap positional: a parse error, no event.
    let err = run(
        &op,
        &RunParams {
            adapter: "nmap".into(),
            target: String::new(),
            args: args(&["10.0.0.9"]),
            timeout: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("positional argument"));
    assert_eq!(op.events().unwrap().len(), before);

    // Out-of-scope target: denied preflight recorded, nothing runs.
    let err = run(
        &op,
        &RunParams {
            adapter: "script".into(),
            target: "10.9.9.9".into(),
            args: args(&["--tier", "1", "/bin/echo", "x"]),
            timeout: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("outside active operation scope"));
    let events = op.events().unwrap();
    assert_eq!(events.last().unwrap().event, "scope.preflight");
    assert_eq!(events.last().unwrap().status, "denied");

    // Tier 3 needs an approval; with one it runs.
    let err = run(
        &op,
        &RunParams {
            adapter: "script".into(),
            target: String::new(),
            args: args(&["--tier", "3", "/bin/echo", "probe"]),
            timeout: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("approval required"), "{err}");
    approval::grant(
        &op,
        &GrantParams {
            capability: Tier::SafeValidation,
            reason: MetadataOnly::scan("client signed off").unwrap(),
            expires_at: Utc::parse("2030-01-01T00:00:00Z").unwrap(),
        },
    )
    .unwrap();
    let out = run(
        &op,
        &RunParams {
            adapter: "script".into(),
            target: String::new(),
            args: args(&["--tier", "3", "/bin/echo", "probe"]),
            timeout: None,
        },
    )
    .unwrap();
    assert_eq!(out.tier, Tier::SafeValidation);
    assert_eq!(out.exit_code, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Field run 1: an operation on a target that was never declared, or not
/// declared in-scope, ran a Tier 2 nmap scan against the bare name. Starting
/// on an undeclared target is refused, and a target whose scope status is
/// not `in-scope` cannot be contacted at any tier above 0.
#[test]
fn only_declared_in_scope_targets_are_contacted() {
    let (root, dir) = fresh("declared");
    let err = Operation::start(
        &root,
        &StartParams {
            name: "x".into(),
            target: "fedora-lan".into(),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("unknown target: fedora-lan"),
        "{err}"
    );
    assert!(
        !dir.join("sessions/x").exists(),
        "refused start left a directory"
    );

    for status in ["unknown", "review"] {
        let name = format!("box-{status}");
        declare(&root, &name, status);
        let (op, _) = Operation::start(
            &root,
            &StartParams {
                name: format!("op-{status}"),
                target: name.clone(),
                ..Default::default()
            },
        )
        .unwrap();
        let err = run(
            &op,
            &RunParams {
                adapter: "script".into(),
                target: String::new(),
                args: args(&["--tier", "1", "--", "/bin/echo", "x"]),
                timeout: None,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("scope status '{status}'")),
            "{err}"
        );
        let events = op.events().unwrap();
        let last = events.last().unwrap();
        assert_eq!(last.event, "scope.preflight");
        assert!(
            last.detail
                .contains(&format!("target-scope-status={status}")),
            "{}",
            last.detail
        );
        assert!(!events.iter().any(|e| e.event == "adapter.started"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review 2026-10-05: a DNS name was resolved by the vantage probe and
/// again by the tool, so the trail could name one address while the scan
/// hit another. The runner now resolves once and records the IP; a name
/// that does not resolve is refused before anything runs.
#[test]
fn a_dns_name_is_resolved_once_and_recorded() {
    for (target, resolves) in [("localhost", true), ("no-such-host.invalid", false)] {
        let (root, dir) = fresh(&format!("dns-{resolves}"));
        declare(&root, target, "in-scope");
        let (op, _) = Operation::start(
            &root,
            &StartParams {
                name: "dns".into(),
                target: target.into(),
                ..Default::default()
            },
        )
        .unwrap();
        let result = run(
            &op,
            &RunParams {
                adapter: "script".into(),
                target: String::new(),
                args: args(&["--tier", "1", "--", "/bin/echo"]),
                timeout: None,
            },
        );
        let events = ledger::read(&op.dir).unwrap();
        let started: Vec<_> = events
            .iter()
            .filter(|e| e.event == "adapter.started")
            .collect();
        if resolves {
            result.unwrap();
            assert!(
                started[0]
                    .detail
                    .contains(" target=localhost resolved=127."),
                "{}",
                started[0].detail
            );
        } else {
            let e = result.unwrap_err().to_string();
            assert!(
                e.contains("does not resolve") || e.contains("no IPv4 address"),
                "{e}"
            );
            let last = events.last().unwrap();
            assert_eq!(
                (last.event.as_str(), last.status.as_str()),
                ("adapter.refused", "denied")
            );
            assert!(
                last.detail.ends_with("reason=unresolved"),
                "{}",
                last.detail
            );
            assert!(started.is_empty(), "nothing ran for an unresolved name");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
