//! The write side through the real binary: a full lifecycle in a fresh root,
//! then crash injection at every step of the transaction-order table, with
//! the verifiers reporting the documented state each time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fresh(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lcoat-cli-life-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn lcoat(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lcoat"))
        .args(args)
        .env_remove("LAB_ROOT")
        .env_remove("LCOAT_TEST_CRASH_AT")
        .env("LCOAT_ROOT", root)
        .env("LCOAT_NOW", "2026-10-02T07:40:00Z")
        .env("LCOAT_OPERATOR", "tester")
        .output()
        .unwrap()
}

fn crash_at(root: &Path, point: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lcoat"))
        .args(args)
        .env_remove("LAB_ROOT")
        .env("LCOAT_ROOT", root)
        .env("LCOAT_TEST_CRASH_AT", point)
        .env("LCOAT_NOW", "2026-10-02T07:40:00Z")
        .output()
        .unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn err(out: &Output) -> String {
    assert!(
        !out.status.success(),
        "expected failure, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn kv(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or("")
        .to_owned()
}

#[test]
fn full_lifecycle_through_the_binary() {
    let root = fresh("full");
    let recon = root.join("recon.txt");
    std::fs::write(&recon, "PORT 22 open ssh\n").unwrap();

    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "demo-node",
            "10.10.10.5",
            "--scope-status",
            "in-scope",
            "--criticality",
            "medium",
            "--tag",
            "prototype",
        ],
    ));
    assert!(ok(&lcoat(&root, &["target", "list"])).contains("demo-node"));
    let start = ok(&lcoat(
        &root,
        &[
            "op",
            "start",
            "--profile",
            "default",
            "full-op",
            "demo-node",
            "authorized",
            "lifecycle",
        ],
    ));
    assert_eq!(kv(&start, "active_operation"), "full-op");
    assert!(ok(&lcoat(&root, &["op", "list"])).contains("full-op"));

    // Secrets are refused at the flag, before anything is written.
    let e = err(&lcoat(
        &root,
        &["finding", "add", "leak", "--impact", "password=hunter2"],
    ));
    assert!(e.contains("--impact: refusing to record"), "{e}");

    let ev = ok(&lcoat(
        &root,
        &[
            "evidence",
            "add",
            recon.to_str().unwrap(),
            "--kind",
            "scan-output",
            "--classification",
            "public",
        ],
    ));
    let ev_id = kv(&ev, "id");
    assert!(ev_id.starts_with("ev_"));
    let f = ok(&lcoat(
        &root,
        &[
            "finding",
            "add",
            "SSH exposed",
            "--level",
            "observed",
            "--severity",
            "low",
            "--confidence",
            "high",
            "--evidence",
            &ev_id,
        ],
    ));
    let f_id = kv(&f, "id");
    assert!(ok(&lcoat(&root, &["finding", "list"])).contains(&f_id));
    ok(&lcoat(
        &root,
        &["finding", "note", &f_id, "seen on both interfaces"],
    ));
    ok(&lcoat(
        &root,
        &["finding", "resolve", &f_id, "--note", "firewalled"],
    ));

    // scope check records a denial for an outside target and refuses.
    let e = err(&lcoat(
        &root,
        &["scope", "check", "active-recon", "10.9.9.9"],
    ));
    assert!(e.contains("outside active operation scope"));
    assert!(
        ok(&lcoat(
            &root,
            &["scope", "check", "active-recon", "demo-node"]
        ))
        .contains("ok: scope allowed")
    );

    // Approvals: no open-ended grants, no Tier 4.
    assert!(
        err(&lcoat(
            &root,
            &["approval", "grant", "safe-validation", "--reason", "x"]
        ))
        .contains("--expires")
    );
    assert!(
        err(&lcoat(
            &root,
            &[
                "approval",
                "grant",
                "intrusive-validation",
                "--reason",
                "x",
                "--expires",
                "7d"
            ]
        ))
        .contains("above the Lab Coat ceiling")
    );
    let g = ok(&lcoat(
        &root,
        &[
            "approval",
            "grant",
            "safe-validation",
            "--reason",
            "client signed off",
            "--expires",
            "7d",
        ],
    ));
    assert_eq!(kv(&g, "approved_by"), "tester");
    assert!(ok(&lcoat(&root, &["approval", "list"])).contains("safe-validation"));

    // Adapter: script at tier 3 runs under the grant and lands as evidence.
    let a = ok(&lcoat(
        &root,
        &[
            "adapter",
            "run",
            "script",
            "demo-node",
            "--tier",
            "3",
            "--",
            "/bin/echo",
            "probe",
        ],
    ));
    assert_eq!(kv(&a, "tier"), "3");
    assert!(kv(&a, "evidence").starts_with("ev_"));
    let e = err(&lcoat(
        &root,
        &["adapter", "run", "nmap", "demo-node", "10.9.9.9"],
    ));
    assert!(e.contains("positional argument"));

    ok(&lcoat(&root, &["op", "report"]));
    ok(&lcoat(&root, &["op", "handoff"]));
    let readiness = ok(&lcoat(&root, &["op", "readiness"]));
    assert!(readiness.contains("Close Readiness: ready"), "{readiness}");
    let closed = ok(&lcoat(&root, &["op", "close"]));
    assert!(closed.contains("status: closed"));

    // Close clears the active pointer (as the shell does), so unnamed write
    // verbs have nothing to act on; a named closed operation is refused by type.
    let e = err(&lcoat(&root, &["evidence", "add", recon.to_str().unwrap()]));
    assert!(e.starts_with("error: no active operation"), "{e}");
    let e = err(&lcoat(&root, &["op", "close", "full-op"]));
    assert!(e.contains("is closed; resume it first"), "{e}");
    let e = err(&lcoat(&root, &["op", "closeout"]));
    assert!(e.contains("name it: lcoat op closeout <operation>"), "{e}");
    let e = err(&lcoat(&root, &["op", "audit-packet", "full-op"]));
    assert!(e.contains("no closeout packet recorded"), "{e}");
    ok(&lcoat(&root, &["op", "closeout", "full-op"]));
    ok(&lcoat(&root, &["op", "audit-packet", "full-op"]));
    ok(&lcoat(&root, &["op", "archive-packet", "full-op"]));

    for v in ["verify", "audit-verify", "archive-verify"] {
        let out = ok(&lcoat(&root, &["op", v, "full-op"]));
        assert!(out.contains("Verification Status: verified"), "{v}: {out}");
        let json = ok(&lcoat(&root, &["op", v, "full-op", "--json"]));
        assert!(
            json.contains("\"status\":\"verified\"")
                && json.contains("\"verification_problems\":0"),
            "{json}"
        );
    }
    let tc = ok(&lcoat(&root, &["op", "trust-chain", "full-op", "--strict"]));
    assert!(tc.contains("Trust Chain Status: current"), "{tc}");
    assert!(tc.contains("Ledger Chain: verified"));
    let json = ok(&lcoat(&root, &["op", "trust-chain", "full-op", "--json"]));
    assert!(json.starts_with("{\"schema_version\":\"lcoat.operation_trust_chain.v1\""));
    assert!(
        ok(&lcoat(&root, &["ledger", "chain-verify", "full-op"]))
            .contains("Chain Status: verified")
    );
    assert!(
        ok(&lcoat(&root, &["evidence", "verify", "full-op"]))
            .contains("Verification Status: verified")
    );
    assert!(ok(&lcoat(&root, &["op", "status", "full-op"])).contains("Status: closed"));
    assert!(ok(&lcoat(&root, &["op", "show", "full-op"])).contains("Operation Scope"));
    assert!(ok(&lcoat(&root, &["op", "brief", "full-op"])).contains("Operator Brief"));

    // Lite must still accept everything this build wrote: its verifiers are
    // exercised by conformance/cross_check.sh; here, the shell-shaped files
    // exist where the shell expects them.
    assert!(
        root.join("sessions/full-op/closeout/full-op-closeout.md")
            .is_file()
    );
    assert!(
        root.join("sessions/full-op/evidence/manifest.ndjson")
            .is_file()
    );
    assert!(root.join("reports/full-op-report.md").is_file());

    // Resume reopens; the lifecycle events are in the ledger in order.
    ok(&lcoat(&root, &["op", "resume", "full-op"]));
    let ledger = std::fs::read_to_string(root.join("sessions/full-op/ledger.ndjson")).unwrap();
    assert!(
        ledger
            .lines()
            .last()
            .unwrap()
            .contains("\"event\":\"op.resumed\"")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_injection_leaves_states_the_verifiers_describe() {
    let root = fresh("crash");
    let recon = root.join("recon.txt");
    std::fs::write(&recon, "PORT 22 open ssh\n").unwrap();
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "node",
            "10.10.10.5",
            "--scope-status",
            "in-scope",
        ],
    ));

    // op start interrupted before the ledger: op list shows it, verify says missing ledger.
    let out = crash_at(&root, "start.snapshot", &["op", "start", "half", "node"]);
    // Crash points exist only with `--features lcoat/test-support`. Feature
    // unification in a workspace-wide `cargo test` can turn them on in the
    // binary without this crate's own feature being set, so probe the binary
    // rather than trusting cfg!: with the feature it must stop; without it, a
    // start that ran to completion means a release-shaped binary, so skip.
    if out.status.code() != Some(99) {
        assert!(
            cfg!(not(feature = "test-support")) && out.status.success(),
            "expected an injected crash (exit 99), got {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        eprintln!("crash injection skipped: run with --features lcoat/test-support");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert!(ok(&lcoat(&root, &["op", "list"])).contains("half"));
    assert!(root.join("sessions/half/scope.snapshot.env").is_file());
    assert!(!root.join("sessions/half/ledger.ndjson").exists());
    let e = err(&lcoat(&root, &["op", "verify", "half"]));
    assert!(e.contains("no closeout packet recorded"), "{e}");
    // Starting again refuses the half-made directory rather than overwriting it.
    assert!(err(&lcoat(&root, &["op", "start", "half", "node"])).contains("already exists"));

    ok(&lcoat(&root, &["op", "start", "full-op", "node"]));
    // evidence add interrupted after the copy: orphan directory, no record,
    // the next add claims a _02 id under the frozen clock.
    let out = crash_at(
        &root,
        "evidence.copied",
        &["evidence", "add", recon.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(99));
    assert!(
        root.join("sessions/full-op/evidence/ev_20261002T074000Z/recon.txt")
            .is_file()
    );
    assert!(!root.join("sessions/full-op/evidence.ndjson").exists());
    assert!(ok(&lcoat(&root, &["evidence", "list"])).contains("no evidence recorded yet"));
    let ev = ok(&lcoat(&root, &["evidence", "add", recon.to_str().unwrap()]));
    assert_eq!(kv(&ev, "id"), "ev_20261002T074000Z_02");

    // evidence add interrupted after the index: a record without a ledger
    // event. Readiness counts it; the artifact verifies; the ledger does not
    // show artifact.created for it.
    let out = crash_at(
        &root,
        "evidence.indexed",
        &["evidence", "add", recon.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(99));
    let readiness = ok(&lcoat(&root, &["op", "readiness"]));
    assert!(readiness.contains("Evidence Records: 2"), "{readiness}");
    assert!(ok(&lcoat(&root, &["evidence", "verify"])).contains("Artifacts Checked: 2"));
    let ledger = std::fs::read_to_string(root.join("sessions/full-op/ledger.ndjson")).unwrap();
    assert_eq!(ledger.matches("artifact.created").count(), 1);

    // finding add interrupted after claiming the id: directory only, nothing recorded.
    let out = crash_at(&root, "finding.claimed", &["finding", "add", "ghost"]);
    assert_eq!(out.status.code(), Some(99));
    assert!(ok(&lcoat(&root, &["finding", "list"])).contains("no findings recorded yet"));

    // op close interrupted after STATUS=closed but before the events: the
    // record says closed, the ledger has no op.closed, and the chain still verifies.
    ok(&lcoat(&root, &["op", "report"]));
    let out = crash_at(&root, "close.status", &["op", "close", "--force"]);
    assert_eq!(out.status.code(), Some(99));
    assert!(ok(&lcoat(&root, &["op", "status", "full-op"])).contains("Status: closed"));
    let ledger = std::fs::read_to_string(root.join("sessions/full-op/ledger.ndjson")).unwrap();
    assert!(!ledger.contains("op.closed"));
    assert!(
        ok(&lcoat(&root, &["ledger", "chain-verify", "full-op"]))
            .contains("Chain Status: verified")
    );
    // Recovery is the documented command: resume, then close properly.
    ok(&lcoat(&root, &["op", "resume", "full-op"]));
    ok(&lcoat(&root, &["op", "close", "--force"]));

    // closeout interrupted after its ledger event: the verifiers say the
    // packet is missing, exactly as the shell would.
    let out = crash_at(&root, "closeout.event", &["op", "closeout", "full-op"]);
    assert_eq!(out.status.code(), Some(99));
    let e = err(&lcoat(&root, &["op", "verify", "full-op"]));
    assert!(e.contains("recorded closeout packet is missing"), "{e}");
    let tc = ok(&lcoat(&root, &["op", "trust-chain", "full-op"]));
    assert!(tc.contains("Closeout: missing manifest="), "{tc}");
    // Running closeout again repairs it.
    ok(&lcoat(&root, &["op", "closeout", "full-op"]));
    assert!(
        ok(&lcoat(&root, &["op", "verify", "full-op"])).contains("Verification Status: verified")
    );
    let _ = std::fs::remove_dir_all(&root);
}
