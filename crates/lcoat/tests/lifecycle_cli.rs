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
    // A build without the adapters feature says so and verifies everything else.
    if cfg!(feature = "adapters") {
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
    } else {
        let e = err(&lcoat(
            &root,
            &[
                "adapter",
                "run",
                "script",
                "demo-node",
                "--tier",
                "1",
                "--",
                "/bin/true",
            ],
        ));
        assert!(e.contains("without the adapters feature"), "{e}");
    }

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

/// Found in the field run: `finding accept --expires 90d` stored the text
/// "90d", which the readiness check (a date comparison) never treats as
/// expired. Relative and date forms are now stored as the instant they
/// name; anything else, and a date already past, is refused.
#[test]
fn finding_accept_stores_a_real_expiry() {
    let root = fresh("accept");
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
    ok(&lcoat(&root, &["op", "start", "acc", "node"]));
    let f = ok(&lcoat(&root, &["finding", "add", "rsyslog 514 on tailnet"]));
    let id = kv(&f, "id");
    for (bad, why) in [
        ("90", "--expires must be"),
        ("soon", "--expires must be"),
        ("0d", "--expires must be"),
        ("99999999999999d", "--expires must be"),
        ("2020-01-01", "already in the past"),
    ] {
        let e = err(&lcoat(
            &root,
            &[
                "finding",
                "accept",
                &id,
                "--reason",
                "tailnet only",
                "--expires",
                bad,
            ],
        ));
        assert!(e.contains(why), "{bad}: {e}");
    }
    let out = ok(&lcoat(
        &root,
        &[
            "finding",
            "accept",
            &id,
            "--reason",
            "tailnet only",
            "--owner",
            "anthony",
            "--expires",
            "90d",
        ],
    ));
    // LCOAT_NOW is 2026-10-02T07:40:00Z in these tests.
    assert_eq!(kv(&out, "expires"), "2026-12-31T07:40:00Z");
    let rec = std::fs::read_to_string(root.join("sessions/acc/findings.ndjson")).unwrap();
    assert!(
        rec.contains("\"accepted_until\":\"2026-12-31T07:40:00Z\""),
        "{rec}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Found in field run 1: adapter evidence recorded the target as typed (an
/// address), and the readers matched the name only, so two of three scans
/// vanished from `evidence list`, readiness and the report while `evidence
/// verify` still counted them. Records are now written under the name, and
/// readers (and the approval check) accept any identifier of the target,
/// so records already on disk are counted too.
#[test]
fn any_target_identifier_lands_under_the_target() {
    let root = fresh("ident");
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "local-vm",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "lb", "local-vm"]));
    let src = root.join("scan.txt");
    std::fs::write(&src, "PORT 22 open\n").unwrap();
    let ev = ok(&lcoat(
        &root,
        &[
            "evidence",
            "add",
            src.to_str().unwrap(),
            "--target",
            "127.0.0.1",
        ],
    ));
    assert_eq!(kv(&ev, "target"), "local-vm");
    let f = ok(&lcoat(
        &root,
        &["finding", "add", "ssh open", "--target", "127.0.0.1"],
    ));
    assert_eq!(kv(&f, "target"), "local-vm");
    // A record already on disk under the address (what the field build wrote).
    let idx = root.join("sessions/lb/evidence.ndjson");
    let line = std::fs::read_to_string(&idx).unwrap();
    let old = line
        .trim_end()
        .replace("\"target\":\"local-vm\"", "\"target\":\"127.0.0.1\"")
        .replacen("\"id\":\"ev_", "\"id\":\"ev_old_", 1);
    std::fs::write(&idx, format!("{line}{old}\n")).unwrap();
    let list = ok(&lcoat(&root, &["evidence", "list"]));
    assert_eq!(list.lines().count(), 2, "{list}");
    assert!(ok(&lcoat(&root, &["op", "readiness"])).contains("Evidence Records: 2"));
    if cfg!(feature = "adapters") {
        // An approval granted for the name covers a tier-3 run typed by address.
        ok(&lcoat(
            &root,
            &[
                "approval",
                "grant",
                "safe-validation",
                "--reason",
                "lab",
                "--expires",
                "1d",
            ],
        ));
        let a = ok(&lcoat(
            &root,
            &[
                "adapter",
                "run",
                "script",
                "127.0.0.1",
                "--tier",
                "3",
                "--",
                "/bin/echo",
                "x",
            ],
        ));
        assert_eq!(kv(&a, "tier"), "3");
        assert!(ok(&lcoat(&root, &["op", "readiness"])).contains("Evidence Records: 3"));
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Field run 1, as typed: `target add` failed (a shell redirect), then
/// `op start` and a Tier 2 nmap run went ahead on the bare name. Now the
/// start is refused and says how to declare the target.
#[test]
fn undeclared_target_cannot_start_an_operation() {
    let root = fresh("undeclared");
    let e = err(&lcoat(
        &root,
        &[
            "op",
            "start",
            "fedora-lan-check",
            "fedora-lan",
            "514 reachability",
        ],
    ));
    assert!(e.contains("unknown target: fedora-lan"), "{e}");
    assert!(
        e.contains("lcoat target add fedora-lan <address> --scope-status in-scope"),
        "{e}"
    );
    assert!(!root.join("sessions/fedora-lan-check").exists());
    // Declared but not in-scope: the operation can be started and notes
    // kept, but nothing contacts the target.
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "fedora-lan",
            "192.0.2.10",
            "--scope-status",
            "review",
        ],
    ));
    ok(&lcoat(
        &root,
        &["op", "start", "fedora-lan-check", "fedora-lan"],
    ));
    if cfg!(feature = "adapters") {
        let e = err(&lcoat(
            &root,
            &[
                "adapter",
                "run",
                "nmap",
                "fedora-lan",
                "--",
                "-sV",
                "-p",
                "514",
            ],
        ));
        assert!(e.contains("scope status 'review'"), "{e}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Field run 1: a full-port nmap scan hit the 10-minute default timeout and
/// the run ended with the plain "no proposed findings" note. A timed-out
/// run now says it did not test what it did not reach.
#[test]
fn a_timed_out_run_says_it_is_incomplete() {
    if !cfg!(feature = "adapters") {
        return;
    }
    let root = fresh("timeout");
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "box",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "t", "box"]));
    let out = lcoat(
        &root,
        &[
            "adapter",
            "run",
            "script",
            "box",
            "--timeout",
            "1",
            "--tier",
            "1",
            "--",
            "/bin/sleep",
            "5",
        ],
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains("stopped at its timeout"), "{all}");
    assert!(!all.contains("confirm findings manually"), "{all}");
    let _ = std::fs::remove_dir_all(&root);
}

/// Field run 1: `local-baseline` closed `ready` with every packet verified
/// but stayed `incomplete` because its accepted risk had no review packet.
/// Now: review the closed operation, regenerate audit and archive, and the
/// trust chain is current; change a finding afterwards and the review
/// packet stops verifying.
#[test]
fn accepted_risk_review_completes_the_trust_chain() {
    let root = fresh("review");
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "local-vm",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(
        &root,
        &["op", "start", "local-baseline", "local-vm"],
    ));
    let src = root.join("scan.txt");
    std::fs::write(&src, "PORT 22 open\n").unwrap();
    ok(&lcoat(&root, &["evidence", "add", src.to_str().unwrap()]));
    let id = kv(
        &ok(&lcoat(
            &root,
            &["finding", "add", "ssh on loopback", "--severity", "low"],
        )),
        "id",
    );
    ok(&lcoat(
        &root,
        &[
            "finding",
            "accept",
            &id,
            "--reason",
            "lab loopback only",
            "--owner",
            "anthony",
            "--expires",
            "90d",
        ],
    ));
    let q = ok(&lcoat(&root, &["finding", "review-queue"]));
    assert!(
        q.contains("Current: 1") && q.contains("reason=lab loopback only"),
        "{q}"
    );
    ok(&lcoat(&root, &["op", "report"]));
    ok(&lcoat(&root, &["op", "handoff"]));
    ok(&lcoat(&root, &["op", "close"]));
    for c in ["closeout", "audit-packet", "archive-packet"] {
        ok(&lcoat(&root, &["op", c, "local-baseline"]));
    }
    let tc = lcoat(&root, &["op", "trust-chain", "local-baseline", "--strict"]);
    assert!(!tc.status.success());
    assert!(
        String::from_utf8_lossy(&tc.stdout).contains("Generate an accepted-risk review packet")
    );

    // The fix, on the closed operation.
    let w = ok(&lcoat(
        &root,
        &["finding", "review-packet", "--op", "local-baseline"],
    ));
    assert!(w.contains("lcoat op audit-packet local-baseline"), "{w}");
    let v = ok(&lcoat(
        &root,
        &["finding", "review-verify", "--op", "local-baseline"],
    ));
    assert!(v.contains("Verification Status: verified"), "{v}");
    for c in ["audit-packet", "archive-packet"] {
        ok(&lcoat(&root, &["op", c, "local-baseline"]));
    }
    let tc = ok(&lcoat(
        &root,
        &["op", "trust-chain", "local-baseline", "--strict"],
    ));
    assert!(tc.contains("Trust Chain Status: current"), "{tc}");
    assert!(tc.contains("Accepted Risk Review Packet: verified"), "{tc}");

    // A finding edited after the review: the packet no longer verifies.
    let idx = root.join("sessions/local-baseline/findings.ndjson");
    let text = std::fs::read_to_string(&idx).unwrap();
    std::fs::write(&idx, text.replace("lab loopback only", "lab loopback ONLY")).unwrap();
    let e = lcoat(
        &root,
        &["finding", "review-verify", "--op", "local-baseline"],
    );
    assert!(!e.status.success());
    assert!(String::from_utf8_lossy(&e.stdout).contains("Finding Index        changed"));
    let tc =
        String::from_utf8_lossy(&lcoat(&root, &["op", "trust-chain", "local-baseline"]).stdout)
            .into_owned();
    assert!(
        tc.contains("Accepted Risk Review Packet: attention-required"),
        "{tc}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Field run 1, the tailnet scans before and after moving tailscale0 out of
/// the trusted zone, compared by eye; now `evidence diff`. Tampered
/// evidence, a non-nmap artifact and a host-down run are all called out.
#[test]
fn evidence_diff_compares_two_scans() {
    if !cfg!(feature = "adapters") {
        return;
    }
    let root = fresh("diff");
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "fedora-lab",
            "100.71.57.96",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(
        &root,
        &["op", "start", "fedora-baseline", "fedora-lab"],
    ));
    let services = "22,53,80,514,3000,3001,4330,5001,8080,8085,8096,9090,11434,40004,44321,44725";
    let report = |open: &[(&str, &str)], up: u32| {
        let mut x = format!(
            r#"<?xml version="1.0"?><nmaprun><scaninfo type="connect" protocol="tcp" numservices="16" services="{services}"/>"#
        );
        for (p, svc) in open {
            x.push_str(&format!(r#"<port protocol="tcp" portid="{p}"><state state="open"/><service name="{svc}"/></port>"#));
        }
        x.push_str(&format!(
            r#"<runstats><hosts up="{up}" down="{}" total="1"/></runstats></nmaprun>"#,
            1 - up
        ));
        x
    };
    let before = report(
        &[
            ("22", "ssh"),
            ("53", "domain"),
            ("80", "http"),
            ("514", "shell"),
            ("3000", "http"),
            ("8080", "http"),
            ("9090", "zeus-admin"),
            ("11434", "http"),
        ],
        1,
    );
    let after = report(
        &[
            ("22", "ssh"),
            ("80", "http"),
            ("3000", "http"),
            ("11434", "http"),
        ],
        1,
    );
    let add = |name: &str, body: &str| {
        let p = root.join(name);
        std::fs::write(&p, body).unwrap();
        kv(
            &ok(&lcoat(
                &root,
                &[
                    "evidence",
                    "add",
                    p.to_str().unwrap(),
                    "--kind",
                    "adapter-output",
                ],
            )),
            "id",
        )
    };
    let b = add("before.txt", &before);
    let a = add("after.txt", &after);
    let out = ok(&lcoat(&root, &["evidence", "diff", &b, &a]));
    assert!(out.contains("Closed: 4"), "{out}");
    assert!(out.contains("Unchanged: 4"), "{out}");
    assert!(out.contains("Opened: 0"), "{out}");
    assert!(
        out.lines()
            .any(|l| l.starts_with("closed") && l.contains("514/tcp")),
        "{out}"
    );
    let json = ok(&lcoat(&root, &["evidence", "diff", &b, &a, "--json"]));
    assert!(
        json.starts_with(r#"{"schema_version":"lcoat.evidence_diff.v1""#),
        "{json}"
    );

    // A host-down run is flagged, not read as "everything closed".
    let down = add("down.txt", &report(&[], 0));
    let out = ok(&lcoat(&root, &["evidence", "diff", &b, &down]));
    assert!(out.contains("host down"), "{out}");

    // Not an nmap report; then a capture edited after the fact.
    let notes = add("notes.txt", "just notes\n");
    assert!(err(&lcoat(&root, &["evidence", "diff", &b, &notes])).contains("not an nmap report"));
    let art = root.join(format!("sessions/fedora-baseline/evidence/{a}/after.txt"));
    std::fs::write(&art, after.replace(r#"portid="3000""#, r#"portid="3001""#)).unwrap();
    assert!(err(&lcoat(&root, &["evidence", "diff", &b, &a])).contains("changed since capture"));
    let _ = std::fs::remove_dir_all(&root);
}

/// Field run 1: two pasted placeholders (`<fedora-LAN-IP>`, `<that-target>`)
/// became shell redirects. Commands now print `next:` lines with the real
/// ids; running one as printed must work.
#[test]
fn next_lines_run_as_printed() {
    let root = fresh("next");
    let t = ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "fedora-lab",
            "100.71.57.96",
            "--scope-status",
            "in-scope",
        ],
    ));
    assert!(
        t.contains("next: lcoat op start fedora-lab-check fedora-lab"),
        "{t}"
    );
    ok(&lcoat(
        &root,
        &["op", "start", "fedora-lab-check", "fedora-lab"],
    ));
    let f = ok(&lcoat(
        &root,
        &["finding", "add", "Open tcp/514 (shell) it's $(id)"],
    ));
    let line = f
        .lines()
        .find_map(|l| l.strip_prefix("next: lcoat finding resolve "))
        .unwrap_or_else(|| panic!("{f}"));
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(format!(
            "{} finding resolve {line}",
            env!("CARGO_BIN_EXE_lcoat")
        ))
        .env("LCOAT_ROOT", &root)
        .env("LCOAT_NOW", "2026-10-02T07:40:00Z")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("status: resolved"));
    let list = ok(&lcoat(&root, &["finding", "list"]));
    assert!(list.contains("it's $(id)"), "{list}");
    let r = lcoat(
        &root,
        &[
            "target",
            "add",
            "maybe",
            "10.0.0.9",
            "--scope-status",
            "review",
        ],
    );
    assert!(String::from_utf8_lossy(&r.stdout).contains("nothing above Tier 0 will contact"));
    let _ = std::fs::remove_dir_all(&root);
}

/// Review 2026-10-05: `evidence verify` trusted the index alone. Emptying
/// it gave `verified, checked 0`; a newer index record with a new hash
/// re-blessed an edited artifact; a `..` path was followed. The index is
/// now cross-checked against the manifest and the ledger.
#[test]
fn evidence_verify_cross_checks_index_manifest_and_ledger() {
    let root = fresh("ev-cross");
    std::fs::write(root.join("scan.txt"), b"22/tcp open ssh\n").unwrap();
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "box",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "demo", "box"]));
    let added = ok(&lcoat(
        &root,
        &["evidence", "add", root.join("scan.txt").to_str().unwrap()],
    ));
    let id = kv(&added, "id");
    assert!(id.starts_with("ev_"), "{added}");
    let op = root.join("sessions/demo");
    let index = op.join("evidence.ndjson");
    let original = std::fs::read_to_string(&index).unwrap();
    ok(&lcoat(&root, &["evidence", "verify", "demo"]));

    let verdict = |root: &Path| {
        let out = lcoat(root, &["evidence", "verify", "demo"]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    // 1. Emptied index: the manifest and the ledger still name the capture.
    std::fs::write(&index, "").unwrap();
    let text = verdict(&root);
    assert!(text.contains(&id) && text.contains("unindexed"), "{text}");
    assert!(
        text.contains("recorded by the manifest, absent from the index"),
        "{text}"
    );
    assert_eq!(kv(&text, "Verification Status"), "attention-required");

    // 2. Edit the artifact, then append a newer index record blessing it.
    std::fs::write(&index, &original).unwrap();
    let artifact = op.join(format!("evidence/{id}/scan.txt"));
    std::fs::write(&artifact, b"nothing open\n").unwrap();
    let new_sha = ok(&lcoat(&root, &["hash", artifact.to_str().unwrap()]))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let old_sha = kv(&added, "sha256");
    assert!(!old_sha.is_empty(), "{added}");
    let last = original.lines().last().unwrap().replace(&old_sha, &new_sha);
    std::fs::write(&index, format!("{original}{last}\n")).unwrap();
    let text = verdict(&root);
    assert!(text.contains("conflict"), "{text}");
    assert!(
        text.contains(&format!("an earlier index record has sha256={old_sha}")),
        "{text}"
    );

    // 3. Rewrite the only record instead: the manifest disagrees.
    std::fs::write(&index, original.replace(&old_sha, &new_sha)).unwrap();
    let text = verdict(&root);
    assert!(
        text.contains(&format!("the manifest recorded sha256={old_sha}")),
        "{text}"
    );

    // 4. A stored path that leaves the operation directory.
    std::fs::write(
        &index,
        original.replace(&format!("evidence/{id}/scan.txt"), "../../../etc/hostname"),
    )
    .unwrap();
    let text = verdict(&root);
    assert!(
        text.contains("unsafe") && text.contains("leaves the operation directory"),
        "{text}"
    );

    // Restored, everything verifies again.
    std::fs::write(&index, &original).unwrap();
    std::fs::write(&artifact, b"22/tcp open ssh\n").unwrap();
    ok(&lcoat(&root, &["evidence", "verify", "demo"]));
    let _ = std::fs::remove_dir_all(&root);
}

/// Review 2026-10-05: a ledger event edited before any packet existed was
/// anchored by every packet written afterwards, and `op trust-chain
/// --strict` said `current` (exit 0) while its own `Ledger Chain` line said
/// `broken`. The chain now decides the verdict, and no packet anchors an
/// altered ledger.
#[test]
fn a_broken_ledger_chain_is_never_current_and_never_anchored() {
    let root = fresh("broken-chain");
    std::fs::write(root.join("scan.txt"), b"22/tcp open ssh\n").unwrap();
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "box",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "demo", "box"]));
    ok(&lcoat(
        &root,
        &["evidence", "add", root.join("scan.txt").to_str().unwrap()],
    ));
    ok(&lcoat(&root, &["op", "report"]));
    ok(&lcoat(&root, &["op", "close", "--force"]));

    let ledger = root.join("sessions/demo/ledger.ndjson");
    let text = std::fs::read_to_string(&ledger).unwrap();
    let edited = text.replacen("reason=add evidence artifact", "reason=nothing here", 1);
    assert_ne!(text, edited, "tamper did not apply");
    std::fs::write(&ledger, edited).unwrap();

    for (args, packet) in [
        (&["op", "closeout", "demo"][..], "closeout manifest"),
        (
            &["finding", "review-packet", "--op", "demo"][..],
            "accepted-risk review packet",
        ),
    ] {
        let e = err(&lcoat(&root, args));
        assert!(
            e.contains(&format!(
                "refusing to write the {packet}: ledger event 2 was altered"
            )),
            "{e}"
        );
        assert!(e.contains("lcoat ledger chain-verify demo"), "{e}");
    }
    assert!(!root.join("sessions/demo/closeout").exists());

    let out = lcoat(&root, &["op", "trust-chain", "demo", "--strict"]);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(kv(&text, "Trust Chain Status"), "attention-required");
    assert!(
        kv(&text, "Next Trust Step").contains("ledger event 2 was altered"),
        "{text}"
    );
    assert!(
        kv(&text, "Ledger Chain").starts_with("broken at event 2"),
        "{text}"
    );

    let json =
        String::from_utf8_lossy(&lcoat(&root, &["op", "trust-chain", "demo", "--json"]).stdout)
            .into_owned();
    assert!(json.contains(r#""status":"attention-required""#), "{json}");

    // A deleted ledger is not an empty v1 one.
    std::fs::remove_file(&ledger).unwrap();
    let e = err(&lcoat(&root, &["ledger", "chain-verify", "demo"]));
    assert!(e.contains("operation ledger is missing"), "{e}");
    let text =
        String::from_utf8_lossy(&lcoat(&root, &["op", "trust-chain", "demo"]).stdout).into_owned();
    assert_eq!(kv(&text, "Trust Chain Status"), "attention-required");
    assert_eq!(kv(&text, "Ledger Chain"), "missing");
    let _ = std::fs::remove_dir_all(&root);
}

/// Review 2026-10-05: a planted `manifest.ndjson` symlink made `evidence
/// add` append outside the root, and a `reports/` symlink made `op report`
/// write there. Writes now refuse to follow a link below the lab root, and
/// nothing lands outside it.
#[test]
fn writes_never_follow_a_planted_symlink() {
    use std::os::unix::fs::symlink;
    let root = fresh("symlinks");
    let outside = fresh("symlinks-outside");
    std::fs::write(root.join("scan.txt"), b"22/tcp open ssh\n").unwrap();
    let scan = root.join("scan.txt");
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "box",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "demo", "box"]));
    let op_dir = root.join("sessions/demo");

    // A manifest that is a link to a file elsewhere.
    ok(&lcoat(&root, &["evidence", "add", scan.to_str().unwrap()]));
    let manifest = op_dir.join("evidence/manifest.ndjson");
    std::fs::rename(&manifest, outside.join("manifest.ndjson")).unwrap();
    symlink(outside.join("manifest.ndjson"), &manifest).unwrap();
    let before = std::fs::read(outside.join("manifest.ndjson")).unwrap();
    let e = err(&lcoat(&root, &["evidence", "add", scan.to_str().unwrap()]));
    assert!(e.contains("manifest.ndjson: it is a symbolic link"), "{e}");
    assert_eq!(
        std::fs::read(outside.join("manifest.ndjson")).unwrap(),
        before
    );
    std::fs::remove_file(&manifest).unwrap();
    std::fs::rename(outside.join("manifest.ndjson"), &manifest).unwrap();

    // A reports directory that is a link to a directory elsewhere.
    let reports = root.join("reports");
    let _ = std::fs::remove_dir_all(&reports);
    symlink(&outside, &reports).unwrap();
    let e = err(&lcoat(&root, &["op", "report"]));
    assert!(e.contains("is a symbolic link"), "{e}");
    assert!(e.contains("reports"), "{e}");
    assert_eq!(
        std::fs::read_dir(&outside).unwrap().count(),
        0,
        "nothing may land outside"
    );
    std::fs::remove_file(&reports).unwrap();
    ok(&lcoat(&root, &["op", "report"]));

    // A link further up (the operation's evidence directory) is refused too.
    let evidence = op_dir.join("evidence");
    std::fs::rename(&evidence, outside.join("evidence")).unwrap();
    symlink(outside.join("evidence"), &evidence).unwrap();
    let e = err(&lcoat(&root, &["evidence", "add", scan.to_str().unwrap()]));
    assert!(e.contains("is a symbolic link"), "{e}");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

/// Review 2026-10-05: a command loaded its operation, then waited for the
/// lock; if `op close` ran meanwhile, `evidence add` appended to the closed
/// operation. The state is now checked again once the lock is held.
#[test]
fn a_writer_that_waited_for_the_lock_rechecks_the_state() {
    let root = fresh("recheck");
    std::fs::write(root.join("scan.txt"), b"22/tcp open ssh\n").unwrap();
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "box",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "demo", "box"]));
    let op_dir = root.join("sessions/demo");

    // Hold the operation lock as another lcoat command would.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(op_dir.join(".lock"))
        .unwrap();
    held.lock().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_lcoat"))
        .args(["evidence", "add", root.join("scan.txt").to_str().unwrap()])
        .env_remove("LAB_ROOT")
        .env("LCOAT_ROOT", &root)
        .env("LCOAT_OPERATOR", "tester")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // The waiting note is printed only after the child has loaded the (still
    // active) operation and found the lock held: change the state then, not
    // after a fixed sleep.
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        use std::io::BufRead;
        let mut all = String::new();
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("note: waiting for another lcoat command") {
                let _ = tx.send(());
            }
            all.push_str(&line);
            all.push('\n');
        }
        all
    });
    rx.recv_timeout(std::time::Duration::from_secs(60))
        .expect("the child never reported waiting for the lock");
    // What a concurrent `op close` would have done while it waited.
    let session = op_dir.join("session.env");
    let text = std::fs::read_to_string(&session).unwrap();
    std::fs::write(&session, text.replace("STATUS=active", "STATUS=closed")).unwrap();
    let events_before = std::fs::read_to_string(op_dir.join("ledger.ndjson"))
        .unwrap()
        .lines()
        .count();
    held.unlock().unwrap();

    let status = child.wait().unwrap();
    let e = reader.join().unwrap();
    assert!(!status.success(), "{e}");
    assert!(
        e.contains("operation 'demo' is no longer active (now closed)"),
        "{e}"
    );
    let events_after = std::fs::read_to_string(op_dir.join("ledger.ndjson"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(events_before, events_after, "nothing may be appended");
    let copied = std::fs::read_dir(op_dir.join("evidence"))
        .map(|rd| {
            rd.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("ev_"))
        })
        .unwrap_or(false);
    assert!(!copied, "no artifact may be copied");
    let _ = std::fs::remove_dir_all(&root);
}

/// Review 2026-10-05: two adapter runs at once shared one capture file, so
/// one run recorded the other's output as its evidence (with a matching
/// hash). A run now holds the operation lock throughout and captures under
/// its own name; each run's evidence is its own output.
#[test]
fn concurrent_adapter_runs_keep_their_own_evidence() {
    if !cfg!(feature = "adapters") {
        return;
    }
    let root = fresh("concurrent-runs");
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "box",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "demo", "box"]));
    let spawn = |word: &str| {
        Command::new(env!("CARGO_BIN_EXE_lcoat"))
            .args([
                "adapter", "run", "script", "box", "--tier", "1", "--", "/bin/sh", "-c",
            ])
            .arg(format!("sleep 1; echo {word}"))
            .env_remove("LAB_ROOT")
            .env("LCOAT_ROOT", &root)
            .env("LCOAT_OPERATOR", "tester")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let a = spawn("AAA");
    let b = spawn("BBB");
    for (child, word) in [(a, "AAA"), (b, "BBB")] {
        let out = ok(&child.wait_with_output().unwrap());
        let id = kv(&out, "evidence");
        assert!(id.starts_with("ev_"), "{out}");
        let dir = root.join("sessions/demo/evidence").join(&id);
        let file = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .path();
        let body = std::fs::read_to_string(file).unwrap();
        assert_eq!(body.trim(), word, "run {word} recorded {body:?}");
    }
    // Each started run is finished before the next starts.
    let events: Vec<String> = std::fs::read_to_string(root.join("sessions/demo/ledger.ndjson"))
        .unwrap()
        .lines()
        .filter_map(|l| {
            ["adapter.started", "adapter.finished"]
                .into_iter()
                .find(|e| l.contains(&format!(r#""event":"{e}""#)))
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        events,
        [
            "adapter.started",
            "adapter.finished",
            "adapter.started",
            "adapter.finished"
        ]
    );
    ok(&lcoat(&root, &["evidence", "verify", "demo"]));
    let _ = std::fs::remove_dir_all(&root);
}

/// Review 2026-10-05: a tool that could not be started left an
/// `adapter.started` with no `adapter.finished`.
#[test]
fn a_run_that_cannot_start_is_still_finished_in_the_ledger() {
    if !cfg!(feature = "adapters") {
        return;
    }
    let root = fresh("spawn-failed");
    ok(&lcoat(
        &root,
        &[
            "target",
            "add",
            "box",
            "127.0.0.1",
            "--scope-status",
            "in-scope",
        ],
    ));
    ok(&lcoat(&root, &["op", "start", "demo", "box"]));
    // Executable, but its interpreter does not exist: found, then fails to spawn.
    let tool = root.join("broken-tool");
    std::fs::write(&tool, "#!/nonexistent/interpreter\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    err(&lcoat(
        &root,
        &[
            "adapter",
            "run",
            "script",
            "box",
            "--tier",
            "1",
            "--",
            tool.to_str().unwrap(),
        ],
    ));
    let ledger = std::fs::read_to_string(root.join("sessions/demo/ledger.ndjson")).unwrap();
    let last = ledger.lines().last().unwrap();
    assert!(last.contains(r#""event":"adapter.finished""#), "{last}");
    assert!(last.contains("reason=spawn-failed"), "{last}");
    let _ = std::fs::remove_dir_all(&root);
}
