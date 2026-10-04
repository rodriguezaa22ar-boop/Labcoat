#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! CLI tests through the real binary (std only; no assert_cmd).

use std::process::Command;

fn lcoat() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lcoat"))
}

fn fixture(rel: &str) -> String {
    format!("{}/../../fixtures/golden/{rel}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn version_prints_crate_version() {
    let out = lcoat().arg("version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("lcoat {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn hash_matches_golden_ledger() {
    let out = lcoat()
        .args(["hash", &fixture("learning-op-001/ledger.ndjson")])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .starts_with("ba36a56433f5a4153a1d430bb4632bfe7bdcc989adbf5438ba1ea667758f0c6f  ")
    );
}

#[test]
fn hash_of_missing_file_fails() {
    assert!(
        !lcoat()
            .args(["hash", "/nonexistent/file"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn scan_accepts_golden_receipt_and_rejects_credentials() {
    let ok = lcoat()
        .args(["scan", &fixture("demo-site-receipts/demo-site-packet.json")])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stdout)
    );

    let bad = lcoat()
        .args(["scan", "--text", "Authorization: Bearer x"])
        .output()
        .unwrap();
    assert!(!bad.status.success());

    let fine = lcoat()
        .args(["scan", "--text", "nmap reported 22/tcp open"])
        .output()
        .unwrap();
    assert!(fine.status.success());
}

#[test]
fn unknown_command_fails_with_usage() {
    let out = lcoat().arg("frobnicate").output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
}

// --- phase 1: read-only commands against the golden state -----------------

fn golden_root() -> String {
    format!("{}/../../fixtures/golden", env!("CARGO_MANIFEST_DIR"))
}

/// A command run against the golden fixture, whose operation directory sits
/// directly under `fixtures/golden` rather than under `sessions/`.
fn golden_cmd(args: &[&str]) -> std::process::Output {
    let g = golden_root();
    lcoat()
        .args(args)
        .env_remove("LAB_ROOT")
        .env("LCOAT_ROOT", &g)
        .env("LAB_SESSIONS_DIR", &g)
        .env("ATLAS_TODAY", "2026-10-02")
        .output()
        .unwrap()
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn expected(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../expected/learning-op-001.{name}.txt",
        golden_root()
    ))
    .unwrap()
}

#[test]
fn unset_root_is_an_error_not_a_guess() {
    let out = lcoat()
        .args(["op", "list"])
        .env_remove("LAB_ROOT")
        .env_remove("LCOAT_ROOT")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("error: LCOAT_ROOT is not set"), "{err}");
    assert!(err.contains("export LCOAT_ROOT="));
}

#[test]
fn read_only_commands_never_create_directories() {
    let root = std::env::temp_dir().join(format!("lcoat-cli-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for args in [
        &["op", "list"][..],
        &["op", "readiness"],
        &["op", "verify"],
        &["op", "trust-chain"],
        &["scope", "status"],
        &["evidence", "list"],
        &["finding", "list"],
    ] {
        let out = lcoat()
            .args(args)
            .env_remove("LAB_ROOT")
            .env("LCOAT_ROOT", &root)
            .output()
            .unwrap();
        // Lite created state/, targets/, sessions/, reports/ on every call.
        assert!(
            std::fs::read_dir(&root).unwrap().next().is_none(),
            "{args:?} created something under the root"
        );
        if args != ["op", "list"] {
            assert!(!out.status.success(), "{args:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("no active operation"),
                "{args:?}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn op_list_and_readiness_match_the_recorded_output() {
    let out = golden_cmd(&["op", "list"]);
    assert!(out.status.success());
    assert_eq!(
        stdout(&out),
        format!(
            "{:<24} {:<16} {:<24} {}\n{:<24} {:<16} {:<24} {}\n",
            "OPERATION",
            "STATUS",
            "TARGET",
            "ACTIVE",
            "learning-op-001",
            "closed",
            "demo-learning-node",
            "no"
        )
    );
    let out = golden_cmd(&["op", "readiness", "learning-op-001"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out), expected("readiness"));
}

#[test]
fn lists_and_scope_status_render_golden_state() {
    let out = golden_cmd(&["finding", "list", "learning-op-001"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 2);
    assert!(
        text.starts_with("finding_20261002T054007Z observed   low      open       "),
        "{text}"
    );

    let out = golden_cmd(&["evidence", "list", "learning-op-001"]);
    assert!(out.status.success());
    assert!(
        stdout(&out).starts_with("ev_20261002T054004Z    "),
        "{}",
        stdout(&out)
    );

    let out = golden_cmd(&["scope", "status", "learning-op-001"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.starts_with("ScopeGuard\n"));
    assert!(text.contains("Profile: htb-starting-point\n"));
    assert!(text.contains("Address: 192.168.100.50\n"));
    assert!(text.ends_with(&format!(
        "Snapshot: {}/learning-op-001/scope.snapshot.env\n",
        golden_root()
    )));

    // Usage errors for the read-only loaders.
    let out = golden_cmd(&["finding", "list", "a", "b"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: finding list [operation]"));
}

#[test]
fn ledger_and_receipt_commands_match_the_shell_build() {
    let ledger = format!("{}/learning-op-001/ledger.ndjson", golden_root());
    let out = golden_cmd(&["ledger", "verify", &ledger, "--json"]);
    assert!(out.status.success());
    assert_eq!(
        stdout(&out),
        "{\"schema_version\":\"atlas.ledger_verify.v1\",\"status\":\"ok\",\"ledger_type\":\"atlas.operation_ledger.v1\",\"event_count\":18,\"head_event_hash\":\"abd88a7fe5dbf8b017a73a9a8ae5e84a1afb396bde656f2d0d558eb2bc6a1b75\"}\n"
    );
    let out = golden_cmd(&["ledger", "checkpoint", &ledger]);
    assert!(out.status.success());
    assert!(stdout(&out).contains(
        "ledger_hash: ba36a56433f5a4153a1d430bb4632bfe7bdcc989adbf5438ba1ea667758f0c6f\n"
    ));

    let receipt = format!(
        "{}/demo-site-receipts/demo-site-boundary.json",
        golden_root()
    );
    let out = golden_cmd(&["receipt", "verify", &receipt, "--json"]);
    assert!(out.status.success());
    let recorded = std::fs::read_to_string(format!(
        "{}/../expected/receipt-verify.demo-site-boundary.json",
        golden_root()
    ))
    .unwrap();
    assert_eq!(stdout(&out), recorded);

    // Replay in the wrong order fails with the shell build's message.
    let packet = format!("{}/demo-site-receipts/demo-site-packet.json", golden_root());
    let out = golden_cmd(&["receipt", "replay", &packet, &receipt]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("receipt 1 prev_hash must be null"));
}

#[test]
fn receipt_create_writes_the_shell_form_and_validates() {
    let dir = std::env::temp_dir().join(format!("lcoat-cli-receipt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out_path = dir.join("r.json").display().to_string();
    let out = lcoat()
        .args([
            "receipt",
            "create",
            "--action",
            "demo.created",
            "--actor",
            "tester",
            "--subject-type",
            "atlas-operation",
            "--subject",
            "operation://demo",
            "--receipt-id",
            "receipt_fixed",
            "--timestamp",
            "2026-10-02T07:40:00Z",
            "--out",
            &out_path,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stdout(&out), format!("receipt: {out_path}\n"));
    let body = std::fs::read_to_string(&out_path).unwrap();
    assert!(
        body.starts_with("{\n  \"action\": \"demo.created\",\n"),
        "{body}"
    );
    let out = lcoat()
        .args(["receipt", "verify", &out_path])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).starts_with("receipt: ok\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_side_commands_say_what_is_missing() {
    let out = golden_cmd(&["op", "start", "x", "y"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("phase 2"));
}
