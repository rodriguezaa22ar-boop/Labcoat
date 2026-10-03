#![allow(clippy::unwrap_used)]
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
