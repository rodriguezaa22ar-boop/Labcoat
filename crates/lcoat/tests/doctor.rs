#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `lcoat doctor` through the real binary: read-only on every root, and
//! each problem field runs met is reported on its own row.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use lcoat_format::json::Value;

fn fresh(name: &str) -> PathBuf {
    lcoat_format::fsutil::private_temp_dir(&format!("lcoat-doctor-{name}")).unwrap()
}

fn cmd(root: Option<&Path>, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lcoat"));
    c.args(args)
        .env_remove("LAB_ROOT")
        .env_remove("LCOAT_ROOT")
        .env_remove("LAB_CONFIG")
        .env_remove("LCOAT_NOW")
        .env_remove("ATLAS_TODAY")
        .env_remove("LCOAT_TEST_CRASH_AT")
        .env("LCOAT_OPERATOR", "tester");
    if let Some(r) = root {
        c.env("LCOAT_ROOT", r);
    }
    c.output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// The `label status` part of the row with this label, e.g. `"fail"`.
fn row_status(text: &str, label: &str) -> String {
    text.lines()
        .find(|l| l.len() > 25 && l[..24].trim_end() == label)
        .map(|l| l[25..].split_whitespace().next().unwrap_or("").to_owned())
        .unwrap_or_else(|| panic!("no row {label:?} in:\n{text}"))
}

fn row_detail(text: &str, label: &str) -> String {
    text.lines()
        .find(|l| l.len() > 25 && l[..24].trim_end() == label)
        .map(|l| l[34.min(l.len())..].to_owned())
        .unwrap_or_default()
}

/// Every path under `dir` with its size and modification time.
fn snapshot(dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let m = std::fs::symlink_metadata(e.path()).unwrap();
            out.push((e.path(), m.len(), m.modified().unwrap()));
            if m.is_dir() {
                stack.push(e.path());
            }
        }
    }
    out.sort();
    out
}

/// A lab with one closed and one active operation and one evidence file.
fn lab(name: &str) -> (PathBuf, PathBuf) {
    let base = fresh(name);
    let root = base.join("lab");
    let ok = |args: &[&str]| {
        let o = cmd(Some(&root), args);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    };
    std::fs::write(base.join("scan.txt"), b"22/tcp open ssh\n").unwrap();
    ok(&[
        "target",
        "add",
        "box",
        "127.0.0.1",
        "--scope-status",
        "in-scope",
    ]);
    ok(&["op", "start", "first", "box"]);
    ok(&["evidence", "add", base.join("scan.txt").to_str().unwrap()]);
    ok(&["op", "close", "--force"]);
    ok(&["op", "start", "second", "box"]);
    (base, root)
}

#[test]
fn unset_root_is_one_failing_row_and_the_rest_still_runs() {
    let o = cmd(None, &["doctor"]);
    assert!(!o.status.success());
    let text = stdout(&o);
    assert_eq!(row_status(&text, "root variable"), "fail");
    assert!(text.contains("LCOAT_ROOT is not set"));
    assert_eq!(row_status(&text, "system clock"), "ok");
    assert!(text.contains("Status: attention required"));
}

#[test]
fn a_missing_root_is_reported_and_not_created() {
    let base = fresh("missing");
    let root = base.join("not-yet");
    let text = stdout(&cmd(Some(&root), &["doctor"]));
    assert_eq!(row_status(&text, "root"), "warn");
    assert!(
        !text.contains("state dir"),
        "layout rows are skipped:\n{text}"
    );
    assert!(!root.exists(), "doctor must never create the root");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_healthy_lab_has_no_root_side_problems_and_is_left_untouched() {
    let (base, root) = lab("healthy");
    let before = snapshot(&root);
    let o = cmd(Some(&root), &["doctor"]);
    let text = stdout(&o);
    assert_eq!(snapshot(&root), before, "doctor wrote under the root");
    for label in [
        "root",
        "sessions dir",
        "ownership",
        "symlinks",
        "interrupted writes",
        "active operation",
        "first",
        "second",
    ] {
        assert_eq!(row_status(&text, label), "ok", "{label}:\n{text}");
    }
    #[cfg(unix)]
    assert_eq!(row_status(&text, "root permissions"), "ok");
    assert!(row_detail(&text, "operations").starts_with("2 (1 active, 1 closed)"));
    assert!(row_detail(&text, "first").contains("chain verified, 1 artifact verified"));
    assert!(row_detail(&text, "second").contains("no evidence yet"));
    assert_eq!(row_detail(&text, "active operation"), "second");
    // Only the tools rows depend on this machine (nmap may be absent).
    let fails: Vec<&str> = text
        .lines()
        .filter(|l| l.len() > 25 && l[25..].starts_with("fail"))
        .collect();
    assert!(fails.iter().all(|l| l.starts_with("nmap ")), "{fails:?}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn each_field_problem_gets_its_own_row() {
    let (base, root) = lab("broken");
    // An evidence file edited after capture.
    let ev = std::fs::read_dir(root.join("sessions/first/evidence"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .unwrap();
    let artifact = std::fs::read_dir(&ev)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    std::fs::write(&artifact, b"edited\n").unwrap();
    // An interrupted write, a planted symlink, a stale active pointer, and a
    // frozen clock left over from a test.
    std::fs::write(root.join("sessions/second/.session.env.4242.tmp"), b"x").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/", root.join("escape")).unwrap();
    std::fs::write(
        root.join("state/atlas/active.env"),
        b"ACTIVE_OPERATION=gone\n",
    )
    .unwrap();

    let mut c = Command::new(env!("CARGO_BIN_EXE_lcoat"));
    let o = c
        .arg("doctor")
        .env_remove("LAB_ROOT")
        .env("LCOAT_ROOT", &root)
        .env("LCOAT_NOW", "2026-10-02T07:40:00Z")
        .output()
        .unwrap();
    assert!(!o.status.success());
    let text = stdout(&o);
    assert_eq!(row_status(&text, "first"), "fail");
    assert!(row_detail(&text, "first").contains("lcoat evidence verify first"));
    assert_eq!(row_status(&text, "active operation"), "fail");
    assert!(row_detail(&text, "active operation").contains("'gone'"));
    assert_eq!(row_status(&text, "interrupted writes"), "warn");
    #[cfg(unix)]
    assert_eq!(row_status(&text, "symlinks"), "warn");
    assert_eq!(row_status(&text, "frozen clock"), "warn");
    assert_eq!(row_status(&text, "second"), "ok");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_rewritten_ledger_event_is_named() {
    let (base, root) = lab("chain");
    let ledger = root.join("sessions/first/ledger.ndjson");
    let text = std::fs::read_to_string(&ledger).unwrap();
    std::fs::write(
        &ledger,
        text.replacen("reason=add evidence artifact", "reason=nothing to see", 1),
    )
    .unwrap();
    let out = stdout(&cmd(Some(&root), &["doctor"]));
    assert_eq!(row_status(&out, "first"), "fail");
    assert!(
        row_detail(&out, "first").contains("chain broken at event"),
        "{out}"
    );
    // A deleted ledger is not an empty v1 one.
    std::fs::remove_file(&ledger).unwrap();
    let out = stdout(&cmd(Some(&root), &["doctor"]));
    assert_eq!(row_status(&out, "first"), "fail");
    assert!(
        row_detail(&out, "first").contains("ledger missing"),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn files_left_by_another_user_fail() {
    use std::os::unix::fs::MetadataExt;
    // Needs chown, so only when the tests run as root (containers do).
    if std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(1)
        != 0
    {
        return;
    }
    let (base, root) = lab("owner");
    let f = root.join("sessions/second/session.env");
    let st = Command::new("chown").arg("4242").arg(&f).status().unwrap();
    assert!(st.success());
    let out = stdout(&cmd(Some(&root), &["doctor"]));
    assert_eq!(row_status(&out, "ownership"), "fail");
    assert!(row_detail(&out, "ownership").contains("sessions/second/session.env, uid 4242"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn json_carries_every_row_and_the_counts() {
    let (base, root) = lab("json");
    let o = cmd(Some(&root), &["doctor", "--json"]);
    let text = stdout(&o);
    let v = Value::parse(text.trim_end()).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.get("schema_version").and_then(Value::as_str),
        Some("lcoat.doctor.v1")
    );
    let Some(Value::Array(checks)) = obj.get("checks") else {
        panic!("{text}")
    };
    let fails = checks
        .iter()
        .filter(|c| {
            c.as_object()
                .and_then(|o| o.get("status"))
                .and_then(Value::as_str)
                == Some("fail")
        })
        .count();
    let Some(Value::Number(n)) = obj.get("failures") else {
        panic!("{text}")
    };
    assert_eq!(n, &fails.to_string());
    assert_eq!(o.status.success(), fails == 0);
    let status = obj.get("status").and_then(Value::as_str).unwrap();
    assert_eq!(status == "ok", fails == 0);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn unknown_options_are_refused() {
    let o = cmd(None, &["doctor", "--deep"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("unknown doctor option: --deep"));
}
