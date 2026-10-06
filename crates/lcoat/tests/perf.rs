#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Quality bar 8, measured: every command on a 10,000-event ledger.
//!
//! Ignored by default (it is a measurement, not a check). Run it on a
//! release build and record the numbers in docs/BLUEPRINT.md:
//!
//!   cargo test --release -p lcoat --test perf -- --ignored --nocapture
//!
//! It builds an operation through the library (10,000 ledger events, 200
//! evidence artifacts, 50 findings), then times each read command through
//! the real binary, best of three runs.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use lcoat_core::evidence::{self, AddParams};
use lcoat_core::findings;
use lcoat_core::metadata::MetadataOnly;
use lcoat_core::operation::{NewTarget, Operation, StartParams, add_target};
use lcoat_core::root::LabRoot;
use lcoat_core::tier::Tier;

const EVENTS: usize = 10_000;
const ARTIFACTS: usize = 200;
const FINDINGS: usize = 50;

fn time(root: &Path, args: &[&str]) -> Duration {
    (0..3)
        .map(|_| {
            let started = Instant::now();
            let out = Command::new(env!("CARGO_BIN_EXE_lcoat"))
                .args(args)
                .env_remove("LAB_ROOT")
                .env("LCOAT_ROOT", root)
                .output()
                .unwrap();
            let took = started.elapsed();
            assert!(
                out.status.code().is_some_and(|c| c <= 1),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            took
        })
        .min()
        .unwrap()
}

#[test]
#[ignore = "measurement; run with --release -- --ignored --nocapture"]
fn ten_thousand_event_ledger() {
    let dir = std::env::temp_dir().join(format!("lcoat-perf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = LabRoot::at(&dir).unwrap();
    root.ensure_layout().unwrap();
    add_target(
        &root,
        &NewTarget {
            name: "node".into(),
            address: "10.10.10.5".into(),
            scope_status: "in-scope".into(),
            criticality: "low".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let (op, _) = Operation::start(
        &root,
        &StartParams {
            name: "perf".into(),
            target: "node".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let build = Instant::now();
    for i in 0..ARTIFACTS {
        let p = dir.join(format!("scan-{i}.txt"));
        std::fs::write(&p, format!("PORT {i} open\n").repeat(200)).unwrap();
        evidence::add(
            &op,
            &AddParams {
                source: p,
                kind: Some(MetadataOnly::scan("scan-output").unwrap()),
                target: None,
                classification: None,
                redacted: false,
                tool: String::new(),
                vantage: None,
            },
        )
        .unwrap();
    }
    for i in 0..FINDINGS {
        findings::add(
            &op,
            &findings::AddParams {
                title: Some(MetadataOnly::scan(&format!("finding {i}")).unwrap()),
                ..Default::default()
            },
        )
        .unwrap();
    }
    let detail = MetadataOnly::scan("note=perf").unwrap();
    let written = op.events().unwrap().len();
    for _ in written..EVENTS {
        op.append_event("operator.note", Tier::ReadOnly, "lcoat", "ok", &detail)
            .unwrap();
    }
    assert_eq!(op.events().unwrap().len(), EVENTS);
    eprintln!("built in {:?}", build.elapsed());

    let ledger = op.dir.join("ledger.ndjson").display().to_string();
    for args in [
        &["op", "status", "perf"][..],
        &["op", "readiness", "perf"],
        &["op", "trust-chain", "perf"],
        &["evidence", "list", "perf"],
        &["evidence", "verify", "perf"],
        &["finding", "list", "perf"],
        &["ledger", "verify", &ledger],
        &["ledger", "chain-verify", "perf"],
        &["ledger", "checkpoint", &ledger],
    ] {
        let t = time(&dir, args);
        eprintln!(
            "{:>8.1} ms  lcoat {}",
            t.as_secs_f64() * 1e3,
            args.join(" ").replace(&ledger, "<ledger>")
        );
    }
    if std::env::var_os("LCOAT_PERF_KEEP").is_some() {
        eprintln!("kept: {}", dir.display());
    } else {
        let _ = std::fs::remove_dir_all(&dir);
    }
}
