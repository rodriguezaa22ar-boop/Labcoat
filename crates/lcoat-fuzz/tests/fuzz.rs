//! Every fuzz target under `cargo test`: the stored corpus (seeds and every
//! regression ever found) is replayed, then a short deterministic campaign
//! runs. `LCOAT_FUZZ_ITERS` raises the budget; `LCOAT_FUZZ_SEED` changes
//! the seed (the default is fixed so a CI failure reproduces locally).

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use lcoat_fuzz::{Config, TARGETS, corpus_dir, fuzz};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn every_parser_survives_its_fuzz_campaign() {
    let iterations = env_u64("LCOAT_FUZZ_ITERS", 3_000);
    let seed = env_u64("LCOAT_FUZZ_SEED", 0x1ab_c0a7);
    let crash_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/fuzz-crashes");
    let mut report = String::new();
    for t in TARGETS {
        let cfg = Config {
            seed,
            iterations,
            time_budget: Duration::from_secs(120),
            corpus_dir: Some(corpus_dir(t.name)),
            crash_dir: Some(crash_dir.clone()),
            ..Config::default()
        };
        let r = fuzz(t, &cfg);
        eprintln!(
            "{:<14} execs={:<7} shapes={:<5} corpus={:<5} failures={}",
            t.name,
            r.execs,
            r.shapes,
            r.corpus,
            r.failures.len()
        );
        for f in r.failures {
            report.push_str(&format!(
                "\n{} (seed {seed:#x}, iteration {}): {}\n  input ({} bytes): {:?}\n  saved: {}\n",
                f.target,
                f.iteration,
                f.message,
                f.input.len(),
                String::from_utf8_lossy(&f.input[..f.input.len().min(300)]),
                f.saved.map(|p| p.display().to_string()).unwrap_or_default()
            ));
        }
    }
    lcoat_fuzz::targets::cleanup();
    assert!(report.is_empty(), "fuzz failures:{report}");
}

/// A campaign whose seeds all fail to parse never exercises the accept
/// path, where the round-trip invariants live. Every structured target must
/// have at least one seed that parses.
#[test]
fn seeds_reach_the_accept_path() {
    use lcoat_adapters::nmap::NmapArg;
    use lcoat_adapters::script::ScriptArgs;
    let words = |b: &[u8]| -> Vec<String> {
        String::from_utf8_lossy(b)
            .split(['\0', '\n'])
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let seeds = |name: &str| (lcoat_fuzz::find(name).unwrap().seeds)();
    let ok = |name: &str, f: &dyn Fn(&[u8]) -> bool| {
        let n = seeds(name).iter().filter(|s| f(s)).count();
        assert!(n > 0, "{name}: no seed reaches the accept path");
    };
    ok("nmap_args", &|s| NmapArg::parse_all(&words(s)).is_ok());
    ok("script_args", &|s| ScriptArgs::parse(&words(s)).is_ok());
    ok("json", &|s| {
        lcoat_format::json::Value::parse(&String::from_utf8_lossy(s)).is_ok()
    });
    ok("envfile", &|s| lcoat_format::envfile::parse(s).is_ok());
    ok("timestamp", &|s| {
        lcoat_format::clock::Utc::parse(&String::from_utf8_lossy(s)).is_some()
    });
    ok("receipt", &|s| lcoat_core::receipt::validate(s).is_ok());
    ok("nmap_xml", &|s| {
        !lcoat_adapters::nmap::open_ports(&String::from_utf8_lossy(s)).is_empty()
    });
    ok("ndjson", &|s| {
        lcoat_format::ndjson::parse_lines(&String::from_utf8_lossy(s), "x").is_ok()
    });
}

/// Every target has a cargo-fuzz harness and every harness names a target,
/// so the coverage-guided CI job cannot silently skip one.
#[test]
fn every_target_has_a_cargo_fuzz_harness() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/fuzz_targets");
    let mut harnesses: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()?
                .strip_suffix(".rs")
                .map(str::to_owned)
        })
        .collect();
    harnesses.sort();
    let mut targets: Vec<String> = TARGETS.iter().map(|t| t.name.to_owned()).collect();
    targets.sort();
    assert_eq!(harnesses, targets);
    let manifest = std::fs::read_to_string(dir.join("../Cargo.toml")).unwrap();
    for t in &targets {
        assert!(
            manifest.contains(&format!("name = \"{t}\"")),
            "{t} missing from fuzz/Cargo.toml"
        );
        let src = std::fs::read_to_string(dir.join(format!("{t}.rs"))).unwrap();
        assert!(
            src.contains(&format!("run_one(\"{t}\"")),
            "{t}.rs runs another target"
        );
    }
}
