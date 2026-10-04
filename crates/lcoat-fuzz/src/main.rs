//! `lcoat-fuzz`: long fuzzing campaigns without nightly or dependencies.
//!
//!   cargo run -p lcoat-fuzz --profile fuzz -- list
//!   cargo run -p lcoat-fuzz --profile fuzz -- run all --seconds 60
//!   cargo run -p lcoat-fuzz --profile fuzz -- run nmap_xml --seconds 600 --seed 7
//!   cargo run -p lcoat-fuzz --profile fuzz -- replay nmap_xml <file>...
//!   cargo run -p lcoat-fuzz -- seeds all fuzz/corpus   (for cargo-fuzz)
//!
//! Failing inputs are written to target/fuzz-crashes/. To keep one as a
//! regression, copy it into crates/lcoat-fuzz/corpus/<target>/ once fixed.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use lcoat_fuzz::{Config, TARGETS, corpus_dir, find, fuzz};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  lcoat-fuzz list\n  lcoat-fuzz run <target|all> [--seconds N] [--iters N] [--seed N]\n  lcoat-fuzz replay <target> <file>..."
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return usage();
    };
    match cmd.as_str() {
        "list" => {
            for t in TARGETS {
                println!("{:<14} {}", t.name, t.about);
            }
            ExitCode::SUCCESS
        }
        "run" => run(&args[1..]),
        "replay" => replay(&args[1..]),
        "seeds" => seeds(&args[1..]),
        _ => usage(),
    }
}

fn run(args: &[String]) -> ExitCode {
    let Some(which) = args.first() else {
        return usage();
    };
    let mut seconds: u64 = 30;
    let mut iters: u64 = u64::MAX;
    let mut seed: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);
    let mut i = 1;
    while i < args.len() {
        let v = args.get(i + 1).and_then(|v| v.parse::<u64>().ok());
        match (args[i].as_str(), v) {
            ("--seconds", Some(n)) => seconds = n,
            ("--iters", Some(n)) => iters = n,
            ("--seed", Some(n)) => seed = n,
            _ => return usage(),
        }
        i += 2;
    }
    let targets: Vec<_> = if which == "all" {
        TARGETS.iter().collect()
    } else {
        match find(which) {
            Some(t) => vec![t],
            None => {
                eprintln!("unknown target: {which} (try: lcoat-fuzz list)");
                return ExitCode::from(2);
            }
        }
    };
    let per_target = Duration::from_secs(seconds) / targets.len().max(1) as u32;
    let crash_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/fuzz-crashes");
    let mut failed = false;
    println!("seed {seed}");
    for t in targets {
        let cfg = Config {
            seed,
            iterations: iters,
            time_budget: per_target,
            corpus_dir: Some(corpus_dir(t.name)),
            crash_dir: Some(crash_dir.clone()),
            ..Config::default()
        };
        let r = fuzz(t, &cfg);
        println!(
            "{:<14} execs={:<9} shapes={:<6} corpus={:<5} failures={}",
            t.name,
            r.execs,
            r.shapes,
            r.corpus,
            r.failures.len()
        );
        for f in &r.failures {
            failed = true;
            println!(
                "  FAIL iteration {}: {}\n       saved: {}",
                f.iteration,
                f.message,
                f.saved
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".into())
            );
        }
    }
    lcoat_fuzz::targets::cleanup();
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn replay(args: &[String]) -> ExitCode {
    let Some((name, files)) = args.split_first() else {
        return usage();
    };
    let Some(t) = find(name) else {
        eprintln!("unknown target: {name}");
        return ExitCode::from(2);
    };
    let mut failed = false;
    for f in files {
        let data = std::fs::read(f).unwrap_or_default();
        match lcoat_fuzz::exec(t, &data) {
            Ok(_) => println!("ok    {f}"),
            Err(m) => {
                failed = true;
                println!("FAIL  {f}: {m}");
            }
        }
    }
    lcoat_fuzz::targets::cleanup();
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Write the built-in seeds and the stored corpus of each target to
/// `<out>/<target>/`, the layout cargo-fuzz expects.
fn seeds(args: &[String]) -> ExitCode {
    let [which, out] = args else {
        return usage();
    };
    let targets: Vec<_> = if which == "all" {
        TARGETS.iter().collect()
    } else {
        match find(which) {
            Some(t) => vec![t],
            None => return usage(),
        }
    };
    for t in targets {
        let dir = PathBuf::from(out).join(t.name);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("cannot create {}", dir.display());
            return ExitCode::FAILURE;
        }
        let mut inputs = (t.seeds)();
        inputs.extend(lcoat_fuzz::engine::read_dir_inputs(&corpus_dir(t.name)));
        for input in &inputs {
            let p = dir.join(format!("seed-{:016x}", lcoat_fuzz::engine::fnv(input)));
            if std::fs::write(&p, input).is_err() {
                eprintln!("cannot write {}", p.display());
                return ExitCode::FAILURE;
            }
        }
        println!(
            "{:<14} {} inputs -> {}",
            t.name,
            inputs.len(),
            dir.display()
        );
    }
    ExitCode::SUCCESS
}
