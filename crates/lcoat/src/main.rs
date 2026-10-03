//! `lcoat` command-line entry point.
//!
//! The grammar is `lcoat <domain> <verb>`, as in the shell and Go builds, and
//! parsing is hand-rolled as Lite's was so the binary carries no
//! dependencies. Phase 0 ships `version`, `hash` and `scan`. Each later phase
//! adds its command group; the full surface is in `docs/BLUEPRINT.md`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::path::Path;
use std::process::ExitCode;

use lcoat_core::metadata::{MetadataOnly, forbidden_paths};
use lcoat_format::hash::Sha256Hex;
use lcoat_format::json::Value;

const USAGE: &str = "usage:
  lcoat version                 print the version
  lcoat hash <file>...          SHA-256 of each file, as the packets record it
  lcoat scan <file.json>...     report forbidden raw-content paths in JSON documents
  lcoat scan --text <string>    check one string against the metadata-only scanner
  lcoat help                    this text
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
    };
    match cmd {
        "version" | "--version" | "-V" => {
            println!("lcoat {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        "hash" => hash(rest),
        "scan" => scan(rest),
        other => {
            eprintln!("error: unknown command: {other}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn hash(paths: &[String]) -> ExitCode {
    if paths.is_empty() {
        eprintln!("error: hash requires at least one file\n{USAGE}");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    for p in paths {
        match Sha256Hex::of_file(Path::new(p)) {
            Ok(h) => println!("{h}  {p}"),
            Err(e) => {
                eprintln!("error: {p}: {e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn scan(args: &[String]) -> ExitCode {
    if let Some((flag, rest)) = args.split_first()
        && flag == "--text"
    {
        let text = rest.join(" ");
        return match MetadataOnly::scan(&text) {
            Ok(_) => {
                println!("ok: metadata-only");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        };
    }
    if args.is_empty() {
        eprintln!("error: scan requires a file or --text\n{USAGE}");
        return ExitCode::FAILURE;
    }
    let mut dirty = false;
    for p in args {
        let text = match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {p}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let doc = match Value::parse(&text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {p}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let paths = forbidden_paths(&doc);
        if paths.is_empty() {
            println!("ok: {p}: metadata-only");
        } else {
            dirty = true;
            println!("forbidden: {p}: {}", paths.join(","));
        }
    }
    if dirty {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
