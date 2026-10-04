//! The lifecycle rules that are types, checked by the compiler refusing code
//! that breaks them (quality bar item 2). Each case is a tiny downstream
//! crate built against this one with `cargo`; the test asserts the build
//! fails with the expected error. std-only: no trybuild.
//!
//! The cases take a few seconds each (one shared target directory keeps the
//! dependency build to the first case). `LCOAT_SKIP_COMPILE_FAIL=1` skips.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

const PRELUDE: &str = r#"
#![allow(unused_imports, dead_code, unreachable_code)]
use lcoat_core::operation::{Active, Closed, Operation};
use lcoat_core::metadata::MetadataOnly;
use lcoat_core::root::LabRoot;
use lcoat_core::tier::Tier;
fn root() -> LabRoot { LabRoot::at(std::path::Path::new("/nonexistent")).unwrap() }
"#;

struct Case {
    name: &'static str,
    body: &'static str,
    /// Every one of these must appear in rustc's stderr.
    errors: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        name: "evidence_on_closed_operation",
        body: r#"
fn main() {
    let closed: Operation<Closed> = Operation::load(&root(), "x").unwrap().into_closed().unwrap();
    let params = lcoat_core::evidence::AddParams {
        source: std::path::PathBuf::from("/tmp/a"),
        kind: None, target: None, classification: None, redacted: false,
        tool: String::new(), vantage: None,
    };
    let _ = lcoat_core::evidence::add(&closed, &params);
}
"#,
        errors: &[
            "E0308",
            "expected `&Operation<Active>`",
            "found `&Operation<Closed>`",
        ],
    },
    Case {
        name: "finding_on_closed_operation",
        body: r#"
fn main() {
    let closed: Operation<Closed> = Operation::load(&root(), "x").unwrap().into_closed().unwrap();
    let _ = lcoat_core::findings::resolve(&closed, "f", &[], None);
}
"#,
        errors: &["E0308", "expected `&Operation<Active>`"],
    },
    Case {
        name: "close_an_already_closed_operation",
        body: r#"
fn main() {
    let closed: Operation<Closed> = Operation::load(&root(), "x").unwrap().into_closed().unwrap();
    let _ = closed.close("ready", "");
}
"#,
        errors: &["E0599", "no method named `close` found"],
    },
    Case {
        name: "closeout_on_active_operation",
        body: r#"
fn main() {
    let active: Operation<Active> = Operation::load(&root(), "x").unwrap().into_active().unwrap();
    let _ = lcoat_core::packet::closeout(&active, "");
}
"#,
        errors: &[
            "E0308",
            "expected `&Operation<Closed>`",
            "found `&Operation<Active>`",
        ],
    },
    Case {
        name: "scoped_target_without_preflight",
        body: r#"
fn main() {
    let _ = lcoat_core::scope::ScopedTarget::new("node", "10.0.0.1", Tier::PassiveRecon);
}
"#,
        errors: &["E0624", "associated function `new` is private"],
    },
    Case {
        name: "free_text_where_metadata_required",
        body: r#"
fn main() {
    let active: Operation<Active> = Operation::load(&root(), "x").unwrap().into_active().unwrap();
    let params = lcoat_core::findings::AddParams {
        title: Some(String::from("password=hunter2")),
        ..Default::default()
    };
    let _ = lcoat_core::findings::add(&active, &params);
}
"#,
        errors: &["E0308", "expected `MetadataOnly`, found `String`"],
    },
    Case {
        name: "forged_packet_handle",
        body: r#"
fn main() {
    let closed: Operation<Closed> = Operation::load(&root(), "x").unwrap().into_closed().unwrap();
    let fake = lcoat_core::packet::Written { path: std::path::PathBuf::from("/tmp/c.md"), sha256: String::new() };
    let _ = lcoat_core::packet::audit(&closed, &fake, "");
}
"#,
        errors: &[
            "E0451",
            "fields `path` and `sha256` of struct `Written` are private",
        ],
    },
    Case {
        name: "audit_before_closeout_by_type",
        body: r#"
fn main() {
    let closed: Operation<Closed> = Operation::load(&root(), "x").unwrap().into_closed().unwrap();
    // The path of the closeout manifest is not a proof that it was written.
    let _ = lcoat_core::packet::audit(&closed, std::path::Path::new("/tmp/c.md"), "");
}
"#,
        errors: &["E0308", "expected `&Written`"],
    },
];

fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn target_dir() -> PathBuf {
    // Under the workspace target directory, git-ignored, shared by all cases.
    core_dir()
        .join("../../target/compile-fail")
        .canonicalize_or_self()
}

trait CanonicalizeOrSelf {
    fn canonicalize_or_self(self) -> PathBuf;
}
impl CanonicalizeOrSelf for PathBuf {
    fn canonicalize_or_self(self) -> PathBuf {
        std::fs::create_dir_all(&self).unwrap();
        self.canonicalize().unwrap_or(self)
    }
}

fn write_case(dir: &Path, case: &Case) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    // One package name per case: cargo fingerprints by package id, and two
    // packages with the same name in one target directory would share a
    // fingerprint, letting a case that failed pass as "fresh".
    let manifest = format!(
        r#"[package]
name = "compile_fail_{name}"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
lcoat-core = {{ path = {core:?} }}
"#,
        name = case.name,
        core = core_dir().display().to_string()
    );
    std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
    std::fs::write(dir.join("src/main.rs"), format!("{PRELUDE}\n{}", case.body)).unwrap();
}

#[test]
fn lifecycle_rules_are_enforced_by_the_compiler() {
    if std::env::var_os("LCOAT_SKIP_COMPILE_FAIL").is_some() {
        eprintln!("compile-fail cases skipped (LCOAT_SKIP_COMPILE_FAIL)");
        return;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let target = target_dir();
    let mut failures = Vec::new();
    for case in CASES {
        let dir = target.join("cases").join(case.name);
        write_case(&dir, case);
        let out = Command::new(&cargo)
            .args(["build", "--quiet", "--offline"])
            .current_dir(&dir)
            .env("CARGO_TARGET_DIR", &target)
            .env_remove("RUSTFLAGS")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() {
            failures.push(format!(
                "{}: compiled, but must not; cargo said:\n{stderr}",
                case.name
            ));
            continue;
        }
        for e in case.errors {
            if !stderr.contains(e) {
                failures.push(format!(
                    "{}: expected {e:?} in the compiler output; got:\n{stderr}",
                    case.name
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    // And the prelude itself is sound: an empty main compiles.
    let dir = target.join("cases").join("control");
    write_case(
        &dir,
        &Case {
            name: "control",
            body: "fn main() {}",
            errors: &[],
        },
    );
    let out = Command::new(&cargo)
        .args(["build", "--quiet", "--offline"])
        .current_dir(&dir)
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("RUSTFLAGS")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "control case must compile:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
