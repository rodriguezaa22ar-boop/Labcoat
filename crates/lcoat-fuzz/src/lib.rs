//! Fuzzing for every Lab Coat parser that reads untrusted bytes.
//!
//! - [`targets`]: one function per parser, asserting its safety invariants.
//! - [`engine`]: a dependency-free mutational fuzzer that runs the targets
//!   under `cargo test` (short budget) and from the `lcoat-fuzz` binary
//!   (long campaigns).
//! - `fuzz/` at the repository root: cargo-fuzz (libFuzzer, coverage-guided)
//!   harnesses that call the same target functions; CI runs them on nightly.
//!
//! Never shipped: this crate exists to break the others.

// Harness code: a target reports a broken invariant by panicking, and the
// engine catches it. The workspace's no-panic rule is for the shipped crates.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

pub mod engine;
pub mod targets;

pub use engine::{Config, Report, Target, exec, fuzz};
pub use targets::{TARGETS, find};

/// Run one input through a named target, for the cargo-fuzz harness: a
/// failure panics (libFuzzer reports it), success returns nothing.
pub fn run_one(name: &str, data: &[u8]) {
    if let Some(t) = find(name) {
        let _ = (t.run)(data);
    }
}

/// The repository's corpus directory for a target
/// (`crates/lcoat-fuzz/corpus/<target>`: seeds and every regression).
pub fn corpus_dir(target: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(target)
}
