//! On-disk formats shared by every Lab Coat implementation.
//!
//! This crate is where byte-compatibility lives. Every rule here was first
//! established by the Atlas shell build and reproduced by Lab Coat Lite (Go);
//! the Go fixtures under `fixtures/golden/` are the test vectors. The crate
//! uses the standard library only, performs no I/O beyond reading a path it
//! is handed, and depends on nothing else in the workspace.
//!
//! Status per module (see `docs/BLUEPRINT.md`, "Eight-week plan"):
//!
//! | Module | Phase | Status |
//! | --- | --- | --- |
//! | [`json`] | 0 | done: strict RFC 8259 parser that keeps number literals |
//! | [`canonical`] | 0 | done: reproduces `jq -cS` and the golden receipt hashes |
//! | [`sha256`] | 0 | done: FIPS 180-4, tested against the standard vectors |
//! | [`hash`] | 0 | done: `Sha256Hex`; reproduces the golden ledger hash |
//! | [`envfile`] | 1 | done: bash `printf %q` quoting round trip |
//! | [`ndjson`] | 1 | done: line reader, latest-per-id, append |
//! | [`clock`] | 1 | done: RFC 3339 UTC, `LCOAT_NOW` frozen clock |
//! | [`ids`] | 1 | done: slugify, second-resolution IDs with `_02` suffixes |

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod canonical;
pub mod clock;
pub mod envfile;
pub mod hash;
pub mod ids;
pub mod json;
pub mod ndjson;
pub mod sha256;
