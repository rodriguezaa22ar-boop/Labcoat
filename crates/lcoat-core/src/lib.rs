//! Lab Coat trust logic.
//!
//! This crate turns the rules the shell and Go builds enforced with tests
//! into types. The two that matter most:
//!
//! - [`metadata::MetadataOnly`]: the only string type a packet or receipt
//!   writer accepts, and the forbidden-content scanner is its only
//!   constructor. Raw content has no path onto disk.
//! - [`tier::Tier`]: capability tiers as an enum with a hard ceiling, so
//!   "above Tier 3" is unrepresentable in a runner call.
//!
//! Status per module (see `docs/BLUEPRINT.md`, "Eight-week plan"):
//!
//! | Module | Phase | Status |
//! | --- | --- | --- |
//! | [`metadata`] | 0 | done: scanner ported from `receipt.sh`, type-gated |
//! | [`tier`] | 0 | done |
//! | [`chain`] | 0 | done: ledger event-hash definition frozen with jq-computed vectors; `verify` names the broken event |
//! | [`root`] | 1 | done: `LabRoot::from_env`, unset is an error, nothing here creates directories |
//! | [`ledger`] | 1 | done: reader, `verify_operation_ledger`, prefix hash, append-only `Ledger` handle |
//! | [`scope`] | 1 | done: profiles, snapshot, `preflight` with the Tier ceiling ahead of the approval gate |
//! | [`operation`] | 1 | done: loading side; the typestate lifecycle is phase 2 |
//! | [`evidence`], [`findings`], [`validation`] | 1 | done: readers, orderings, `verify_artifacts`; writers are phase 2 |
//! | [`readiness`] | 1 | done: byte-identical to the shell build's block |
//! | [`packet`] | 1 | done: closeout/audit/archive verifiers and the trust chain, shell-exact rows; renderers are phase 2 |
//! | [`receipt`] | 1 | done: verify, replay, create (`jq -S` form); signatures are phase 4 |
//! | `approval` | 4 | planned: Tier 3 grants |

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod approval;
pub mod chain;
pub mod crash;
pub mod doctor;
pub mod error;
pub mod evidence;
pub mod findings;
pub mod history;
pub mod ledger;
pub mod lock;
pub mod metadata;
pub mod operation;
pub mod packet;
pub mod readiness;
pub mod receipt;
pub mod repair;
pub mod report;
pub mod root;
pub mod scope;
pub mod tier;
pub mod validation;

pub use error::{Error, Result};
pub use root::LabRoot;
