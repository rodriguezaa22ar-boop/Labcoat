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
//! Status per module (see `docs/BLUEPRINT.md`, "Eight-week plan" and
//! "What is prepared today"):
//!
//! | Module | Phase | Status |
//! | --- | --- | --- |
//! | [`metadata`] | 0 | done: scanner ported from `receipt.sh`, type-gated |
//! | [`tier`] | 0 | done |
//! | [`chain`] | 0 | done: ledger event-hash definition frozen with jq-computed vectors; `verify` names the broken event |
//! | [`root`] | 1 | done: `LabRoot::from_env`, unset is an error, nothing here creates directories |
//! | [`ledger`] | 1-2 | done: reader, `verify_operation_ledger`, prefix hash, append-only chained `Ledger` handle |
//! | [`scope`] | 1-2 | done: profiles, snapshot, `preflight` with the Tier ceiling ahead of the approval gate, `ScopedTarget` |
//! | [`operation`] | 2 | done: the `Operation<Active>` typestate lifecycle, targets |
//! | [`evidence`], [`findings`], [`validation`] | 2 | done: readers and writers, `verify_artifacts`, finding resolve/accept/reopen |
//! | [`readiness`] | 1 | done: byte-identical to the shell build's block |
//! | [`packet`], [`report`] | 2-3 | done: closeout/audit/archive and accepted-risk review packets, their verifiers, the trust chain |
//! | [`receipt`] | 1 | done: verify, replay, create (`jq -S` form); signatures are phase 4 |
//! | [`approval`] | 2 | done: Tier 3 grants with required expiry, list, revoke |
//! | [`lock`], [`crash`], [`history`] | 2 | done: lab-root lock, crash-injection points (test builds only), operation history |
//! | [`doctor`] | 3 | done: environment and lab-root checks |

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
pub mod report;
pub mod root;
pub mod scope;
pub mod tier;
pub mod validation;

pub use error::{Error, Result};
pub use root::LabRoot;
