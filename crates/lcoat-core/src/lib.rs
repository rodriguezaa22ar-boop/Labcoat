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
//! | `root` | 1 | planned: `LabRoot::from_env`, unset is an error |
//! | `ledger` | 1 | planned: read v1, append-only handle, chain fields (phase 3) |
//! | `verify` | 1 | planned: packet verifiers, trust chain, evidence verify |
//! | `receipt` | 1 | planned: verify, replay, create, sign (phase 4) |
//! | `scope`, `operation` | 2 | planned: profiles, preflight, typestate lifecycle |
//! | `evidence`, `findings`, `packet` | 2 | planned: writers take `MetadataOnly` only |
//! | `approval` | 4 | planned: Tier 3 grants |

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod chain;
pub mod metadata;
pub mod tier;
