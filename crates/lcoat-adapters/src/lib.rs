//! Tool adapters.
//!
//! An adapter wraps one external tool as a subprocess. The runner
//! ([`run`]) is the only code in the workspace that spawns a process, and it
//! takes a [`ScopedTarget`], which only a recorded preflight can produce.
//! Arguments are parsed into typed enums at the boundary: an nmap flag that
//! is not a variant of [`nmap::NmapArg`] is a parse error before any
//! classification happens, and a positional argument has no variant to
//! become, so operator arguments can never add a host.
//!
//! The tier of a run is derived from the adapter and its arguments, never
//! chosen by a flag (the script adapter is the exception, and there the
//! declared tier is a ceiling the operator asserts, checked by the preflight
//! like any other). Tier 4 and 5 are refused before the preflight; Tier 3
//! reaches the preflight, which requires a current approval.
//!
//! Every run records `adapter.started` (with the vantage it ran from) and
//! `adapter.finished`, captures the tool's output as hashed evidence whatever
//! the exit code, and never lets output into a ledger detail or packet.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod nmap;
pub mod runner;
pub mod script;
pub mod vantage;

pub use lcoat_core::scope::ScopedTarget;
pub use runner::{Outcome, RunParams, run};

use lcoat_core::error::Result;
use lcoat_core::tier::Tier;

/// A finding an adapter suggests from its output. The runner prints these
/// for the operator to confirm; nothing is recorded automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposedFinding {
    /// Title.
    pub title: String,
    /// Severity word.
    pub severity: &'static str,
    /// Confidence word.
    pub confidence: &'static str,
    /// One-line detail (metadata: port, protocol, service name).
    pub detail: String,
}

/// Contract every adapter implements.
pub trait Adapter {
    /// Stable identifier, e.g. `"nmap"`.
    fn name(&self) -> &'static str;
    /// Parse the operator's arguments and classify the invocation. Unknown
    /// input must fail here rather than classify low.
    fn classify(&self, args: &[String]) -> Result<Tier>;
    /// The argv to execute for `target`. Never passed to a shell.
    fn command(&self, target: &ScopedTarget, args: &[String]) -> Result<Vec<String>>;
    /// Findings proposed from captured stdout; empty when not parsed.
    fn parse(&self, stdout: &[u8]) -> Vec<ProposedFinding>;
    /// Hard timeout when the operator gives none.
    fn default_timeout(&self) -> std::time::Duration;
    /// One line for `adapter list`.
    fn note(&self) -> &'static str;
}

/// The registered adapters, in listing order.
pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![Box::new(nmap::Nmap), Box::new(script::Script)]
}

/// Look an adapter up by name.
pub fn lookup(name: &str) -> Option<Box<dyn Adapter>> {
    adapters().into_iter().find(|a| a.name() == name)
}
