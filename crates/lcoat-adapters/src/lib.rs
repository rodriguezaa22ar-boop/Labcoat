//! Tool adapters.
//!
//! An adapter wraps one external tool as a subprocess. The runner is the only
//! code in the workspace that spawns a process, and its entry point takes a
//! `ScopedTarget`, which only `lcoat_core::scope::preflight` can produce
//! (phase 2). Arguments are parsed into typed enums at the boundary; an nmap
//! flag that is not a variant of `NmapArg` is a parse error before any
//! classification happens, and a positional argument has no variant to
//! become.
//!
//! Planned (phase 2): `nmap`, `script`. Phase 3: vantage recording.
//! After 0.2.0: `nuclei`, `zap`. Never: exploit frameworks.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

/// Contract every adapter implements. Concrete adapters arrive in phase 2.
pub trait Adapter {
    /// Stable identifier, e.g. `"nmap"`.
    fn name(&self) -> &'static str;
    /// The tier this invocation is classified at. Unknown input must fail to
    /// parse rather than classify low.
    fn tier(&self) -> lcoat_core::tier::Tier;
}
