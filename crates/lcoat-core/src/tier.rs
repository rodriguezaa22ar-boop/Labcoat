//! Capability tiers.
//!
//! The six tiers come from the Atlas scope model. Lite refused anything above
//! Tier 2; Lab Coat allows Tier 3 only under a recorded approval and refuses
//! Tier 4 and 5 unconditionally. Because the ceiling is a type-level constant,
//! a runner cannot be handed a tier above it.

use std::fmt;

/// A capability tier. Ordering is meaningful: higher is more intrusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Tier {
    /// Tier 0: reads local state only; touches no target.
    ReadOnly = 0,
    /// Tier 1: observes without probing (host discovery, local listing).
    PassiveRecon = 1,
    /// Tier 2: probes services (port and version scans).
    ActiveRecon = 2,
    /// Tier 3: non-destructive validation; requires an approval record.
    SafeValidation = 3,
    /// Tier 4: intrusive validation. Refused by Lab Coat.
    IntrusiveValidation = 4,
    /// Tier 5: destructive. Refused by Lab Coat.
    Destructive = 5,
}

/// The highest tier any Lab Coat runner will execute, approval or not.
pub const MAX_EXECUTABLE_TIER: Tier = Tier::SafeValidation;

impl Tier {
    /// The capability name as it appears in profiles, ledgers and packets.
    pub fn capability(self) -> &'static str {
        match self {
            Tier::ReadOnly => "read-only",
            Tier::PassiveRecon => "passive-recon",
            Tier::ActiveRecon => "active-recon",
            Tier::SafeValidation => "safe-validation",
            Tier::IntrusiveValidation => "intrusive-validation",
            Tier::Destructive => "destructive",
        }
    }

    /// Parse a capability name from a profile or ledger line.
    pub fn from_capability(name: &str) -> Option<Self> {
        Some(match name {
            "read-only" => Tier::ReadOnly,
            "passive-recon" => Tier::PassiveRecon,
            "active-recon" => Tier::ActiveRecon,
            "safe-validation" => Tier::SafeValidation,
            "intrusive-validation" => Tier::IntrusiveValidation,
            "destructive" => Tier::Destructive,
            _ => return None,
        })
    }

    /// Tier 3 and above need an approval record before they may run.
    pub fn requires_approval(self) -> bool {
        self >= Tier::SafeValidation
    }

    /// Whether any Lab Coat runner may execute this tier at all.
    pub fn executable(self) -> bool {
        self <= MAX_EXECUTABLE_TIER
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tier {} ({})", *self as u8, self.capability())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for t in [
            Tier::ReadOnly,
            Tier::PassiveRecon,
            Tier::ActiveRecon,
            Tier::SafeValidation,
            Tier::IntrusiveValidation,
            Tier::Destructive,
        ] {
            assert_eq!(Tier::from_capability(t.capability()), Some(t));
        }
        assert_eq!(Tier::from_capability("exploit"), None);
    }

    #[test]
    fn ceiling_and_approval() {
        assert!(Tier::ActiveRecon.executable());
        assert!(!Tier::ActiveRecon.requires_approval());
        assert!(Tier::SafeValidation.executable());
        assert!(Tier::SafeValidation.requires_approval());
        assert!(!Tier::IntrusiveValidation.executable());
        assert!(!Tier::Destructive.executable());
    }
}
