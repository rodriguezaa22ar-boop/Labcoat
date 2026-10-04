//! The script adapter: an operator-provided command captured as evidence.
//!
//! The operator must declare the tier (`--tier 1|2|3`) and the preflight
//! checks it like any other request, so a Tier 3 script needs a current
//! approval. An undeclared tier is a parse error rather than a guess: Lite
//! treated it as Tier 3 and refused; here the message says what to add.
//! Output is not parsed; the capture is the evidence.

use std::time::Duration;

use lcoat_core::error::Result;
use lcoat_core::fail;
use lcoat_core::scope::ScopedTarget;
use lcoat_core::tier::Tier;

use crate::{Adapter, ProposedFinding};

/// Arbitrary command, declared tier.
pub struct Script;

/// A parsed script invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptArgs {
    /// The declared tier.
    pub tier: Tier,
    /// The command and its arguments, run as given (no shell).
    pub argv: Vec<String>,
}

impl ScriptArgs {
    /// `--tier N [--] cmd args...`
    pub fn parse(args: &[String]) -> Result<Self> {
        let (tier, rest) = match args {
            [flag, n, rest @ ..] if flag == "--tier" => {
                let tier = match n.as_str() {
                    "1" => Tier::PassiveRecon,
                    "2" => Tier::ActiveRecon,
                    "3" => Tier::SafeValidation,
                    other => fail!("script adapter: --tier must be 1, 2 or 3, got: {other}"),
                };
                (tier, rest)
            }
            _ => fail!(
                "script adapter requires a declared tier: --tier 1|2|3 [--] <command> [args...]"
            ),
        };
        let rest = match rest {
            [sep, cmd @ ..] if sep == "--" => cmd,
            cmd => cmd,
        };
        if rest.is_empty() {
            fail!("script adapter requires a command after --tier <1|2|3>");
        }
        if rest[0].starts_with('-') {
            fail!(
                "script adapter: command {:?} looks like a flag; put the command after --",
                rest[0]
            );
        }
        Ok(Self {
            tier,
            argv: rest.to_vec(),
        })
    }
}

impl Adapter for Script {
    fn name(&self) -> &'static str {
        "script"
    }

    fn classify(&self, args: &[String]) -> Result<Tier> {
        Ok(ScriptArgs::parse(args)?.tier)
    }

    fn command(&self, _target: &ScopedTarget, args: &[String]) -> Result<Vec<String>> {
        Ok(ScriptArgs::parse(args)?.argv)
    }

    fn parse(&self, _stdout: &[u8]) -> Vec<ProposedFinding> {
        Vec::new()
    }

    fn default_timeout(&self) -> Duration {
        Duration::from_secs(120)
    }

    fn note(&self) -> &'static str {
        "evidence capture only; --tier 1|2|3 required (3 needs an approval)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn declared_tier_is_required_and_bounded() {
        assert_eq!(
            ScriptArgs::parse(&args(&["--tier", "1", "ss", "-ltn"]))
                .unwrap()
                .tier,
            Tier::PassiveRecon
        );
        assert_eq!(
            ScriptArgs::parse(&args(&["--tier", "3", "--", "curl", "-sI", "http://x"]))
                .unwrap()
                .argv,
            ["curl", "-sI", "http://x"]
        );
        assert!(
            ScriptArgs::parse(&args(&["ss", "-ltn"]))
                .unwrap_err()
                .to_string()
                .contains("declared tier")
        );
        assert!(
            ScriptArgs::parse(&args(&["--tier", "4", "x"]))
                .unwrap_err()
                .to_string()
                .contains("1, 2 or 3")
        );
        assert!(
            ScriptArgs::parse(&args(&["--tier", "2"]))
                .unwrap_err()
                .to_string()
                .contains("requires a command")
        );
        assert!(
            ScriptArgs::parse(&args(&["--tier", "2", "--timeout"]))
                .unwrap_err()
                .to_string()
                .contains("looks like a flag")
        );
    }
}
