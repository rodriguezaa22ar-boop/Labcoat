//! The script adapter: an operator-provided command captured as evidence.
//!
//! The operator must declare the tier (`--tier 1|2|3`) and the preflight
//! checks it like any other request, so a Tier 3 script needs a current
//! approval. An undeclared tier is a parse error rather than a guess: Lite
//! treated it as Tier 3 and refused; here the message says what to add.
//! Output is not parsed; the capture is the evidence.
//!
//! The command is bound to the scoped target: it must name it, as the
//! placeholder `{target}` (replaced with the scoped address, also inside a
//! larger argument such as `http://{target}/`) or as that address
//! literally. Any other IP address, network or `scheme://host` in the
//! arguments is refused. This closes the plain mistake (a scan pointed at
//! 8.8.8.8 after a preflight for 127.0.0.1); it cannot see inside the
//! program, so a command that finds another host by itself is still the
//! operator's word (THREAT_MODEL.md).

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

/// The placeholder replaced with the scoped address.
pub const TARGET_PLACEHOLDER: &str = "{target}";

/// A host named in `arg` other than the placeholder: an IP address or
/// network anywhere in it, the host of a `scheme://host` URL, or the host
/// after `user@`. Bare words that might be DNS names are not judged.
fn named_host(arg: &str) -> Option<String> {
    let is_ip_or_net = |t: &str| {
        let t = t.trim_matches(|c| c == '[' || c == ']');
        let addr = t.split('/').next().unwrap_or(t);
        addr.parse::<std::net::IpAddr>().is_ok()
    };
    if let Some((_, rest)) = arg.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let host = if let Some(v6) = host_port.strip_prefix('[') {
            v6.split(']').next().unwrap_or(v6)
        } else {
            host_port.split(':').next().unwrap_or(host_port)
        };
        if !host.is_empty() && host != TARGET_PLACEHOLDER {
            return Some(host.to_owned());
        }
    }
    if let Some((_, host)) = arg.split_once('@') {
        let host = host.split([':', '/']).next().unwrap_or(host);
        if !host.is_empty() && host != TARGET_PLACEHOLDER && host.contains('.') {
            return Some(host.to_owned());
        }
    }
    // Whole argument first (IPv6 contains ':'), then each piece of it.
    if is_ip_or_net(arg) {
        return Some(arg.to_owned());
    }
    arg.split(|c: char| !(c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/' | '[' | ']')))
        .chain(arg.split(|c: char| !(c.is_ascii_digit() || c == '.' || c == '/')))
        .find(|t| t.len() > 2 && is_ip_or_net(t))
        .map(str::to_owned)
}

impl ScriptArgs {
    /// The argv to run against `address`: placeholders filled, the target
    /// named at least once, and no other host named.
    pub fn bind(&self, address: &str) -> Result<Vec<String>> {
        let Some((program, rest)) = self.argv.split_first() else {
            fail!("script adapter requires a command");
        };
        if program.contains(TARGET_PLACEHOLDER) {
            fail!("script adapter: {TARGET_PLACEHOLDER} cannot be the command itself");
        }
        let mut named = false;
        let mut argv = vec![program.clone()];
        for a in rest {
            let bound = a.replace(TARGET_PLACEHOLDER, address);
            named |= bound != *a || a == address;
            if a != address
                && let Some(host) = named_host(a)
                && host != address
            {
                fail!(
                    "script adapter: argument {a:?} names {host:?}, which is not this operation's target ({address}); use {TARGET_PLACEHOLDER}"
                );
            }
            argv.push(bound);
        }
        if !named {
            fail!(
                "script adapter: the command does not name the target; put {TARGET_PLACEHOLDER} where the address goes (it becomes {address}). To keep the output of a command that does not touch the target, use evidence add"
            );
        }
        Ok(argv)
    }
}

impl Adapter for Script {
    fn name(&self) -> &'static str {
        "script"
    }

    fn classify(&self, args: &[String]) -> Result<Tier> {
        Ok(ScriptArgs::parse(args)?.tier)
    }

    fn command(&self, target: &ScopedTarget, args: &[String]) -> Result<Vec<String>> {
        ScriptArgs::parse(args)?.bind(target.address())
    }

    fn parse(&self, _stdout: &[u8]) -> Vec<ProposedFinding> {
        Vec::new()
    }

    fn default_timeout(&self) -> Duration {
        Duration::from_secs(120)
    }

    fn note(&self) -> &'static str {
        "evidence capture only; --tier 1|2|3 required (3 needs an approval); name the target as {target}"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn bind(list: &[&str]) -> Result<Vec<String>> {
        let mut a = args(&["--tier", "2", "--"]);
        a.extend(args(list));
        ScriptArgs::parse(&a)?.bind("10.10.10.5")
    }

    /// Review 2026-10-05: `--tier 2 -- /bin/echo 8.8.8.8` ran after a
    /// preflight for 127.0.0.1.
    #[test]
    fn the_command_is_bound_to_the_scoped_target() {
        assert_eq!(
            bind(&["curl", "-sI", "http://{target}:8080/x"]).unwrap(),
            ["curl", "-sI", "http://10.10.10.5:8080/x"]
        );
        assert_eq!(
            bind(&["ssh-keyscan", "-p", "22", "{target}"]).unwrap(),
            ["ssh-keyscan", "-p", "22", "10.10.10.5"]
        );
        assert_eq!(
            bind(&["ping", "-c1", "10.10.10.5"]).unwrap(),
            ["ping", "-c1", "10.10.10.5"]
        );
        assert!(bind(&["ssh", "root@{target}", "true"]).is_ok());

        let refused = |list: &[&str]| bind(list).unwrap_err().to_string();
        assert!(refused(&["/bin/echo", "probe"]).contains("does not name the target"));
        for other in [
            &["/bin/echo", "{target}", "8.8.8.8"][..],
            &["nc", "{target}", "10.10.10.0/24"],
            &["curl", "{target}", "https://example.com/"],
            &["curl", "http://user:pw@8.8.8.8/", "{target}"],
            &["curl", "{target}", "--resolve", "x:80:1.2.3.4"],
            &["ssh", "root@other.lab", "{target}"],
            &["ping6", "{target}", "2001:db8::1"],
            &["/bin/sh", "-c", "curl 8.8.8.8", "{target}"],
        ] {
            assert!(
                refused(other).contains("not this operation's target"),
                "{other:?}"
            );
        }
        assert!(refused(&["{target}"]).contains("command itself"));
        // Ports, sizes, versions and dates are not hosts.
        assert!(bind(&["nc", "-w", "3", "{target}", "22", "--opt=1.5", "2026-10-05"]).is_ok());
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
