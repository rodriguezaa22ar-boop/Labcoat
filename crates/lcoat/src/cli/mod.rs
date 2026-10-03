//! The `lcoat <domain> <verb>` grammar, hand-rolled as in Lite so the binary
//! carries no dependencies. Output reproduces the shell build's plain text
//! so the three implementations can be diffed line for line.
//!
//! Phase 1 ships the read-only side: everything here takes `&LabRoot` and
//! writes nothing under the lab root. Commands that need no root
//! (`version`, `hash`, `scan`, `receipt *`, `ledger *`) never resolve one,
//! and no read-only command ever creates a directory.

use std::io::Write;

use lcoat_core::error::Error;
use lcoat_core::root::LabRoot;

mod evidence;
mod finding;
mod ledger;
mod op;
mod receipt;
mod scope;
mod tools;

/// The rule line the shell build prints between sections.
pub const RULE: &str = "------------------------------------------------------------";

/// Usage text.
pub const USAGE: &str = "usage:
  lcoat help
  lcoat version
  lcoat op list
  lcoat op readiness [name]
  lcoat op verify [name] [closeout-manifest]
  lcoat op audit-verify [name] [audit-packet]
  lcoat op archive-verify [name] [archive-packet]
  lcoat op trust-chain [name] [--strict]
  lcoat scope status [operation]
  lcoat evidence list [operation]
  lcoat evidence verify [operation]
  lcoat finding list [operation]
  lcoat ledger verify <ledger-file|-> [--json]
  lcoat ledger checkpoint <ledger-file|-> [--json]
  lcoat receipt create --action action --actor actor --subject-type type --subject ref [--prev-hash sha256] [--evidence-ref ref] [--artifact-ref path=sha256] [--approval-ref ref] [--limitation text] [--out receipt.json] [--json]
  lcoat receipt verify <receipt-file|-> [--json]
  lcoat receipt replay <receipt-file> [receipt-file ...] [--json]
  lcoat hash <file>...
  lcoat scan <file.json>... | lcoat scan --text <string>

The lab root comes from LCOAT_ROOT (or LAB_ROOT); read-only commands never
create it. Phase 2 adds the write side (target, profile, op start/close,
evidence add, finding add, packets, adapters).
";

/// A command's failure: an operator-facing error, or an exit code for a
/// verifier that already printed its verdict.
#[derive(Debug)]
pub enum CliError {
    /// Printed as `error: <message>`, exit 1.
    Core(Error),
    /// Exit with this code; output already written.
    Exit(i32),
}

impl From<Error> for CliError {
    fn from(e: Error) -> Self {
        CliError::Core(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Core(Error::Io(e))
    }
}

/// Command result.
pub type CmdResult = std::result::Result<(), CliError>;

/// Output streams for one invocation.
pub struct Ctx<'a> {
    /// Standard output.
    pub out: &'a mut dyn Write,
    /// Standard error.
    pub err: &'a mut dyn Write,
}

impl Ctx<'_> {
    /// `key: value`
    pub fn kv(&mut self, key: &str, value: &str) {
        let _ = writeln!(self.out, "{key}: {value}");
    }
    /// `note: msg`
    pub fn note(&mut self, msg: &str) {
        let _ = writeln!(self.out, "note: {msg}");
    }
    /// A heading line.
    pub fn heading(&mut self, msg: &str) {
        let _ = writeln!(self.out, "{msg}");
    }
    /// The rule.
    pub fn rule(&mut self) {
        let _ = writeln!(self.out, "{RULE}");
    }
    /// Any line.
    pub fn line(&mut self, text: &str) {
        let _ = writeln!(self.out, "{text}");
    }
    /// Raw bytes.
    pub fn raw(&mut self, bytes: &[u8]) {
        let _ = self.out.write_all(bytes);
    }
}

/// Build an operator-facing error.
pub fn fail(msg: impl Into<String>) -> CliError {
    CliError::Core(Error::user(msg))
}

/// `need_args`.
pub fn need_args(min: usize, args: &[String], usage: &str) -> CmdResult {
    if args.len() < min {
        Err(fail(usage))
    } else {
        Ok(())
    }
}

/// Read a flag value, failing with `usage` when missing.
pub fn option<'a>(
    args: &'a [String],
    i: usize,
    usage: &str,
) -> std::result::Result<&'a str, CliError> {
    args.get(i + 1)
        .map(String::as_str)
        .ok_or_else(|| fail(usage))
}

/// Run argv (without the program name); returns the exit code.
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut ctx = Ctx { out, err };
    let result = dispatch(&mut ctx, args);
    let code = match result {
        Ok(()) => 0,
        Err(CliError::Exit(code)) => code,
        Err(CliError::Core(e)) => {
            let _ = writeln!(ctx.err, "error: {e}");
            1
        }
    };
    let _ = ctx.out.flush();
    let _ = ctx.err.flush();
    code
}

fn dispatch(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((domain, rest)) = args.split_first() else {
        ctx.raw(USAGE.as_bytes());
        return Ok(());
    };
    match domain.as_str() {
        "help" | "--help" | "-h" => {
            ctx.raw(USAGE.as_bytes());
            Ok(())
        }
        "version" | "--version" | "-V" => {
            ctx.line(&format!("lcoat {}", env!("CARGO_PKG_VERSION")));
            Ok(())
        }
        "hash" => tools::hash(ctx, rest),
        "scan" => tools::scan(ctx, rest),
        "receipt" => receipt::run(ctx, rest),
        "ledger" => ledger::run(ctx, rest),
        "op" => op::run(ctx, &root()?, rest),
        "scope" => scope::run(ctx, &root()?, rest),
        "evidence" => evidence::run(ctx, &root()?, rest),
        "finding" => finding::run(ctx, &root()?, rest),
        other => Err(fail(format!(
            "unknown command: {other}\n{}",
            USAGE.trim_end()
        ))),
    }
}

fn root() -> std::result::Result<LabRoot, CliError> {
    Ok(LabRoot::from_env()?)
}

/// `[name]` or nothing: the first non-flag argument names the operation.
pub fn load_op(
    root: &LabRoot,
    args: &[String],
) -> std::result::Result<lcoat_core::operation::Operation, CliError> {
    let name = args
        .first()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("");
    Ok(lcoat_core::operation::Operation::load_named_or_active(
        root, name,
    )?)
}

/// `[operation]` only: more than one argument, or a flag, is a usage error.
pub fn load_read_only_op(
    root: &LabRoot,
    args: &[String],
    usage: &str,
) -> std::result::Result<lcoat_core::operation::Operation, CliError> {
    if args.len() > 1 || args.first().is_some_and(|a| a.starts_with('-')) {
        return Err(fail(format!("usage: {usage}")));
    }
    load_op(root, args)
}
