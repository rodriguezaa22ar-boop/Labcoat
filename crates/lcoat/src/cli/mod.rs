//! The `lcoat <domain> <verb>` grammar, hand-rolled as in Lite so the binary
//! carries no dependencies. Output reproduces the shell build's plain text
//! so the three implementations can be diffed line for line.
//!
//! Read-only commands take `&LabRoot` and write nothing under the lab root;
//! none of them creates a directory. Mutating commands go through
//! [`mutable_root`], which creates the layout (0700) once, and then through
//! the typestate: a writer that needs an active operation calls
//! `into_active()`, which refuses a closed one with the command to run.
//! Commands that need no root (`version`, `hash`, `scan`, `receipt *`,
//! `ledger *`) never resolve one.

use std::io::Write;

use lcoat_core::error::Error;
use lcoat_core::root::LabRoot;

mod adapter;
mod approval;
mod evidence;
mod finding;
mod ledger;
mod op;
mod profile;
mod receipt;
mod scope;
mod target;
mod tools;

/// The rule line the shell build prints between sections.
pub const RULE: &str = "------------------------------------------------------------";

/// Usage text.
pub const USAGE: &str = "usage:
  lcoat help
  lcoat version
  lcoat target add <name> <address> [--scope-status status] [--criticality level] [--tag tag] [--owner owner] [notes...]
  lcoat target show <name>
  lcoat target list
  lcoat profile list
  lcoat profile show <name>
  lcoat op start [--profile profile] <name> <target> [notes...]
  lcoat op resume <name>
  lcoat op list
  lcoat op status [name]
  lcoat op show [name]
  lcoat op brief [name]
  lcoat op readiness [name]
  lcoat op close [name] [--force]
  lcoat op report [name] [report-name]
  lcoat op handoff [name] [handoff-name]
  lcoat op closeout [name] [manifest-name]
  lcoat op audit-packet [name] [packet-name]
  lcoat op archive-packet [name] [packet-name]
  lcoat op verify [name] [closeout-manifest] [--json]
  lcoat op audit-verify [name] [audit-packet] [--json]
  lcoat op archive-verify [name] [archive-packet] [--json]
  lcoat op trust-chain [name] [--strict] [--json]
  lcoat scope status [operation]
  lcoat scope check <capability> <target>
  lcoat approval grant <capability> --reason text --expires <YYYY-MM-DD|timestamp|Nh|Nd>
  lcoat approval list [operation]
  lcoat approval revoke <capability> --reason text
  lcoat evidence add <path> [--kind kind] [--target target] [--classification label] [--redacted true|false]
  lcoat evidence list [operation]
  lcoat evidence verify [operation] [--json]
  lcoat evidence diff <before-id> <after-id> [--op operation] [--json]
  lcoat finding add <title> [--level observed|inferred|validated] [--severity severity] [--confidence confidence] [--status status] [--impact text] [--recommendation text] [--evidence id]...
  lcoat finding resolve <id> [--evidence id]... [--note text]
  lcoat finding accept <id> --reason text [--owner owner] [--expires YYYY-MM-DD|timestamp|Nh|Nd] [--evidence id]...
  lcoat finding reopen <id> [--note text]
  lcoat finding note <id> <text>
  lcoat finding list [operation]
  lcoat finding review-queue [--op operation] [--within days]
  lcoat finding review-packet [--op operation] [--within days] [packet-name]
  lcoat finding review-verify [--op operation] [packet]
  lcoat adapter list
  lcoat adapter run <adapter> <target> [--timeout seconds] [--] [tool args...]
  lcoat ledger verify <ledger-file|-> [--json]
  lcoat ledger checkpoint <ledger-file|-> [--json]
  lcoat ledger chain-verify [operation] [--json]
  lcoat receipt create --action action --actor actor --subject-type type --subject ref [--prev-hash sha256] [--evidence-ref ref] [--artifact-ref path=sha256] [--approval-ref ref] [--limitation text] [--out receipt.json] [--json]
  lcoat receipt verify <receipt-file|-> [--json]
  lcoat receipt replay <receipt-file> [receipt-file ...] [--json]
  lcoat hash <file>...
  lcoat scan <file.json>... | lcoat scan --text <string>

The lab root comes from LCOAT_ROOT (or LAB_ROOT). Read-only commands never
create it; mutating commands create the layout once. Tiers: 0-2 run under
the scope profile, 3 needs 'approval grant', 4 and 5 are refused.
'op close' clears the active operation, so the packets that follow name it:
lcoat op closeout <name>, then audit-packet and archive-packet.
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
    /// `ok: msg`
    pub fn ok(&mut self, msg: &str) {
        let _ = writeln!(self.out, "ok: {msg}");
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
        "op" => op::run(ctx, rest),
        "scope" => scope::run(ctx, rest),
        "evidence" => evidence::run(ctx, rest),
        "finding" => finding::run(ctx, rest),
        "target" => target::run(ctx, rest),
        "profile" => profile::run(ctx, rest),
        "approval" => approval::run(ctx, rest),
        "adapter" => adapter::run(ctx, rest),
        other => Err(fail(format!(
            "unknown command: {other}\n{}",
            USAGE.trim_end()
        ))),
    }
}

/// The lab root for a read-only command: resolved, never created.
pub fn root() -> std::result::Result<LabRoot, CliError> {
    Ok(LabRoot::from_env()?)
}

/// The lab root for a mutating command: resolved and laid out (0700).
pub fn mutable_root() -> std::result::Result<LabRoot, CliError> {
    let r = LabRoot::from_env()?;
    r.ensure_layout()?;
    Ok(r)
}

/// Scan a free-text argument into [`MetadataOnly`], refusing credentials
/// and raw-content markers with the operator's flag named.
pub fn metadata(
    flag: &str,
    text: &str,
) -> std::result::Result<lcoat_core::metadata::MetadataOnly, CliError> {
    lcoat_core::metadata::MetadataOnly::scan(text)
        .map_err(|e| fail(format!("{flag}: refusing to record this text: {e}")))
}

/// `[name]` then the flags: the first non-flag argument names the operation.
/// One argument quoted for bash and zsh, for the `next:` lines commands
/// print: plain words stay bare, anything else is single-quoted with `'`
/// written as `'\''`. Field run 1: placeholders like `<target>` in pasted
/// commands became shell redirects twice, so the hints carry real values.
pub fn shell_word(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/:=@%+-,".contains(c))
    {
        return s.to_owned();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Print a ready-to-run follow-up command.
pub fn next(ctx: &mut Ctx<'_>, words: &[&str]) {
    let line: Vec<String> = words.iter().map(|w| shell_word(w)).collect();
    ctx.line(&format!("next: lcoat {}", line.join(" ")));
}

pub fn first_name(args: &[String]) -> &str {
    args.first()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("")
}

/// `[name] [second]`: the first two non-flag arguments.
pub fn two_names(args: &[String]) -> (&str, &str) {
    let mut names = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str);
    (names.next().unwrap_or(""), names.next().unwrap_or(""))
}

/// The active operation (or the named one) as `Active`, for writers.
pub fn load_active(
    root: &LabRoot,
    name: &str,
) -> std::result::Result<lcoat_core::operation::Operation<lcoat_core::operation::Active>, CliError>
{
    Ok(lcoat_core::operation::Operation::load_named_or_active(root, name)?.into_active()?)
}

/// The named operation (or the active one) as `Closed`, for packet writers.
/// `op close` clears the active pointer, so after a close the packets are
/// usually written by name; without a name and without an active operation
/// the refusal says so instead of the generic "no active operation".
pub fn load_closed(
    root: &LabRoot,
    name: &str,
    verb: &str,
) -> std::result::Result<lcoat_core::operation::Operation<lcoat_core::operation::Closed>, CliError>
{
    use lcoat_core::operation::Operation;
    if name.is_empty() && Operation::active_slug(root).is_none() {
        return Err(fail(format!(
            "no active operation; packets are written for a closed operation, so name it: lcoat op {verb} <operation>"
        )));
    }
    Ok(Operation::load_named_or_active(root, name)?.into_closed()?)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::shell_word;

    /// Every quoted word must reach the program as exactly that one
    /// argument through a real bash: banners chosen by a scanned host end
    /// up in these lines.
    #[test]
    fn shell_word_round_trips_through_bash() {
        let cases = [
            "plain",
            "Open tcp/22 (ssh OpenSSH)",
            "it's",
            "$(touch /tmp/lcoat-pwned)",
            "`id`",
            "a\\b",
            "semi;colon && pipe | redirect > x < y",
            "quote ' and \" both",
            "glob * ? [x]",
            "~home #hash",
            "ünïcödé",
            "",
            "'",
            "''",
        ];
        for c in cases {
            let w = shell_word(c);
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("printf '%s' {w}"))
                .output()
                .unwrap();
            assert_eq!(String::from_utf8(out.stdout).unwrap(), c, "word {w:?}");
        }
        assert!(!std::path::Path::new("/tmp/lcoat-pwned").exists());
        assert_eq!(shell_word("ev_20261004T080003Z"), "ev_20261004T080003Z");
    }
}
