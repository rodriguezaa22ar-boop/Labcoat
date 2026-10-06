//! `ledger verify|checkpoint`.

use std::path::{Path, PathBuf};

use lcoat_core::ledger;
use lcoat_format::canonical::compact;
use lcoat_format::clock;
use lcoat_format::hash::Sha256Hex;
use lcoat_format::json::{Object, Value};

use super::{CliError, CmdResult, Ctx, fail};

/// Dispatch `ledger <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("ledger verify|checkpoint <ledger-file|-> [--json]"));
    };
    match verb.as_str() {
        "verify" => verify(ctx, rest),
        "checkpoint" => checkpoint(ctx, rest),
        "chain-verify" => chain_verify(ctx, rest),
        other => Err(fail(format!("unknown ledger command: {other}"))),
    }
}

/// `ledger chain-verify [operation] [--json]`: walk the format 1.1 event
/// chain of an operation's ledger and name the first broken event. A v1
/// ledger is reported as `unchained`, a Lite-started one as `partial`.
fn chain_verify(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    use lcoat_core::chain::{self, ChainStatus};
    let json = args.iter().any(|a| a == "--json");
    let names: Vec<String> = args.iter().filter(|a| *a != "--json").cloned().collect();
    let root = super::root()?;
    let op =
        lcoat_core::operation::Operation::load_named_or_active(&root, super::first_name(&names))?;
    // A missing ledger reads as zero events, which would print as an
    // unchained v1 ledger and exit 0; every operation has `op.started`.
    if !lcoat_core::root::file_exists(&op.ledger_file()) {
        return Err(fail(format!(
            "operation ledger is missing: {}",
            op.ledger_file().display()
        )));
    }
    let objects = ledger::read_objects(&op.ledger_file())?;
    let status = chain::verify(&objects);
    let (word, ok) = match &status {
        ChainStatus::Verified => ("verified", true),
        ChainStatus::Unchained => ("unchained", true),
        ChainStatus::Partial { .. } => ("partial", true),
        ChainStatus::Broken { .. } => ("broken", false),
    };
    if json {
        let mut o = Object::new();
        o.insert("schema_version", s("lcoat.ledger_chain_verify.v1"));
        o.insert("operation", s(&op.slug));
        o.insert("ledger", s(&op.ledger_file().display().to_string()));
        o.insert("events", Value::Number(objects.len().to_string()));
        o.insert("status", s(word));
        o.insert("detail", s(&super::op::chain_word(&status)));
        if let ChainStatus::Broken { index, reason } = &status {
            o.insert("broken_event", Value::Number((index + 1).to_string()));
            o.insert("reason", s(reason));
        }
        if let ChainStatus::Partial { first_chained } = &status {
            o.insert(
                "first_chained_event",
                Value::Number((first_chained + 1).to_string()),
            );
        }
        emit(ctx, o);
    } else {
        ctx.heading("Ledger Chain Verification");
        ctx.rule();
        ctx.kv("Operation", &op.name);
        ctx.kv("Ledger", &op.ledger_file().display().to_string());
        ctx.kv("Events", &objects.len().to_string());
        ctx.kv("Chain Status", &super::op::chain_word(&status));
        if let ChainStatus::Unchained | ChainStatus::Partial { .. } = status {
            ctx.note("events without chain fields were written by the shell build or Lite; they are covered by the whole-file hash the packets anchor");
        }
    }
    if ok { Ok(()) } else { Err(CliError::Exit(1)) }
}

/// The ledger file to read: a path, or stdin spooled to a temp file.
struct Input {
    path: PathBuf,
    temp: bool,
}

impl Drop for Input {
    fn drop(&mut self) {
        if self.temp {
            let _ = std::fs::remove_file(&self.path);
            if let Some(dir) = self.path.parent() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
}

fn input(args: &[String], usage: &str) -> std::result::Result<(Input, bool), CliError> {
    let Some(first) = args.first() else {
        return Err(fail(usage));
    };
    let mut json = false;
    for a in &args[1..] {
        if a == "--json" {
            json = true;
        } else {
            return Err(fail(format!("unknown ledger option: {a}")));
        }
    }
    if first == "-" {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
        // A fresh private directory, not a guessable name in /tmp.
        let dir = lcoat_format::fsutil::private_temp_dir("lcoat-ledger")?;
        let path = dir.join("ledger.ndjson");
        if let Err(e) = lcoat_format::envfile::write_private(&path, &buf) {
            let _ = std::fs::remove_dir(&dir);
            return Err(e.into());
        }
        return Ok((Input { path, temp: true }, json));
    }
    if !lcoat_core::root::file_exists(Path::new(first)) {
        return Err(fail(format!("missing ledger: {first}")));
    }
    Ok((
        Input {
            path: PathBuf::from(first),
            temp: false,
        },
        json,
    ))
}

fn emit(ctx: &mut Ctx<'_>, obj: Object) {
    let mut bytes = compact(&Value::Object(obj));
    bytes.push(b'\n');
    ctx.raw(&bytes);
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn verify(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (input, json) = input(args, "ledger verify <ledger-file|-> [--json]")?;
    let res = ledger::verify_operation_ledger(&input.path)?;
    if json {
        let mut o = Object::new();
        o.insert("schema_version", s("atlas.ledger_verify.v1"));
        o.insert("status", s("ok"));
        o.insert("ledger_type", s("atlas.operation_ledger.v1"));
        o.insert("event_count", Value::Number(res.event_count.to_string()));
        o.insert("head_event_hash", s(res.head_event_hash.as_str()));
        emit(ctx, o);
    } else {
        ctx.line("ledger: ok");
    }
    Ok(())
}

fn checkpoint(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (input, json) = input(args, "ledger checkpoint <ledger-file|-> [--json]")?;
    let res = ledger::verify_operation_ledger(&input.path)?;
    let file_sha = Sha256Hex::of_file(&input.path)?;
    if json {
        let mut o = Object::new();
        o.insert("schema_version", s("atlas.checkpoint.v1"));
        o.insert(
            "checkpoint_id",
            s(&format!("checkpoint_{}", &file_sha.as_str()[..12])),
        );
        o.insert("timestamp", s(&clock::timestamp()));
        o.insert("metadata_only", Value::Bool(true));
        o.insert("ledger_ref", s(&args[0]));
        o.insert("event_count", Value::Number(res.event_count.to_string()));
        o.insert("head_event_hash", s(res.head_event_hash.as_str()));
        o.insert("ledger_hash", s(file_sha.as_str()));
        emit(ctx, o);
    } else {
        ctx.line("ledger checkpoint: ok");
        ctx.line(&format!("events: {}", res.event_count));
        ctx.line(&format!("head_event_hash: {}", res.head_event_hash));
        ctx.line(&format!("ledger_hash: {file_sha}"));
    }
    Ok(())
}
