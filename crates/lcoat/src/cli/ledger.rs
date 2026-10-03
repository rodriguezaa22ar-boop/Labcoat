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
        other => Err(fail(format!("unknown ledger command: {other}"))),
    }
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
        let path = std::env::temp_dir().join(format!(
            "lcoat-ledger-{}-{}",
            std::process::id(),
            clock::Utc::now().unix()
        ));
        lcoat_format::envfile::write_private(&path, &buf)?;
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
