//! `receipt create|verify|replay`.

use lcoat_core::receipt::{self, CreateParams};
use lcoat_format::canonical::compact;
use lcoat_format::json::Value;

use super::{CmdResult, Ctx, fail, need_args, option};

/// Dispatch `receipt <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("receipt create|verify|replay"));
    };
    match verb.as_str() {
        "verify" => verify(ctx, rest),
        "replay" => replay(ctx, rest),
        "create" => create(ctx, rest),
        other => Err(fail(format!("unknown receipt command: {other}"))),
    }
}

fn verify(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    need_args(1, args, "receipt verify <receipt-file|-> [--json]")?;
    let mut json = false;
    for a in &args[1..] {
        if a == "--json" {
            json = true;
        } else {
            return Err(fail(format!("unknown receipt verify option: {a}")));
        }
    }
    let res = receipt::verify_file(&args[0])?;
    if json {
        let mut bytes = compact(&Value::Object(res.to_json()));
        bytes.push(b'\n');
        ctx.raw(&bytes);
    } else {
        ctx.line("receipt: ok");
        ctx.line("This receipt validates as a metadata-only proof record.");
        ctx.line("It does not prove external artifact availability, human intent, legal compliance, or artifact correctness.");
    }
    Ok(())
}

fn replay(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let mut json = false;
    let mut inputs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--" => {
                inputs.extend(args[i + 1..].iter().cloned());
                break;
            }
            a if a.len() > 1 && a.starts_with('-') => {
                return Err(fail(format!("unknown receipt replay option: {a}")));
            }
            a => inputs.push(a.to_owned()),
        }
        i += 1;
    }
    let res = receipt::replay(&inputs)?;
    if json {
        let mut bytes = compact(&Value::Object(res.to_json()));
        bytes.push(b'\n');
        ctx.raw(&bytes);
    } else {
        ctx.line("receipt replay: ok");
        ctx.line(&format!("receipts: {}", res.receipt_count));
        ctx.line("ledger binding: ok prev_hash -> event_hash");
        ctx.line(&format!(
            "chain_head_event_hash: {}",
            res.chain_head_event_hash
        ));
        ctx.line(&format!(
            "chain_head_receipt_hash: {}",
            res.chain_head_receipt_hash
        ));
        ctx.line("metadata-only boundary: ok");
        ctx.line("This replay verifies receipt hashes and provided-order prev_hash linkage only.");
        ctx.line("It does not prove external artifact availability, human intent, legal compliance, artifact correctness, authorization, or production readiness.");
    }
    Ok(())
}

fn create(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let mut p = CreateParams::default();
    let mut out_file = String::new();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--receipt-id" | "--timestamp" | "--action" | "--actor" | "--subject-type"
            | "--subject" | "--prev-hash" | "--evidence-ref" | "--artifact-ref"
            | "--approval-ref" | "--limitation" | "--out" => {
                let v = option(args, i, &format!("receipt create {flag} <value>"))?.to_owned();
                match flag {
                    "--receipt-id" => p.receipt_id = v,
                    "--timestamp" => p.timestamp = v,
                    "--action" => p.action = v,
                    "--actor" => p.actor = v,
                    "--subject-type" => p.subject_type = v,
                    "--subject" => p.subject_ref = v,
                    "--prev-hash" => p.prev_hash = v,
                    "--evidence-ref" => p.evidence_refs.push(v),
                    "--artifact-ref" => p.artifact_refs.push(v),
                    "--approval-ref" => p.approval_refs.push(v),
                    "--limitation" => p.limitations.push(v),
                    _ => out_file = v,
                }
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            other => return Err(fail(format!("unknown receipt create option: {other}"))),
        }
    }
    let body = receipt::create(&p)?;
    if out_file.is_empty() {
        ctx.raw(&body);
        return Ok(());
    }
    lcoat_format::envfile::write_private(std::path::Path::new(&out_file), &body)?;
    if json {
        ctx.raw(&body);
    } else {
        ctx.kv("receipt", &out_file);
    }
    Ok(())
}
