//! `receipt create|verify|replay`.

use lcoat_core::receipt::{self, CreateParams};
use lcoat_format::canonical::compact;
use lcoat_format::json::Value;

use super::args::{Kind, Spec, parse};
use super::{CmdResult, Ctx, fail};

const JSON: &[(&str, Kind)] = &[("--json", Kind::Switch)];

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
    let a = parse(
        &Spec::new("receipt verify <receipt-file|-> [--json]", 1, Some(1)).flags(JSON),
        args,
    )?;
    let json = a.has("--json");
    let res = receipt::verify_file(a.pos(0))?;
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
    let a = parse(
        &Spec::new(
            "receipt replay <receipt-file> [receipt-file ...] [--json]",
            0,
            None,
        )
        .flags(JSON),
        args,
    )?;
    let json = a.has("--json");
    let inputs = a.pos.clone();
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
    const SPEC: Spec = Spec::new(
        "receipt create --action action --actor actor --subject-type type --subject ref [--prev-hash sha256] [--evidence-ref ref] [--artifact-ref path=sha256] [--approval-ref ref] [--limitation text] [--out receipt.json] [--json]",
        0,
        Some(0),
    )
    .flags(&[
        ("--receipt-id", Kind::Value),
        ("--timestamp", Kind::Value),
        ("--action", Kind::Value),
        ("--actor", Kind::Value),
        ("--subject-type", Kind::Value),
        ("--subject", Kind::Value),
        ("--prev-hash", Kind::Value),
        ("--evidence-ref", Kind::Many),
        ("--artifact-ref", Kind::Many),
        ("--approval-ref", Kind::Many),
        ("--limitation", Kind::Many),
        ("--out", Kind::Value),
        ("--json", Kind::Switch),
    ]);
    let a = parse(&SPEC, args)?;
    let one = |f: &str| a.value(f).unwrap_or("").to_owned();
    let many = |f: &str| a.values(f).into_iter().map(str::to_owned).collect();
    let p = CreateParams {
        receipt_id: one("--receipt-id"),
        timestamp: one("--timestamp"),
        action: one("--action"),
        actor: one("--actor"),
        subject_type: one("--subject-type"),
        subject_ref: one("--subject"),
        prev_hash: one("--prev-hash"),
        evidence_refs: many("--evidence-ref"),
        artifact_refs: many("--artifact-ref"),
        approval_refs: many("--approval-ref"),
        limitations: many("--limitation"),
    };
    let out_file = one("--out");
    let json = a.has("--json");
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
