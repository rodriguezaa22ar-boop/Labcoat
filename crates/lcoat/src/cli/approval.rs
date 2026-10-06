//! `approval grant|list|revoke`.

use lcoat_core::approval::{self, GrantParams};
use lcoat_core::operation::Operation;
use lcoat_core::tier::Tier;
use lcoat_format::clock::Utc;

use super::args::{Kind, Spec, parse};
use super::{CmdResult, Ctx, fail, load_active, metadata, mutable_root, root};

/// Dispatch `approval <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("approval grant|list|revoke"));
    };
    match verb.as_str() {
        "grant" => grant(ctx, rest),
        "list" => list(ctx, rest),
        "revoke" => revoke(ctx, rest),
        other => Err(fail(format!("unknown approval command: {other}"))),
    }
}

fn tier_arg(name: &str) -> Result<Tier, super::CliError> {
    Tier::from_capability(name).ok_or_else(|| {
        fail(format!("unknown capability: {name} (read-only, passive-recon, active-recon, safe-validation, intrusive-validation, destructive)"))
    })
}

/// `YYYY-MM-DD` (end of that day), a full timestamp, or `Nh`/`Nd` from now.
pub fn parse_expiry(v: &str) -> Result<Utc, super::CliError> {
    lcoat_format::clock::parse_expiry(v, Utc::now()).ok_or_else(|| {
        fail(format!(
            "--expires must be YYYY-MM-DD, YYYY-MM-DDTHH:MM:SSZ, <N>h or <N>d (up to year 9999); got: {v}"
        ))
    })
}

fn grant(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const SPEC: Spec = Spec::new(
        "approval grant <capability> --reason text --expires <YYYY-MM-DD|timestamp|Nh|Nd>",
        1,
        Some(1),
    )
    .flags(&[("--reason", Kind::Value), ("--expires", Kind::Value)]);
    let a = parse(&SPEC, args)?;
    let capability = tier_arg(a.pos(0))?;
    let reason = a.value("--reason").unwrap_or("").to_owned();
    let expires = a.value("--expires").map(parse_expiry).transpose()?;
    if reason.trim().is_empty() {
        return Err(fail("approval reason is required (--reason)"));
    }
    let Some(expires_at) = expires else {
        return Err(fail(
            "approval expiry is required (--expires); open-ended grants are not recorded",
        ));
    };
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let g = approval::grant(
        &op,
        &GrantParams {
            capability,
            reason: metadata("--reason", &reason)?,
            expires_at,
        },
    )?;
    ctx.ok("approval recorded");
    ctx.kv("capability", &g.capability);
    ctx.kv("tier", &g.tier);
    ctx.kv("target", &g.target);
    ctx.kv("approved_by", &g.approved_by);
    ctx.kv("expires_at", &g.expires_at);
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let a = parse(&Spec::new("approval list [operation]", 0, Some(1)), args)?;
    let root = root()?;
    let op = Operation::load_named_or_active(&root, a.pos(0))?;
    let file = approval::file(&op.dir);
    ctx.heading("Approvals");
    ctx.rule();
    ctx.kv("Operation", &op.name);
    ctx.kv("Target", &op.target);
    ctx.kv("Store", &file.display().to_string());
    ctx.rule();
    let records = approval::list(&op.dir)?;
    if records.is_empty() {
        ctx.note("no approvals recorded yet");
        return Ok(());
    }
    let q = |v: &str| {
        if v.is_empty() {
            "?".to_owned()
        } else {
            v.to_owned()
        }
    };
    for g in &records {
        let mut line = format!(
            "{:<20} {:<18} {:<4} {:<10} {:<12} {}",
            q(&g.ts),
            q(&g.capability),
            q(&g.tier),
            q(&g.status),
            q(&g.approved_by),
            g.reason
        );
        if !g.expires_at.is_empty() {
            line.push_str(&format!(" expires_at={}", g.expires_at));
        }
        ctx.line(&line);
    }
    Ok(())
}

fn revoke(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const SPEC: Spec = Spec::new("approval revoke <capability> --reason text", 1, Some(1))
        .flags(&[("--reason", Kind::Value)]);
    let a = parse(&SPEC, args)?;
    let capability = tier_arg(a.pos(0))?;
    let reason = a.value("--reason").unwrap_or("").to_owned();
    if reason.trim().is_empty() {
        return Err(fail("revocation reason is required (--reason)"));
    }
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let g = approval::revoke(&op, capability, &metadata("--reason", &reason)?)?;
    ctx.ok("approval revoked");
    ctx.kv("capability", &g.capability);
    ctx.kv("target", &g.target);
    Ok(())
}
