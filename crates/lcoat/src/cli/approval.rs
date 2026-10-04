//! `approval grant|list|revoke`.

use lcoat_core::approval::{self, GrantParams};
use lcoat_core::operation::Operation;
use lcoat_core::tier::Tier;
use lcoat_format::clock::Utc;

use super::{
    CmdResult, Ctx, fail, first_name, load_active, metadata, mutable_root, need_args, option, root,
};

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
fn parse_expiry(v: &str) -> Result<Utc, super::CliError> {
    if let Some(t) = Utc::parse(v) {
        return Ok(t);
    }
    if v.len() == 10
        && let Some(t) = Utc::parse(&format!("{v}T23:59:59Z"))
    {
        return Ok(t);
    }
    if let Some(num) = v.strip_suffix('h').or_else(|| v.strip_suffix('d'))
        && let Ok(n) = num.parse::<i64>()
        && n > 0
    {
        let secs = if v.ends_with('h') {
            n * 3600
        } else {
            n * 86_400
        };
        return Ok(Utc::from_unix(Utc::now().unix() + secs));
    }
    Err(fail(format!(
        "--expires must be YYYY-MM-DD, YYYY-MM-DDTHH:MM:SSZ, <N>h or <N>d; got: {v}"
    )))
}

fn grant(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str =
        "approval grant <capability> --reason text --expires <YYYY-MM-DD|timestamp|Nh|Nd>";
    need_args(1, args, USAGE)?;
    let capability = tier_arg(&args[0])?;
    let mut reason = String::new();
    let mut expires: Option<Utc> = None;
    let rest = &args[1..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reason" => {
                reason = option(rest, i, USAGE)?.to_owned();
                i += 2;
            }
            "--expires" => {
                expires = Some(parse_expiry(option(rest, i, USAGE)?)?);
                i += 2;
            }
            other => return Err(fail(format!("unknown approval grant option: {other}"))),
        }
    }
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
    let root = root()?;
    let op = Operation::load_named_or_active(&root, first_name(args))?;
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
    const USAGE: &str = "approval revoke <capability> --reason text";
    need_args(1, args, USAGE)?;
    let capability = tier_arg(&args[0])?;
    let mut reason = String::new();
    let rest = &args[1..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reason" => {
                reason = option(rest, i, USAGE)?.to_owned();
                i += 2;
            }
            other => return Err(fail(format!("unknown approval revoke option: {other}"))),
        }
    }
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
