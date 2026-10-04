//! `scope status`.

use lcoat_core::root::{LabRoot, TOOL_NAME};
use lcoat_core::scope::snapshot_file;
use lcoat_core::tier::Tier;

use super::{CmdResult, Ctx, fail, load_active, load_read_only_op, mutable_root, need_args, root};

/// Dispatch `scope <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail(
            "scope status [operation] | scope check <capability> <target>",
        ));
    };
    match verb.as_str() {
        "status" => status(ctx, &root()?, rest),
        "check" => check(ctx, rest),
        other => Err(fail(format!("unknown scope command: {other}"))),
    }
}

/// `scope check <capability> <target>`: a manual preflight, recorded in
/// the ledger like any other, against the active operation.
fn check(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    need_args(2, args, "scope check <capability> <target>")?;
    let Some(capability) = Tier::from_capability(&args[0]) else {
        return Err(fail(format!(
            "unknown capability: {} (read-only, passive-recon, active-recon, safe-validation, intrusive-validation, destructive)",
            args[0]
        )));
    };
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    op.preflight(capability, TOOL_NAME, &args[1], "manual scope check")?
        .into_result()?;
    ctx.ok("scope allowed");
    ctx.kv("capability", capability.capability());
    ctx.kv("tier", &(capability as u8).to_string());
    ctx.kv("target", &args[1]);
    Ok(())
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

fn status(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let op = load_read_only_op(root, args, "scope status [operation]")?;
    let snap = op.snapshot()?;
    ctx.heading("ScopeGuard");
    ctx.rule();
    ctx.kv("Operation", &op.name);
    ctx.kv("Profile", &snap.profile);
    ctx.kv("Target", &snap.target);
    if !snap.target_address.is_empty() && snap.target_address != snap.target {
        ctx.kv("Address", &snap.target_address);
    }
    ctx.kv("Target Scope", or_unknown(&snap.target_scope_status));
    ctx.kv("Target Criticality", or_unknown(&snap.target_criticality));
    if !snap.target_owner.is_empty() {
        ctx.kv("Target Owner", &snap.target_owner);
    }
    if !snap.target_tags.is_empty() {
        ctx.kv("Target Tags", &snap.target_tags);
    }
    ctx.kv("Allowed", &snap.allowed);
    ctx.kv("Blocked", &snap.blocked);
    let rec = if snap.recommended_workflows.is_empty() {
        "none"
    } else {
        &snap.recommended_workflows
    };
    ctx.kv("Recommended", rec);
    ctx.kv("Snapshot", &snapshot_file(&op.dir).display().to_string());
    Ok(())
}
