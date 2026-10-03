//! `scope status`.

use lcoat_core::root::LabRoot;
use lcoat_core::scope::snapshot_file;

use super::{CmdResult, Ctx, fail, load_read_only_op};

/// Dispatch `scope <verb>`.
pub fn run(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("scope status [operation]"));
    };
    match verb.as_str() {
        "status" => status(ctx, root, rest),
        "check" => Err(fail(
            "scope check is not in this build yet (it records a ledger decision; phase 2 adds the write side)",
        )),
        other => Err(fail(format!("unknown scope command: {other}"))),
    }
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
