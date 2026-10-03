//! `evidence list|verify`.

use lcoat_core::evidence;
use lcoat_core::root::LabRoot;

use super::{CliError, CmdResult, Ctx, fail, load_op, load_read_only_op};

/// Dispatch `evidence <verb>`.
pub fn run(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("evidence list|verify [operation]"));
    };
    match verb.as_str() {
        "list" => list(ctx, root, rest),
        "verify" => verify(ctx, root, rest),
        "add" => Err(fail(
            "evidence add is not in this build yet (phase 2 adds the write side); use Lab Coat Lite (lcoat 0.1.4) for it meanwhile",
        )),
        other => Err(fail(format!("unknown evidence command: {other}"))),
    }
}

/// The evidence table row the shell build prints (`op status`, `evidence list`).
pub fn row(r: &evidence::Record) -> String {
    let sha = if r.sha256.len() > 20 {
        &r.sha256[..20]
    } else {
        &r.sha256
    };
    format!(
        "{:<22} {:<16} {:<14} {:<8} {:<20} {}",
        r.id, r.kind, r.classification, r.redacted, sha, r.path
    )
}

fn list(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let op = load_read_only_op(root, args, "evidence list [operation]")?;
    let rows = evidence::rows(&op.dir, &op.target, 1_000_000)?;
    if rows.is_empty() {
        ctx.note("no evidence recorded yet");
        return Ok(());
    }
    for r in &rows {
        ctx.line(&row(r));
    }
    Ok(())
}

fn verify(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let op = load_op(root, args)?;
    let (checks, problems) = evidence::verify_artifacts(&op.dir)?;
    ctx.heading("Evidence Artifact Verification");
    ctx.rule();
    ctx.kv("Operation", &op.name);
    for c in &checks {
        let mut detail = c.path.clone();
        if c.status == "changed" {
            detail.push_str(&format!(
                " expected_sha={} actual_sha={}",
                c.expected, c.actual
            ));
        }
        ctx.line(&format!("{:<26} {:<9} {detail}", c.id, c.status));
    }
    let status = if problems > 0 {
        "attention-required"
    } else {
        "verified"
    };
    ctx.kv("Artifacts Checked", &checks.len().to_string());
    ctx.kv("Artifact Problems", &problems.to_string());
    ctx.kv("Verification Status", status);
    if problems > 0 {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}
