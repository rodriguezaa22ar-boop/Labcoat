//! `finding list`.

use lcoat_core::findings::{self, Finding};
use lcoat_core::root::LabRoot;

use super::{CmdResult, Ctx, fail, load_read_only_op};

/// Dispatch `finding <verb>`.
pub fn run(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("finding list [operation]"));
    };
    match verb.as_str() {
        "list" => list(ctx, root, rest),
        "add" => Err(fail(
            "finding add is not in this build yet (phase 2 adds the write side); use Lab Coat Lite (lcoat 0.1.4) for it meanwhile",
        )),
        other => Err(fail(format!("unknown finding command: {other}"))),
    }
}

/// The finding table row the shell build prints.
pub fn row(f: &Finding) -> String {
    let ev = if f.evidence.is_empty() {
        "-".to_owned()
    } else {
        f.evidence.join(",")
    };
    format!(
        "{:<24} {:<10} {:<8} {:<10} {:<32} {}",
        f.id_or(),
        f.level_or(),
        f.severity_or(),
        f.status_or(),
        f.title_or(),
        ev
    )
}

fn list(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let op = load_read_only_op(root, args, "finding list [operation]")?;
    let rows = findings::rows(&op.dir, &op.target, 1_000_000)?;
    if rows.is_empty() {
        ctx.note("no findings recorded yet");
        return Ok(());
    }
    for f in &rows {
        ctx.line(&row(f));
    }
    Ok(())
}
