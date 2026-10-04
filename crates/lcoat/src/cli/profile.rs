//! `profile list|show`.

use lcoat_core::scope::{self, DEFAULT_SUMMARY, Snapshot, load_profile};

use super::{CmdResult, Ctx, fail, need_args, root};

/// Dispatch `profile <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("profile list|show <name>"));
    };
    match verb.as_str() {
        "list" => list(ctx),
        "show" => show(ctx, rest),
        other => Err(fail(format!("unknown profile command: {other}"))),
    }
}

fn list(ctx: &mut Ctx<'_>) -> CmdResult {
    let root = root()?;
    ctx.line(&format!("{:<24} {}", "PROFILE", "SUMMARY"));
    ctx.line(&format!("{:<24} {}", "default", DEFAULT_SUMMARY));
    for f in scope::list_profile_files(&root.profiles_dir)? {
        let name = f
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let p = load_profile(&root.profiles_dir, &name)?;
        ctx.line(&format!("{:<24} {}", p.name, p.summary));
    }
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    need_args(1, args, "profile show <name>")?;
    let root = root()?;
    let p = load_profile(&root.profiles_dir, &args[0])?;
    ctx.heading("Atlas Profile");
    ctx.rule();
    ctx.kv("Profile", &p.name);
    ctx.kv("Summary", &p.summary);
    ctx.kv("Allowed", &p.allowed_capabilities);
    ctx.kv("Blocked", &p.blocked_capabilities);
    ctx.rule();
    ctx.heading("Scope");
    ctx.line(&p.scope_text);
    ctx.rule();
    ctx.heading("Allowed Actions");
    let snap = Snapshot {
        allowed_actions: p.allowed_actions.clone(),
        out_of_scope_actions: p.out_of_scope_actions.clone(),
        ..Snapshot::empty()
    };
    for l in snap.allowed_action_lines() {
        ctx.line(&l);
    }
    ctx.rule();
    ctx.heading("Explicitly Out Of Scope");
    for l in snap.out_of_scope_lines() {
        ctx.line(&l);
    }
    ctx.rule();
    ctx.heading("Recommended Workflow");
    let lines = scope::pipe_lines(&p.recommended_workflows);
    if lines.is_empty() {
        ctx.note("no profile-specific workflow configured");
    } else {
        for l in lines {
            ctx.line(&l);
        }
    }
    Ok(())
}
