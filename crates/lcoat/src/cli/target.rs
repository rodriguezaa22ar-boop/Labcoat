//! `target add|show|list`.

use lcoat_core::operation::{NewTarget, add_target, list_targets, load_target};
use lcoat_format::ids::slugify;

use super::{CmdResult, Ctx, fail, metadata, mutable_root, need_args, option, root};

/// Dispatch `target <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("target add|show|list"));
    };
    match verb.as_str() {
        "add" => add(ctx, rest),
        "show" => show(ctx, rest),
        "list" => list(ctx),
        other => Err(fail(format!("unknown target command: {other}"))),
    }
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

fn add(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "target add <name> <address> [--scope-status status] [--criticality level] [--tag tag] [--owner owner] [notes...]";
    need_args(2, args, USAGE)?;
    let mut t = NewTarget {
        name: args[0].clone(),
        address: args[1].clone(),
        scope_status: "unknown".into(),
        criticality: "unknown".into(),
        ..Default::default()
    };
    let mut tags: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let rest = &args[2..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            flag @ ("--scope-status" | "--criticality" | "--tag" | "--owner" | "--notes") => {
                let v = option(
                    rest,
                    i,
                    &format!("target add <name> <address> {flag} <value>"),
                )?
                .to_owned();
                match flag {
                    "--scope-status" => t.scope_status = v,
                    "--criticality" => t.criticality = v,
                    "--tag" => {
                        if v.is_empty() {
                            return Err(fail("target tag cannot be empty"));
                        }
                        if v.contains(char::is_whitespace) {
                            return Err(fail(format!(
                                "target tags cannot contain whitespace: {v}"
                            )));
                        }
                        tags.push(metadata("--tag", &v)?.as_str().to_owned());
                    }
                    "--owner" => t.owner = metadata("--owner", &v)?.as_str().to_owned(),
                    _ => notes.push(v),
                }
                i += 2;
            }
            "--" => {
                notes.extend(rest[i + 1..].iter().cloned());
                break;
            }
            a if a.starts_with("--") => {
                return Err(fail(format!("unknown target add option: {a}")));
            }
            a => {
                notes.push(a.to_owned());
                i += 1;
            }
        }
    }
    metadata("name", &t.name)?;
    metadata("address", &t.address)?;
    t.tags = tags.join(" ");
    t.notes = metadata("notes", &notes.join(" "))?.as_str().to_owned();
    let root = mutable_root()?;
    let slug = add_target(&root, &t)?;
    ctx.line(&format!("created target: {slug}"));
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    need_args(1, args, "target show <name>")?;
    let root = root()?;
    let Some(t) = load_target(&root, &args[0])? else {
        return Err(fail(format!("unknown target: {}", slugify(&args[0]))));
    };
    ctx.kv("Target", &t.name);
    ctx.kv("Address", &t.address);
    ctx.kv("Scope Status", or_unknown(&t.scope_status));
    ctx.kv("Criticality", or_unknown(&t.criticality));
    if !t.tags.is_empty() {
        ctx.kv("Tags", &t.tags);
    }
    if !t.owner.is_empty() {
        ctx.kv("Owner", &t.owner);
    }
    if !t.notes.is_empty() {
        ctx.kv("Notes", &t.notes);
    }
    ctx.kv("Created", &t.created_at);
    ctx.kv("Record", &t.file.display().to_string());
    Ok(())
}

fn list(ctx: &mut Ctx<'_>) -> CmdResult {
    let root = root()?;
    ctx.line(&format!(
        "{:<24} {:<24} {:<12} {:<10} {:<18} {}",
        "TARGET", "ADDRESS", "SCOPE", "CRITICAL", "TAGS", "CREATED_AT"
    ));
    for t in list_targets(&root)? {
        ctx.line(&format!(
            "{:<24} {:<24} {:<12} {:<10} {:<18} {}",
            t.name,
            t.address,
            or_unknown(&t.scope_status),
            or_unknown(&t.criticality),
            t.tags,
            t.created_at
        ));
    }
    Ok(())
}
