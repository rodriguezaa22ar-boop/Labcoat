//! `target add|show|list`.

use lcoat_core::operation::{NewTarget, add_target, list_targets, load_target};
use lcoat_format::ids::slugify;

use super::args::{Kind, Spec, parse};
use super::{CmdResult, Ctx, fail, metadata, mutable_root, root};

/// Dispatch `target <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("target add|show|list"));
    };
    match verb.as_str() {
        "add" => add(ctx, rest),
        "show" => show(ctx, rest),
        "list" => list(ctx, rest),
        other => Err(fail(format!("unknown target command: {other}"))),
    }
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

fn add(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const SPEC: Spec = Spec::new(
        "target add <name> <address> [--scope-status status] [--criticality level] [--tag tag]... [--owner owner] [--notes text]... [notes...]",
        2,
        None,
    )
    .flags(&[
        ("--scope-status", Kind::Value),
        ("--criticality", Kind::Value),
        ("--tag", Kind::Many),
        ("--owner", Kind::Value),
        ("--notes", Kind::Many),
    ]);
    let a = parse(&SPEC, args)?;
    let mut t = NewTarget {
        name: a.pos(0).to_owned(),
        address: a.pos(1).to_owned(),
        scope_status: a.value("--scope-status").unwrap_or("unknown").to_owned(),
        criticality: a.value("--criticality").unwrap_or("unknown").to_owned(),
        ..Default::default()
    };
    let mut tags: Vec<String> = Vec::new();
    for v in a.values("--tag") {
        if v.is_empty() {
            return Err(fail("target tag cannot be empty"));
        }
        if v.contains(char::is_whitespace) {
            return Err(fail(format!("target tags cannot contain whitespace: {v}")));
        }
        tags.push(metadata("--tag", v)?.as_str().to_owned());
    }
    if let Some(v) = a.value("--owner") {
        t.owner = metadata("--owner", v)?.as_str().to_owned();
    }
    // Notes in the order given: `--notes` values, then trailing words.
    let mut notes: Vec<String> = a.values("--notes").into_iter().map(str::to_owned).collect();
    notes.extend(a.rest(2).iter().cloned());
    metadata("name", &t.name)?;
    metadata("address", &t.address)?;
    t.tags = tags.join(" ");
    t.notes = metadata("notes", &notes.join(" "))?.as_str().to_owned();
    let root = mutable_root()?;
    let slug = add_target(&root, &t)?;
    ctx.line(&format!("created target: {slug}"));
    if t.scope_status == "in-scope" {
        super::next(ctx, &["op", "start", &format!("{slug}-check"), &slug]);
    } else {
        ctx.note(&format!(
            "scope status is '{}': nothing above Tier 0 will contact this target until it is added with --scope-status in-scope",
            t.scope_status
        ));
    }
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let a = parse(&Spec::new("target show <name>", 1, Some(1)), args)?;
    let root = root()?;
    let Some(t) = load_target(&root, a.pos(0))? else {
        return Err(fail(format!("unknown target: {}", slugify(a.pos(0)))));
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

fn list(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    parse(&Spec::new("target list", 0, Some(0)), args)?;
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
