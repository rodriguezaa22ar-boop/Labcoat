//! `finding add|resolve|accept|reopen|note|list`.

use lcoat_core::findings::{self, AcceptParams, AddParams, Finding, Update};
use lcoat_core::metadata::MetadataOnly;

use super::{
    CmdResult, Ctx, fail, load_active, load_read_only_op, metadata, mutable_root, need_args,
    option, root,
};

/// Dispatch `finding <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("finding add|resolve|accept|reopen|note|list"));
    };
    match verb.as_str() {
        "add" => add(ctx, rest),
        "resolve" => resolve(ctx, rest),
        "accept" => accept(ctx, rest),
        "reopen" => reopen(ctx, rest),
        "note" => note(ctx, rest),
        "list" => list(ctx, rest),
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

fn print_finding(ctx: &mut Ctx<'_>, f: &Finding) {
    ctx.kv("id", &f.id);
    ctx.kv("title", &f.title);
    ctx.kv("level", &f.level);
    ctx.kv("severity", &f.severity);
    ctx.kv("confidence", &f.confidence);
    ctx.kv("status", &f.status);
    ctx.kv("target", &f.target);
    if !f.evidence.is_empty() {
        ctx.kv("evidence", &f.evidence.join(" "));
    }
}

fn add(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "finding add <title> [--level observed|inferred|validated] [--severity severity] [--confidence confidence] [--status status] [--impact text] [--recommendation text] [--evidence id]";
    need_args(1, args, USAGE)?;
    let mut p = AddParams {
        title: Some(metadata("title", &args[0])?),
        ..Default::default()
    };
    let rest = &args[1..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            flag @ ("--target" | "--level" | "--severity" | "--confidence" | "--status"
            | "--source" | "--impact" | "--recommendation" | "--evidence") => {
                let v = option(rest, i, &format!("finding add <title> {flag} <value>"))?;
                match flag {
                    "--target" => p.target = Some(metadata(flag, v)?),
                    "--level" => p.level = v.to_owned(),
                    "--severity" => p.severity = v.to_owned(),
                    "--confidence" => p.confidence = v.to_owned(),
                    "--status" => p.status = v.to_owned(),
                    "--source" => p.source = v.to_owned(),
                    "--impact" => p.impact = Some(metadata(flag, v)?),
                    "--recommendation" => p.recommendation = Some(metadata(flag, v)?),
                    _ => p.evidence.push(v.to_owned()),
                }
                i += 2;
            }
            other => return Err(fail(format!("unknown finding add option: {other}"))),
        }
    }
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::add(&op, &p)?;
    ctx.ok("finding added");
    print_finding(ctx, &f);
    Ok(())
}

/// `<id> [--evidence id]... [--note text]`
fn id_evidence_note(
    args: &[String],
    usage: &str,
) -> Result<(String, Vec<String>, Option<MetadataOnly>), super::CliError> {
    need_args(1, args, usage)?;
    let id = args[0].clone();
    let mut evidence = Vec::new();
    let mut note = None;
    let rest = &args[1..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--evidence" => {
                evidence.push(option(rest, i, usage)?.to_owned());
                i += 2;
            }
            "--note" => {
                note = Some(metadata("--note", option(rest, i, usage)?)?);
                i += 2;
            }
            other => return Err(fail(format!("unknown option: {other}\nusage: {usage}"))),
        }
    }
    Ok((id, evidence, note))
}

fn resolve(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (id, evidence, note) = id_evidence_note(
        args,
        "finding resolve <id> [--evidence id]... [--note text]",
    )?;
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::resolve(&op, &id, &evidence, note)?;
    ctx.ok("finding resolved");
    print_finding(ctx, &f);
    Ok(())
}

fn reopen(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (id, evidence, note) = id_evidence_note(args, "finding reopen <id> [--note text]")?;
    if !evidence.is_empty() {
        return Err(fail(
            "finding reopen takes no --evidence; add it with 'finding resolve' or 'finding note'",
        ));
    }
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::reopen(&op, &id, note)?;
    ctx.ok("finding reopened");
    print_finding(ctx, &f);
    Ok(())
}

fn note(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    need_args(2, args, "finding note <id> <text>")?;
    let text = metadata("note", &args[1..].join(" "))?;
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::update(
        &op,
        &args[0],
        &Update {
            note: Some(text),
            ..Default::default()
        },
    )?;
    ctx.ok("finding updated");
    print_finding(ctx, &f);
    Ok(())
}

fn accept(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "finding accept <id> --reason text [--owner owner] [--expires YYYY-MM-DD|timestamp|Nh|Nd] [--evidence id]...";
    need_args(1, args, USAGE)?;
    let id = args[0].clone();
    let mut reason = None;
    let mut owner = None;
    let mut expires = None;
    let mut evidence = Vec::new();
    let rest = &args[1..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reason" => reason = Some(metadata("--reason", option(rest, i, USAGE)?)?),
            "--owner" => owner = Some(metadata("--owner", option(rest, i, USAGE)?)?),
            // Same forms as approvals (YYYY-MM-DD, timestamp, Nh, Nd),
            // stored as the instant they name.
            "--expires" | "--until" => {
                expires = Some(super::approval::parse_expiry(option(rest, i, USAGE)?)?.timestamp())
            }
            "--evidence" => evidence.push(option(rest, i, USAGE)?.to_owned()),
            other => return Err(fail(format!("unknown finding accept option: {other}"))),
        }
        i += 2;
    }
    let Some(reason) = reason else {
        return Err(fail("acceptance reason is required"));
    };
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::accept(
        &op,
        &id,
        &AcceptParams {
            reason: reason.clone(),
            owner: owner.clone(),
            expires: expires.clone(),
            evidence,
        },
    )?;
    ctx.ok("finding accepted");
    ctx.kv("id", &f.id);
    ctx.line("status: accepted");
    ctx.kv("reason", reason.as_str());
    ctx.kv("accepted_by", &f.accepted_by);
    ctx.kv("accepted_at", &f.accepted_at);
    if let Some(o) = owner {
        ctx.kv("owner", o.as_str());
    }
    if let Some(e) = expires {
        ctx.kv("expires", &e);
    }
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let root = root()?;
    let op = load_read_only_op(&root, args, "finding list [operation]")?;
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
