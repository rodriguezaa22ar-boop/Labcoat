//! `finding add|resolve|accept|reopen|note|list|review-queue|review-packet|review-verify`.

use lcoat_core::findings::{self, AcceptParams, AddParams, Finding, Update};
use lcoat_core::metadata::MetadataOnly;
use lcoat_core::operation::Operation;
use lcoat_core::packet::review;

use super::{
    CmdResult, Ctx, fail, load_active, load_read_only_op, metadata, mutable_root, need_args,
    option, root,
};

/// Dispatch `finding <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail(
            "finding add|resolve|accept|reopen|note|list|review-queue|review-packet|review-verify",
        ));
    };
    match verb.as_str() {
        "add" => add(ctx, rest),
        "resolve" => resolve(ctx, rest),
        "accept" => accept(ctx, rest),
        "reopen" => reopen(ctx, rest),
        "note" => note(ctx, rest),
        "list" => list(ctx, rest),
        "review-queue" => review_queue(ctx, rest),
        "review-packet" => review_packet(ctx, rest),
        "review-verify" => review_verify(ctx, rest),
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
    super::next(
        ctx,
        &["finding", "resolve", &f.id, "--note", "what fixed it"],
    );
    super::next(
        ctx,
        &[
            "finding",
            "accept",
            &f.id,
            "--reason",
            "why it is acceptable",
            "--expires",
            "90d",
        ],
    );
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
    // The shell's `finding resolve` is an update and says so.
    ctx.ok("finding updated");
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
            // Same forms as approvals (YYYY-MM-DD, timestamp, Nh, Nd). A
            // plain date is stored as typed, as the shell build stores it
            // (core reads it as the end of that day); the other forms are
            // stored as the instant they name.
            "--expires" | "--until" => {
                let v = option(rest, i, USAGE)?;
                let instant = super::approval::parse_expiry(v)?;
                let plain_date = v.len() == 10 && instant.timestamp().starts_with(v);
                expires = Some(if plain_date {
                    v.to_owned()
                } else {
                    instant.timestamp()
                });
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

// --- accepted-risk review ------------------------------------------------------

/// `[--op operation] [--within days] [name]`: the operation (active unless
/// named; a closed one can be reviewed without resuming it), the window,
/// and at most one positional argument.
struct ReviewArgs {
    op: String,
    window: u32,
    name: String,
}

fn review_args(
    args: &[String],
    usage: &str,
    takes_window: bool,
) -> Result<ReviewArgs, super::CliError> {
    let mut r = ReviewArgs {
        op: String::new(),
        window: review::DEFAULT_WINDOW,
        name: String::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--op" | "--operation" => {
                r.op = option(args, i, usage)?.to_owned();
                i += 2;
            }
            "--within" | "--window" if takes_window => {
                r.window = review::parse_window(option(args, i, usage)?)?;
                i += 2;
            }
            a if a.starts_with('-') => {
                return Err(fail(format!("unknown option: {a}\nusage: {usage}")));
            }
            a => {
                if !r.name.is_empty() {
                    return Err(fail(format!("usage: {usage}")));
                }
                r.name = a.to_owned();
                i += 1;
            }
        }
    }
    Ok(r)
}

fn review_queue(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "finding review-queue [--op operation] [--within days]";
    let a = review_args(args, USAGE, true)?;
    if !a.name.is_empty() {
        return Err(fail(format!("usage: {USAGE}")));
    }
    let root = root()?;
    let op = Operation::load_named_or_active(&root, &a.op)?;
    let q = review::queue(&op, a.window)?;
    ctx.heading("Accepted Risk Review Queue");
    ctx.rule();
    ctx.kv("Operation", &op.name);
    ctx.kv("Target", &op.target);
    ctx.kv("Today", &q.today);
    ctx.kv("Review Window", &format!("{} days", q.window));
    ctx.kv("Due By", &q.due_by);
    ctx.kv("Expired", &q.count("expired").to_string());
    ctx.kv("Due Soon", &q.count("due-soon").to_string());
    ctx.kv("No Expiry", &q.count("no-expiry").to_string());
    ctx.kv("Current", &q.count("current").to_string());
    ctx.rule();
    if q.rows.is_empty() {
        ctx.note("no accepted risks recorded");
        return Ok(());
    }
    for l in q.table() {
        ctx.line(&l);
    }
    Ok(())
}

fn review_packet(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "finding review-packet [--op operation] [--within days] [packet-name]";
    let a = review_args(args, USAGE, true)?;
    let root = mutable_root()?;
    let op = Operation::load_named_or_active(&root, &a.op)?;
    let w = review::write(&op, &a.name, a.window)?;
    ctx.ok("accepted-risk review packet written");
    ctx.kv("review_packet", &w.path().display().to_string());
    if !op.is_active() {
        ctx.note(&format!(
            "operation is closed: regenerate the audit and archive packets so they include this review (lcoat op audit-packet {0}, then lcoat op archive-packet {0})",
            op.slug
        ));
    }
    Ok(())
}

fn review_verify(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "finding review-verify [--op operation] [packet]";
    let a = review_args(args, USAGE, false)?;
    let root = root()?;
    let op = Operation::load_named_or_active(&root, &a.op)?;
    let path = review::resolve_packet(&op, &a.name)?;
    let r = review::verify(&op, &path)?;
    ctx.heading("Accepted Risk Review Packet Verification");
    ctx.rule();
    ctx.kv("Operation", &op.name);
    ctx.kv("Packet", &r.packet);
    ctx.rule();
    ctx.line(&format!("{:<20} {:<14} {}", "ARTIFACT", "STATUS", "DETAIL"));
    for (artifact, status, detail) in &r.rows {
        ctx.line(format!("{artifact:<20} {status:<14} {detail}").trim_end());
    }
    ctx.rule();
    ctx.kv("Verification Status", r.status);
    ctx.kv("Verification Problems", &r.problems.to_string());
    if r.problems > 0 {
        Err(super::CliError::Exit(1))
    } else {
        Ok(())
    }
}
