//! `finding add|resolve|accept|reopen|note|list|review-queue|review-packet|review-verify`.

use lcoat_core::findings::{self, AcceptParams, AddParams, Finding, Update};
use lcoat_core::metadata::MetadataOnly;
use lcoat_core::operation::Operation;
use lcoat_core::packet::review;

use super::args::{Args, Kind, Spec, parse};
use super::{CmdResult, Ctx, fail, load_active, metadata, mutable_root, root};

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
    const SPEC: Spec = Spec::new(
        "finding add <title> [--level observed|inferred|validated] [--severity severity] [--confidence confidence] [--status status] [--impact text] [--recommendation text] [--evidence id]...",
        1,
        Some(1),
    )
    .flags(&[
        ("--target", Kind::Value),
        ("--level", Kind::Value),
        ("--severity", Kind::Value),
        ("--confidence", Kind::Value),
        ("--status", Kind::Value),
        ("--source", Kind::Value),
        ("--impact", Kind::Value),
        ("--recommendation", Kind::Value),
        ("--evidence", Kind::Many),
    ]);
    let a = parse(&SPEC, args)?;
    let scanned = |flag: &str| a.value(flag).map(|v| metadata(flag, v)).transpose();
    let plain = |flag: &str| a.value(flag).unwrap_or("").to_owned();
    let p = AddParams {
        title: Some(metadata("title", a.pos(0))?),
        target: scanned("--target")?,
        level: plain("--level"),
        severity: plain("--severity"),
        confidence: plain("--confidence"),
        status: plain("--status"),
        source: plain("--source"),
        impact: scanned("--impact")?,
        recommendation: scanned("--recommendation")?,
        evidence: a
            .values("--evidence")
            .into_iter()
            .map(str::to_owned)
            .collect(),
    };
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
    spec: &Spec,
) -> Result<(String, Vec<String>, Option<MetadataOnly>), super::CliError> {
    let a = parse(spec, args)?;
    let evidence = a
        .values("--evidence")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let note = a
        .value("--note")
        .map(|v| metadata("--note", v))
        .transpose()?;
    Ok((a.pos(0).to_owned(), evidence, note))
}

fn resolve(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const SPEC: Spec = Spec::new(
        "finding resolve <id> [--evidence id]... [--note text]",
        1,
        Some(1),
    )
    .flags(&[("--evidence", Kind::Many), ("--note", Kind::Value)]);
    let (id, evidence, note) = id_evidence_note(args, &SPEC)?;
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::resolve(&op, &id, &evidence, note)?;
    ctx.ok("finding resolved");
    print_finding(ctx, &f);
    Ok(())
}

fn reopen(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const SPEC: Spec = Spec::new("finding reopen <id> [--note text]", 1, Some(1))
        .flags(&[("--note", Kind::Value)]);
    let (id, _, note) = id_evidence_note(args, &SPEC)?;
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::reopen(&op, &id, note)?;
    ctx.ok("finding reopened");
    print_finding(ctx, &f);
    Ok(())
}

fn note(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let a = parse(&Spec::new("finding note <id> <text>", 2, None), args)?;
    let text = metadata("note", &a.rest(1).join(" "))?;
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let f = findings::update(
        &op,
        a.pos(0),
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
    const SPEC: Spec = Spec::new(
        "finding accept <id> --reason text [--owner owner] [--expires YYYY-MM-DD|timestamp|Nh|Nd] [--evidence id]...",
        1,
        Some(1),
    )
    .flags(&[
        ("--reason", Kind::Value),
        ("--owner", Kind::Value),
        ("--expires|--until", Kind::Value),
        ("--evidence", Kind::Many),
    ]);
    let a = parse(&SPEC, args)?;
    let id = a.pos(0).to_owned();
    let reason = a
        .value("--reason")
        .map(|v| metadata("--reason", v))
        .transpose()?;
    let owner = a
        .value("--owner")
        .map(|v| metadata("--owner", v))
        .transpose()?;
    // Same forms as approvals (YYYY-MM-DD, timestamp, Nh, Nd), stored as
    // the instant they name.
    let expires = a
        .value("--expires")
        .map(|v| super::approval::parse_expiry(v).map(|t| t.timestamp()))
        .transpose()?;
    let evidence: Vec<String> = a
        .values("--evidence")
        .into_iter()
        .map(str::to_owned)
        .collect();
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
    let a = parse(&Spec::new("finding list [operation]", 0, Some(1)), args)?;
    let root = root()?;
    let op = Operation::load_named_or_active(&root, a.pos(0))?;
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
/// and the positional argument when the verb takes one.
struct ReviewArgs {
    op: String,
    window: u32,
    name: String,
}

fn review_args(args: &[String], spec: &Spec) -> Result<ReviewArgs, super::CliError> {
    let a: Args = parse(spec, args)?;
    Ok(ReviewArgs {
        op: a.value("--op").unwrap_or("").to_owned(),
        window: match a.value("--within") {
            Some(v) => review::parse_window(v)?,
            None => review::DEFAULT_WINDOW,
        },
        name: a.pos(0).to_owned(),
    })
}

fn review_queue(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const SPEC: Spec = Spec::new(
        "finding review-queue [--op operation] [--within days]",
        0,
        Some(0),
    )
    .flags(&[
        ("--op|--operation", Kind::Value),
        ("--within|--window", Kind::Value),
    ]);
    let a = review_args(args, &SPEC)?;
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
    const SPEC: Spec = Spec::new(
        "finding review-packet [--op operation] [--within days] [packet-name]",
        0,
        Some(1),
    )
    .flags(&[
        ("--op|--operation", Kind::Value),
        ("--within|--window", Kind::Value),
    ]);
    let a = review_args(args, &SPEC)?;
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
    const SPEC: Spec = Spec::new(
        "finding review-verify [--op operation] [packet]",
        0,
        Some(1),
    )
    .flags(&[("--op|--operation", Kind::Value)]);
    let a = review_args(args, &SPEC)?;
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
