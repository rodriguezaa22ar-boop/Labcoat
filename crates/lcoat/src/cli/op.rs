//! `op *`: the operation lifecycle, packets, verifiers and the trust chain.

use std::path::Path;

use lcoat_core::evidence;
use lcoat_core::findings;
use lcoat_core::ledger;
use lcoat_core::operation::{AnyState, Operation, SESSION_FILE, StartParams, State, resume};
use lcoat_core::packet::{self, VerifyResult};
use lcoat_core::readiness;
use lcoat_core::report::{self, Brief};
use lcoat_core::root::{LabRoot, file_exists};
use lcoat_core::validation;
use lcoat_format::canonical::compact;
use lcoat_format::hash::Sha256Hex;
use lcoat_format::ids::slugify;
use lcoat_format::json::{Object, Value};

use super::{
    CliError, CmdResult, Ctx, fail, first_name, load_active, load_closed, metadata, mutable_root,
    need_args, option, root, two_names,
};

/// Dispatch `op <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail(
            "op start|resume|list|status|show|brief|readiness|close|report|handoff|closeout|audit-packet|archive-packet|verify|audit-verify|archive-verify|trust-chain",
        ));
    };
    match verb.as_str() {
        "start" => start(ctx, rest),
        "resume" => resume_cmd(ctx, rest),
        "list" => list(ctx),
        "status" => status(ctx, rest),
        "show" => show(ctx, rest),
        "brief" => brief(ctx, rest),
        "readiness" => readiness_cmd(ctx, rest),
        "close" => close(ctx, rest),
        "report" => report_cmd(ctx, rest),
        "handoff" => handoff(ctx, rest),
        "closeout" => closeout(ctx, rest),
        "audit-packet" => audit_packet(ctx, rest),
        "archive-packet" => archive_packet(ctx, rest),
        "verify" => verify(ctx, rest, "closeout"),
        "audit-verify" => verify(ctx, rest, "audit"),
        "archive-verify" => verify(ctx, rest, "archive"),
        "trust-chain" => trust_chain(ctx, rest),
        "audit" | "archive" => Err(fail(format!(
            "op {verb} (the printed summary) is not in this build; use 'op {verb}-packet' and 'op trust-chain'"
        ))),
        other => Err(fail(format!("unknown op command: {other}"))),
    }
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn n(v: usize) -> Value {
    Value::Number(v.to_string())
}

fn emit(ctx: &mut Ctx<'_>, o: Object) {
    let mut bytes = compact(&Value::Object(o));
    bytes.push(b'\n');
    ctx.raw(&bytes);
}

fn split_json(args: &[String]) -> (Vec<String>, bool) {
    let json = args.iter().any(|a| a == "--json");
    (
        args.iter().filter(|a| *a != "--json").cloned().collect(),
        json,
    )
}

// --- lifecycle --------------------------------------------------------------

fn start(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "op start [--profile profile] <name> <target> [notes...]";
    let mut p = StartParams {
        profile: "default".into(),
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                p.profile = option(args, i, USAGE)?.to_owned();
                i += 2;
            }
            "--" => {
                i += 1;
                break;
            }
            a if a.starts_with("--") => return Err(fail(format!("unknown op start option: {a}"))),
            _ => break,
        }
    }
    let pos = &args[i..];
    need_args(2, pos, USAGE)?;
    p.name = pos[0].clone();
    p.target = pos[1].clone();
    p.notes = metadata("notes", &pos[2..].join(" "))?.as_str().to_owned();
    metadata("name", &p.name)?;
    let root = mutable_root()?;
    let (op, profile) = Operation::start(&root, &p)?;
    ctx.ok("operation ready");
    ctx.kv("operation", &op.name);
    ctx.kv("profile", &profile.name);
    ctx.kv("target", &op.target);
    if op.target_address != op.target {
        ctx.kv("address", &op.target_address);
    }
    ctx.kv("scope_status", &op.scope_status);
    ctx.kv("criticality", &op.criticality);
    if !op.tags.is_empty() {
        ctx.kv("tags", &op.tags);
    }
    if !op.owner.is_empty() {
        ctx.kv("owner", &op.owner);
    }
    ctx.kv("op_dir", &op.dir.display().to_string());
    ctx.kv("active_operation", &op.slug);
    Ok(())
}

fn resume_cmd(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    need_args(1, args, "op resume <name>")?;
    let root = mutable_root()?;
    let op = resume(&root, &args[0])?;
    ctx.ok("operation active");
    ctx.kv("operation", &op.name);
    ctx.kv("target", &op.target);
    if op.target_address != op.target {
        ctx.kv("address", &op.target_address);
    }
    ctx.kv("active_operation", &op.slug);
    Ok(())
}

fn list(ctx: &mut Ctx<'_>) -> CmdResult {
    let root = root()?;
    let ops = Operation::list(&root)?;
    ctx.line(&format!(
        "{:<24} {:<16} {:<24} {}",
        "OPERATION", "STATUS", "TARGET", "ACTIVE"
    ));
    if ops.is_empty() {
        ctx.note("no atlas operations recorded yet");
        return Ok(());
    }
    for o in &ops {
        let active = if o.is_active() { "yes" } else { "no" };
        let target = if !o.target_label.is_empty() && o.target_label != o.target {
            &o.target_label
        } else {
            &o.target
        };
        ctx.line(&format!(
            "{:<24} {:<16} {:<24} {}",
            o.name, o.status, target, active
        ));
    }
    Ok(())
}

fn load_any(root: &LabRoot, args: &[String]) -> Result<Operation<AnyState>, CliError> {
    Ok(Operation::load_named_or_active(root, first_name(args))?)
}

fn readiness_cmd(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let root = root()?;
    let (names, json) = split_json(args);
    let op = load_any(&root, &names)?;
    let st = readiness::collect(&op)?;
    if json {
        let mut o = Object::new();
        o.insert("schema_version", s("lcoat.readiness.v1"));
        o.insert("operation", s(&op.slug));
        o.insert("status", s(st.status));
        o.insert("next_step", s(st.next_step));
        o.insert("evidence_records", n(st.evidence_count));
        o.insert("findings", n(st.finding_count));
        o.insert("open_findings", n(st.open_count));
        o.insert("accepted_risks", n(st.accepted_count));
        o.insert("expired_accepted_risks", n(st.expired_accepted));
        o.insert("validation_plans", n(st.validation_count));
        o.insert("pending_validation", n(st.pending_count));
        let mut fresh = Object::new();
        for (k, v) in [
            ("report", st.report_fresh),
            ("evidence_bundle", st.bundle_fresh),
            ("handoff", st.handoff_fresh),
            ("closeout", st.closeout_fresh),
            ("accepted_risk_review_packet", st.review_fresh),
            ("audit_packet", st.audit_fresh),
            ("archive_packet", st.archive_fresh),
        ] {
            fresh.insert(k, s(v));
        }
        o.insert("freshness", Value::Object(fresh));
        emit(ctx, o);
        return Ok(());
    }
    for l in st.lines(&op) {
        ctx.line(&l);
    }
    Ok(())
}

fn close(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let mut force = false;
    let mut name = "";
    for a in args {
        match a.as_str() {
            "--force" => force = true,
            x if x.starts_with('-') => return Err(fail(format!("unknown op close option: {x}"))),
            x => {
                if !name.is_empty() {
                    return Err(fail(format!("unexpected op close argument: {x}")));
                }
                name = x;
            }
        }
    }
    let root = mutable_root()?;
    let op = load_active(&root, name)?;
    let st = readiness::collect(&op)?;
    let detail = st.ledger_detail(force);
    if st.status != "ready" && !force {
        for l in st.lines(&op) {
            ctx.line(&l);
        }
        return Err(fail(
            "operation is not ready to close; address readiness items or rerun with --force",
        ));
    }
    let closed = op.close(st.status, &detail)?;
    ctx.ok("operation closed");
    ctx.kv("operation", &closed.name);
    ctx.line("status: closed");
    ctx.kv("readiness", st.status);
    ctx.kv("force", if force { "1" } else { "0" });
    Ok(())
}

fn report_cmd(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (name, report_name) = two_names(args);
    let root = mutable_root()?;
    let op = Operation::load_named_or_active(&root, name)?;
    let path = report::write(&op, report_name)?;
    ctx.ok("operation report written");
    ctx.kv("report", &path.display().to_string());
    Ok(())
}

fn handoff(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (name, packet_name) = two_names(args);
    let root = mutable_root()?;
    let op = Operation::load_named_or_active(&root, name)?;
    let w = packet::handoff(&op, packet_name)?;
    ctx.ok("handoff packet written");
    ctx.kv("handoff", &w.path().display().to_string());
    Ok(())
}

fn closeout(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (name, manifest_name) = two_names(args);
    let root = mutable_root()?;
    let op = load_closed(&root, name, "closeout")?;
    let w = packet::closeout(&op, manifest_name)?;
    ctx.ok("closeout manifest written");
    ctx.kv("closeout", &w.path().display().to_string());
    Ok(())
}

fn audit_packet(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (name, packet_name) = two_names(args);
    let root = mutable_root()?;
    let op = load_closed(&root, name, "audit-packet")?;
    let closeout = packet::latest(&op, "closeout")?;
    let w = packet::audit(&op, &closeout, packet_name)?;
    ctx.ok("audit packet written");
    ctx.kv("audit_packet", &w.path().display().to_string());
    Ok(())
}

fn archive_packet(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let (name, packet_name) = two_names(args);
    let root = mutable_root()?;
    let op = load_closed(&root, name, "archive-packet")?;
    let audit = packet::latest(&op, "audit")?;
    let w = packet::archive(&op, &audit, packet_name)?;
    ctx.ok("archive packet written");
    ctx.kv("archive_packet", &w.path().display().to_string());
    Ok(())
}

// --- status / show / brief --------------------------------------------------

fn or_unknown(v: &str) -> &str {
    if v.is_empty() { "unknown" } else { v }
}

fn print_summary<S: State>(ctx: &mut Ctx<'_>, op: &Operation<S>) -> CmdResult {
    let snap = op.snapshot()?;
    ctx.kv("Operation", &op.name);
    ctx.kv("Target", &op.format_target());
    ctx.kv("Target Scope", or_unknown(&op.scope_status));
    ctx.kv("Target Criticality", or_unknown(&op.criticality));
    if !op.owner.is_empty() {
        ctx.kv("Target Owner", &op.owner);
    }
    if !op.tags.is_empty() {
        ctx.kv("Target Tags", &op.tags);
    }
    ctx.kv("Status", &op.status);
    ctx.kv("Profile", &snap.profile);
    ctx.kv("Active", if op.is_active() { "yes" } else { "no" });
    ctx.kv("Created", &op.created_at);
    if !op.closed_at.is_empty() {
        ctx.kv("Closed", &op.closed_at);
    }
    if !op.last_resumed_at.is_empty() {
        ctx.kv("Resumed", &op.last_resumed_at);
    }
    if !op.notes.is_empty() {
        ctx.kv("Notes", &op.notes);
    }
    ctx.kv("Recon Runs", "0");
    ctx.kv("Action Sessions", "0");
    ctx.kv(
        "Evidence",
        &evidence::count(&op.dir, &op.target)?.to_string(),
    );
    ctx.kv(
        "Findings",
        &findings::count(&op.dir, &op.target)?.to_string(),
    );
    ctx.kv(
        "Validation Plans",
        &validation::count(&op.dir, &op.target)?.to_string(),
    );
    ctx.kv("Dir", &op.dir.display().to_string());
    ctx.kv("Latest Recon", "none");
    ctx.kv("Latest Action", "none");
    Ok(())
}

fn status(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let root = root()?;
    let op = load_any(&root, args)?;
    ctx.heading("Operation Status");
    ctx.rule();
    print_summary(ctx, &op)?;
    ctx.rule();
    ctx.heading("Tracked Recon Runs");
    ctx.note("no recon runs tracked yet");
    ctx.rule();
    ctx.heading("Tracked Action Sessions");
    ctx.note("no action sessions tracked yet");
    ctx.line("");
    ctx.heading("Operation Evidence");
    let rows = evidence::rows(&op.dir, &op.target, 8)?;
    if rows.is_empty() {
        ctx.note("no operation evidence recorded yet");
    }
    for r in &rows {
        ctx.line(&super::evidence::row(r));
    }
    ctx.line("");
    ctx.heading("Operation Findings");
    let frows = findings::rows(&op.dir, &op.target, 8)?;
    if frows.is_empty() {
        ctx.note("no operation findings recorded yet");
    }
    for f in &frows {
        ctx.line(&super::finding::row(f));
    }
    ctx.line("");
    ctx.heading("Validation Plans");
    if validation::latest(&op.dir, &op.target)?.is_empty() {
        ctx.note("no operation validation plans recorded yet");
    }
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let root = root()?;
    let op = load_any(&root, args)?;
    let snap = op.snapshot()?;
    ctx.heading("Operation Scope");
    ctx.rule();
    print_summary(ctx, &op)?;
    ctx.rule();
    ctx.heading("Scope");
    ctx.line(&snap.text);
    ctx.rule();
    ctx.heading("Allowed Actions");
    for l in snap.allowed_action_lines() {
        ctx.line(&format!("  - {l}"));
    }
    ctx.rule();
    ctx.heading("Explicitly Out Of Scope");
    for l in snap.out_of_scope_lines() {
        ctx.line(&format!("  - {l}"));
    }
    ctx.rule();
    ctx.heading("Artifacts");
    ctx.kv("Operation Dir", &op.dir.display().to_string());
    ctx.kv("Latest Recon", "");
    ctx.kv("Latest Action", "none");
    Ok(())
}

fn brief(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let root = root()?;
    let op = load_any(&root, args)?;
    let b = Brief::collect(&op)?;
    ctx.heading("Operator Brief");
    ctx.rule();
    for l in b.lines() {
        ctx.line(&l);
    }
    Ok(())
}

// --- verifiers ----------------------------------------------------------------

/// `[name] [packet]`: the first token may be an operation name or a packet.
fn resolve_verify_args(
    root: &LabRoot,
    args: &[String],
    subdir: &str,
) -> Result<(Operation<AnyState>, String), CliError> {
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let (op, packet_arg) = match names.as_slice() {
        [] => (Operation::load_active(root)?, ""),
        [one] => {
            if file_exists(&root.op_dir(&slugify(one)).join(SESSION_FILE)) {
                (Operation::load(root, one)?, "")
            } else {
                (Operation::load_active(root)?, one.as_str())
            }
        }
        [first, second, ..] => (Operation::load(root, first)?, second.as_str()),
    };
    let path = resolve_packet_path(&op, subdir, packet_arg)?;
    Ok((op, path))
}

/// Explicit path, `subdir/name`, `subdir/<slug>.md`, or the latest recorded.
fn resolve_packet_path(
    op: &Operation<AnyState>,
    subdir: &str,
    arg: &str,
) -> Result<String, CliError> {
    let dir = op.dir.join(subdir);
    if arg.is_empty() {
        let latest = packet::latest_in_ledger(op, subdir)?;
        if latest.is_empty() {
            return Err(fail(format!(
                "no {subdir} packet recorded for operation '{}'",
                op.slug
            )));
        }
        if !file_exists(Path::new(&latest)) {
            return Err(fail(format!(
                "recorded {subdir} packet is missing: {latest}"
            )));
        }
        return Ok(latest);
    }
    // Explicit arguments resolve like the shell's `readlink -f`.
    let resolved = |p: &Path| {
        p.canonicalize()
            .unwrap_or_else(|_| p.to_path_buf())
            .display()
            .to_string()
    };
    if file_exists(Path::new(arg)) {
        return Ok(resolved(Path::new(arg)));
    }
    let candidate = dir.join(arg);
    if file_exists(&candidate) {
        return Ok(resolved(&candidate));
    }
    let base = arg.strip_suffix(".md").unwrap_or(arg);
    let base = base.strip_suffix(".json").unwrap_or(base);
    let candidate = dir.join(format!("{}.md", slugify(base)));
    if file_exists(&candidate) {
        return Ok(resolved(&candidate));
    }
    Err(fail(format!(
        "unknown {subdir} packet for operation '{}': {arg}",
        op.slug
    )))
}

fn verify(ctx: &mut Ctx<'_>, args: &[String], subdir: &str) -> CmdResult {
    let (names, json) = split_json(args);
    if names.len() > 2 {
        return Err(fail(format!(
            "op {} [name] [{}] [--json]",
            verb_for(subdir),
            arg_name(subdir)
        )));
    }
    let root = root()?;
    let (op, path) = resolve_verify_args(&root, &names, subdir)?;
    let res = match subdir {
        "closeout" => packet::closeout_verify(&op, &path)?,
        "audit" => packet::audit_verify(&op, &path)?,
        _ => packet::archive_verify(&op, &path)?,
    };
    if json {
        let mut o = Object::new();
        o.insert("schema_version", s("lcoat.packet_verify.v1"));
        o.insert("packet_kind", s(subdir));
        o.insert("operation", s(&op.slug));
        o.insert("packet", s(&path));
        o.insert("status", s(res.status));
        o.insert("verified_anchors", n(res.verified));
        o.insert("verification_gaps", n(res.gaps));
        o.insert("verification_problems", n(res.problems));
        o.insert(
            "rows",
            Value::Array(res.rows.iter().map(|r| s(r)).collect()),
        );
        emit(ctx, o);
        return if res.problems > 0 {
            Err(CliError::Exit(1))
        } else {
            Ok(())
        };
    }
    print_verify(ctx, &op, &path, &res)
}

fn verb_for(subdir: &str) -> &'static str {
    match subdir {
        "closeout" => "verify",
        "audit" => "audit-verify",
        _ => "archive-verify",
    }
}

fn arg_name(subdir: &str) -> &'static str {
    match subdir {
        "closeout" => "closeout-manifest",
        "audit" => "audit-packet",
        _ => "archive-packet",
    }
}

/// The shell build's verification table: heading, operation, packet path,
/// column header, rows, footer.
fn print_verify(
    ctx: &mut Ctx<'_>,
    op: &Operation<AnyState>,
    path: &str,
    res: &VerifyResult,
) -> CmdResult {
    ctx.heading(res.kind.title());
    ctx.rule();
    ctx.kv("Operation", &op.name);
    ctx.kv(res.kind.path_label(), path);
    ctx.rule();
    ctx.line(&res.kind.column_header());
    for r in &res.rows {
        ctx.line(r);
    }
    ctx.rule();
    ctx.kv("Verification Status", res.status);
    if res.kind.prints_counts() {
        ctx.kv("Verified Anchors", &res.verified.to_string());
        ctx.kv("Verification Gaps", &res.gaps.to_string());
    }
    ctx.kv("Verification Problems", &res.problems.to_string());
    if res.problems > 0 {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}

fn trust_chain(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let mut strict = false;
    let mut json = false;
    let mut name = "";
    for a in args {
        match a.as_str() {
            "--strict" => strict = true,
            "--json" => json = true,
            x if x.starts_with('-') => {
                return Err(fail(format!("unknown op trust-chain option: {x}")));
            }
            x => {
                if !name.is_empty() {
                    return Err(fail("op trust-chain [name] [--strict] [--json]"));
                }
                name = x;
            }
        }
    }
    let root = root()?;
    let op = Operation::load_named_or_active(&root, name)?;
    let tc = packet::collect_trust_chain(&op)?;
    let st = &tc.readiness;
    let none = |v: &str| {
        if v.is_empty() {
            "none".to_owned()
        } else {
            v.to_owned()
        }
    };
    let ledger_file = op.ledger_file();
    let sha = Sha256Hex::of_file(&ledger_file)
        .map(|h| h.as_str().to_owned())
        .unwrap_or_default();
    let count = ledger::count(&ledger_file).unwrap_or(0);
    let chain = lcoat_core::chain::verify(&ledger::read_objects(&ledger_file).unwrap_or_default());

    if json {
        let mut o = Object::new();
        o.insert("schema_version", s("lcoat.operation_trust_chain.v1"));
        let mut operation = Object::new();
        operation.insert("slug", s(&op.slug));
        operation.insert("name", s(&op.name));
        operation.insert("target", s(&op.target));
        operation.insert("status", s(&op.status));
        o.insert("operation", Value::Object(operation));
        o.insert("status", s(tc.status));
        o.insert("next_step", s(&tc.next_step));
        let mut r = Object::new();
        r.insert("close", s(st.status));
        r.insert("next_step", s(st.next_step));
        r.insert("evidence_records", n(st.evidence_count));
        r.insert("open_findings", n(st.open_count));
        r.insert("accepted_risks", n(st.accepted_count));
        r.insert("expired_accepted_risks", n(st.expired_accepted));
        r.insert("pending_validation", n(st.pending_count));
        o.insert("readiness", Value::Object(r));
        let mut v1 = Object::new();
        v1.insert("overall", s("not-evaluated"));
        v1.insert("note", s("Lab Coat does not ship the v1 toolchain pillars"));
        o.insert("v1", Value::Object(v1));
        let mut f = Object::new();
        for (k, v) in [
            ("report", st.report_fresh),
            ("evidence_bundle", st.bundle_fresh),
            ("handoff", st.handoff_fresh),
            ("closeout", st.closeout_fresh),
            ("accepted_risk_review_packet", st.review_fresh),
            ("audit_packet", st.audit_fresh),
            ("archive_packet", st.archive_fresh),
        ] {
            f.insert(k, s(v));
        }
        o.insert("freshness", Value::Object(f));
        let mut ver = Object::new();
        let mut c = Object::new();
        c.insert("status", s(tc.closeout_verification));
        c.insert("path", s(&tc.closeout_path));
        c.insert("problems", n(tc.closeout_problems));
        ver.insert("closeout", Value::Object(c));
        let mut rv = Object::new();
        rv.insert("status", s(tc.review_verification));
        rv.insert("path", s(&tc.review_path));
        ver.insert("accepted_risk_review_packet", Value::Object(rv));
        let mut au = Object::new();
        au.insert("status", s(tc.audit_verification));
        au.insert("path", s(&tc.audit_path));
        ver.insert("audit_packet", Value::Object(au));
        let mut ar = Object::new();
        ar.insert("status", s(tc.archive_verification));
        ar.insert(
            "path",
            s(if tc.archive_path.is_empty() {
                "-"
            } else {
                &tc.archive_path
            }),
        );
        ver.insert("archive_packet", Value::Object(ar));
        let mut ev = Object::new();
        ev.insert("status", s(tc.evidence_verification));
        ev.insert("checked", n(tc.evidence_checked));
        ev.insert("problems", n(tc.evidence_problems));
        ver.insert("evidence_artifacts", Value::Object(ev));
        o.insert("verification", Value::Object(ver));
        let mut l = Object::new();
        l.insert("file", s(&ledger_file.display().to_string()));
        l.insert("events", n(count));
        l.insert("sha256", s(&sha));
        l.insert("chain", s(&chain_word(&chain)));
        l.insert("latest_at", s(&none(&st.latest_ledger.at)));
        l.insert("latest_event", s(&none(&st.latest_ledger.event)));
        o.insert("ledger", Value::Object(l));
        emit(ctx, o);
        return if strict && tc.status != "current" {
            Err(CliError::Exit(1))
        } else {
            Ok(())
        };
    }

    // Layout follows the shell build's atlas_trust_chain_print. Two
    // documented differences: the v1 toolchain is not evaluated here, and
    // the Business Flow Evidence block is omitted (Lab Coat has no flows);
    // two additions: the Evidence Artifacts and Ledger Chain lines.
    ctx.heading("Operation Trust Chain");
    ctx.rule();
    ctx.kv("Operation", &op.name);
    ctx.kv("Operation Status", &op.status);
    ctx.kv("Target", &op.target);
    ctx.kv("Trust Chain Status", tc.status);
    ctx.kv("Next Trust Step", &tc.next_step);
    ctx.rule();
    ctx.heading("Readiness");
    ctx.kv("Close Readiness", st.status);
    ctx.kv("Evidence Records", &st.evidence_count.to_string());
    ctx.kv("Open Findings", &st.open_count.to_string());
    ctx.kv("Accepted Risks", &st.accepted_count.to_string());
    ctx.kv("Expired Accepted Risks", &st.expired_accepted.to_string());
    ctx.kv("Pending Validation", &st.pending_count.to_string());
    ctx.kv(
        "V1 Readiness",
        "not evaluated (Lab Coat does not ship the v1 toolchain pillars)",
    );
    ctx.rule();
    ctx.heading("Freshness");
    ctx.kv(
        "Report",
        &format!("{} path={}", st.report_fresh, none(&st.report.detail)),
    );
    ctx.kv(
        "Evidence Bundle",
        &format!("{} detail={}", st.bundle_fresh, none(&st.bundle.detail)),
    );
    ctx.kv(
        "Handoff",
        &format!("{} path={}", st.handoff_fresh, none(&st.handoff.detail)),
    );
    ctx.kv(
        "Closeout",
        &format!("{} path={}", st.closeout_fresh, none(&st.closeout.detail)),
    );
    ctx.kv(
        "Accepted Risk Review Packet",
        &format!(
            "{} path={}",
            st.review_fresh,
            none(&st.review_packet.detail)
        ),
    );
    ctx.kv(
        "Audit Packet",
        &format!("{} path={}", st.audit_fresh, none(&st.audit_packet.detail)),
    );
    ctx.kv(
        "Archive Packet",
        &format!(
            "{} path={}",
            st.archive_fresh,
            none(&st.archive_packet.detail)
        ),
    );
    ctx.rule();
    ctx.heading("Verification");
    ctx.kv(
        "Closeout",
        &format!(
            "{} manifest={} problems={}",
            tc.closeout_verification, tc.closeout_path, tc.closeout_problems
        ),
    );
    ctx.kv(
        "Accepted Risk Review Packet",
        &format!("{} packet={}", tc.review_verification, tc.review_path),
    );
    ctx.kv(
        "Audit Packet",
        &format!("{} packet={}", tc.audit_verification, tc.audit_path),
    );
    ctx.kv(
        "Archive Packet",
        &format!(
            "{} packet={}",
            tc.archive_verification,
            if tc.archive_path.is_empty() {
                "-"
            } else {
                &tc.archive_path
            }
        ),
    );
    ctx.kv(
        "Evidence Artifacts",
        &format!(
            "{} checked={} problems={}",
            tc.evidence_verification, tc.evidence_checked, tc.evidence_problems
        ),
    );
    ctx.rule();
    ctx.heading("Ledger");
    ctx.kv(
        "Operation Ledger",
        &format!("{} events={count} sha256={sha}", ledger_file.display()),
    );
    ctx.kv(
        "Latest Ledger Event",
        &format!(
            "{} {}",
            none(&st.latest_ledger.at),
            none(&st.latest_ledger.event)
        ),
    );
    ctx.kv("Ledger Chain", &chain_word(&chain));
    if strict && tc.status != "current" {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}

/// One word plus detail for the ledger chain state.
pub fn chain_word(c: &lcoat_core::chain::ChainStatus) -> String {
    use lcoat_core::chain::ChainStatus;
    match c {
        ChainStatus::Unchained => "unchained (v1 ledger; whole-file hash only)".into(),
        ChainStatus::Partial { first_chained } => {
            format!("partial (chained from event {})", first_chained + 1)
        }
        ChainStatus::Verified => "verified".into(),
        ChainStatus::Broken { index, reason } => {
            format!("broken at event {} ({reason})", index + 1)
        }
    }
}
