//! `op list|readiness|verify|audit-verify|archive-verify|trust-chain`.

use std::path::Path;

use lcoat_core::ledger;
use lcoat_core::operation::{Operation, SESSION_FILE};
use lcoat_core::packet::{self, VerifyResult};
use lcoat_core::readiness;
use lcoat_core::root::{LabRoot, file_exists};
use lcoat_format::hash::Sha256Hex;
use lcoat_format::ids::slugify;

use super::{CliError, CmdResult, Ctx, fail, load_op};

/// Dispatch `op <verb>`.
pub fn run(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail(
            "op list|readiness|verify|audit-verify|archive-verify|trust-chain",
        ));
    };
    match verb.as_str() {
        "list" => list(ctx, root),
        "readiness" => readiness_cmd(ctx, root, rest),
        "verify" => verify(ctx, root, rest, "closeout"),
        "audit-verify" => verify(ctx, root, rest, "audit"),
        "archive-verify" => verify(ctx, root, rest, "archive"),
        "trust-chain" => trust_chain(ctx, root, rest),
        "start" | "resume" | "close" | "report" | "handoff" | "closeout" | "audit-packet"
        | "archive-packet" | "status" | "show" | "brief" | "audit" | "archive" => {
            Err(fail(format!(
                "op {verb} is not in this build yet (phase 2 adds the write side); use Lab Coat Lite (lcoat 0.1.4) for it meanwhile"
            )))
        }
        other => Err(fail(format!("unknown op command: {other}"))),
    }
}

fn list(ctx: &mut Ctx<'_>, root: &LabRoot) -> CmdResult {
    let ops = Operation::list(root)?;
    ctx.line(&format!(
        "{:<24} {:<16} {:<24} {}",
        "OPERATION", "STATUS", "TARGET", "ACTIVE"
    ));
    if ops.is_empty() {
        ctx.note("no atlas operations recorded yet");
        return Ok(());
    }
    for o in &ops {
        let active = if Operation::is_active(root, &o.slug) {
            "yes"
        } else {
            "no"
        };
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

fn readiness_cmd(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let op = load_op(root, args)?;
    let st = readiness::collect(&op)?;
    for l in st.lines(&op) {
        ctx.line(&l);
    }
    Ok(())
}

/// `[name] [packet]`: the first token may be an operation name or a packet.
fn resolve_verify_args(
    root: &LabRoot,
    args: &[String],
    subdir: &str,
) -> Result<(Operation, String), CliError> {
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
fn resolve_packet_path(op: &Operation, subdir: &str, arg: &str) -> Result<String, CliError> {
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

fn verify(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String], subdir: &str) -> CmdResult {
    if args.len() > 2 {
        return Err(fail(format!(
            "op {} [name] [{}]",
            verb_for(subdir),
            arg_name(subdir)
        )));
    }
    let (op, path) = resolve_verify_args(root, args, subdir)?;
    let res = match subdir {
        "closeout" => packet::closeout_verify(&op, &path)?,
        "audit" => packet::audit_verify(&op, &path)?,
        _ => packet::archive_verify(&op, &path)?,
    };
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
fn print_verify(ctx: &mut Ctx<'_>, op: &Operation, path: &str, res: &VerifyResult) -> CmdResult {
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

fn trust_chain(ctx: &mut Ctx<'_>, root: &LabRoot, args: &[String]) -> CmdResult {
    let mut strict = false;
    let mut name = "";
    for a in args {
        match a.as_str() {
            "--strict" => strict = true,
            "--json" => {
                return Err(fail(
                    "op trust-chain --json is not implemented in this build yet",
                ));
            }
            s if s.starts_with('-') => {
                return Err(fail(format!("unknown op trust-chain option: {s}")));
            }
            s => {
                if !name.is_empty() {
                    return Err(fail("op trust-chain [name] [--strict]"));
                }
                name = s;
            }
        }
    }
    let op = Operation::load_named_or_active(root, name)?;
    let tc = packet::collect_trust_chain(&op)?;
    let st = &tc.readiness;
    let none = |s: &str| {
        if s.is_empty() {
            "none".to_owned()
        } else {
            s.to_owned()
        }
    };
    // Layout follows the shell build's atlas_trust_chain_print. Two
    // documented differences: the v1 toolchain is not evaluated here, and
    // the Business Flow Evidence block is omitted (Lab Coat has no flows);
    // one addition: the Evidence Artifacts re-hash line.
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
    let ledger_file = op.ledger_file();
    let sha = Sha256Hex::of_file(&ledger_file)
        .map(|h| h.as_str().to_owned())
        .unwrap_or_default();
    let n = ledger::count(&ledger_file).unwrap_or(0);
    ctx.kv(
        "Operation Ledger",
        &format!("{} events={n} sha256={sha}", ledger_file.display()),
    );
    ctx.kv(
        "Latest Ledger Event",
        &format!(
            "{} {}",
            none(&st.latest_ledger.at),
            none(&st.latest_ledger.event)
        ),
    );
    if strict && tc.status != "current" {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}
