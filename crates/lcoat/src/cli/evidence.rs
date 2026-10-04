//! `evidence add|list|verify`.

use std::path::PathBuf;

use lcoat_core::evidence::{self, AddParams};
use lcoat_core::operation::Operation;
use lcoat_format::canonical::compact;
use lcoat_format::json::{Object, Value};

use super::{
    CliError, CmdResult, Ctx, fail, first_name, load_active, load_read_only_op, metadata,
    mutable_root, need_args, option, root,
};

/// Dispatch `evidence <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail("evidence add|list|verify"));
    };
    match verb.as_str() {
        "add" => add(ctx, rest),
        "list" => list(ctx, rest),
        "verify" => verify(ctx, rest),
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

fn add(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "evidence add <path> [--kind kind] [--target target] [--classification label] [--redacted true|false]";
    need_args(1, args, USAGE)?;
    let mut p = AddParams {
        source: PathBuf::from(&args[0]),
        kind: None,
        target: None,
        classification: None,
        redacted: false,
        tool: String::new(),
        vantage: None,
    };
    let rest = &args[1..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            flag @ ("--kind" | "--target" | "--classification" | "--redacted") => {
                let v = option(rest, i, &format!("evidence add <path> {flag} <value>"))?;
                match flag {
                    "--kind" => p.kind = Some(metadata(flag, v)?),
                    "--target" => p.target = Some(metadata(flag, v)?),
                    "--classification" => p.classification = Some(metadata(flag, v)?),
                    _ => {
                        p.redacted = match v {
                            "true" => true,
                            "false" => false,
                            other => {
                                return Err(fail(format!(
                                    "expected boolean true or false, got: {other}"
                                )));
                            }
                        }
                    }
                }
                i += 2;
            }
            other => return Err(fail(format!("unknown evidence add option: {other}"))),
        }
    }
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let rec = evidence::add(&op, &p)?;
    ctx.ok("evidence added");
    ctx.kv("id", &rec.id);
    ctx.kv("kind", &rec.kind);
    ctx.kv("target", &rec.target);
    ctx.kv("sha256", &rec.sha256);
    ctx.kv("path", &format!("{}/{}", op.dir.display(), rec.path));
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let root = root()?;
    let op = load_read_only_op(&root, args, "evidence list [operation]")?;
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

fn verify(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let json = args.iter().any(|a| a == "--json");
    let names: Vec<String> = args.iter().filter(|a| *a != "--json").cloned().collect();
    let root = root()?;
    let op = Operation::load_named_or_active(&root, first_name(&names))?;
    let (checks, problems) = evidence::verify_artifacts(&op.dir)?;
    let status = if problems > 0 {
        "attention-required"
    } else {
        "verified"
    };
    if json {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("schema_version", s("lcoat.evidence_verify.v1"));
        o.insert("operation", s(&op.slug));
        o.insert("status", s(status));
        o.insert("checked", Value::Number(checks.len().to_string()));
        o.insert("problems", Value::Number(problems.to_string()));
        o.insert(
            "artifacts",
            Value::Array(
                checks
                    .iter()
                    .map(|c| {
                        let mut a = Object::new();
                        a.insert("id", s(&c.id));
                        a.insert("path", s(&c.path));
                        a.insert("status", s(c.status));
                        a.insert("expected_sha256", s(&c.expected));
                        a.insert("actual_sha256", s(&c.actual));
                        Value::Object(a)
                    })
                    .collect(),
            ),
        );
        let mut bytes = compact(&Value::Object(o));
        bytes.push(b'\n');
        ctx.raw(&bytes);
        return if problems > 0 {
            Err(CliError::Exit(1))
        } else {
            Ok(())
        };
    }
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
    ctx.kv("Artifacts Checked", &checks.len().to_string());
    ctx.kv("Artifact Problems", &problems.to_string());
    ctx.kv("Verification Status", status);
    if problems > 0 {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}
