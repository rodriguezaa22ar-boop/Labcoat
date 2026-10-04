//! `adapter list|run`.

#[cfg(feature = "adapters")]
use std::time::Duration;

use super::{CmdResult, Ctx, fail};

/// Dispatch `adapter <verb>`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let Some((verb, rest)) = args.split_first() else {
        return Err(fail(
            "adapter list|run <adapter> <target> [--timeout seconds] [--] [tool args...]",
        ));
    };
    match verb.as_str() {
        "list" => list(ctx),
        "run" => run_adapter(ctx, rest),
        other => Err(fail(format!("unknown adapter command: {other}"))),
    }
}

#[cfg(not(feature = "adapters"))]
fn list(_ctx: &mut Ctx<'_>) -> CmdResult {
    Err(fail(
        "this build was made without the adapters feature; it can verify but not run tools",
    ))
}

#[cfg(not(feature = "adapters"))]
fn run_adapter(_ctx: &mut Ctx<'_>, _args: &[String]) -> CmdResult {
    Err(fail(
        "this build was made without the adapters feature; it can verify but not run tools",
    ))
}

#[cfg(feature = "adapters")]
fn list(ctx: &mut Ctx<'_>) -> CmdResult {
    ctx.line(&format!("{:<12} {:<16} {}", "ADAPTER", "MAX TIER", "NOTE"));
    for a in lcoat_adapters::adapters() {
        let max = match a.name() {
            "nmap" => "2 (active-recon)",
            _ => "3 (declared)",
        };
        ctx.line(&format!("{:<12} {:<16} {}", a.name(), max, a.note()));
    }
    ctx.note(
        "tier 3 needs 'approval grant'; tiers 4 and 5 are refused; metasploit is refused outright",
    );
    Ok(())
}

#[cfg(feature = "adapters")]
fn run_adapter(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    use super::{load_active, mutable_root, need_args, option};
    use lcoat_adapters::RunParams;

    const USAGE: &str = "adapter run <adapter> <target> [--timeout seconds] [--] [tool args...]";
    need_args(2, args, USAGE)?;
    if args[1].starts_with('-') {
        // Usually an empty shell variable: `adapter run nmap $TARGET --timeout 600`
        // with TARGET unset shifts every argument left by one.
        return Err(fail(format!(
            "adapter run: missing <target> before {:?} (is $TARGET set?)\nusage: {USAGE}",
            args[1]
        )));
    }
    let mut p = RunParams {
        adapter: args[0].clone(),
        target: args[1].clone(),
        args: Vec::new(),
        timeout: None,
    };
    let rest = &args[2..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--timeout" => {
                let v = option(rest, i, USAGE)?;
                match v.parse::<u64>() {
                    Ok(secs) if secs > 0 => p.timeout = Some(Duration::from_secs(secs)),
                    _ => {
                        return Err(fail(
                            "adapter run --timeout must be a positive number of seconds",
                        ));
                    }
                }
                i += 2;
            }
            "--" => {
                p.args.extend(rest[i + 1..].iter().cloned());
                break;
            }
            a => {
                p.args.push(a.to_owned());
                i += 1;
            }
        }
    }
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let out = lcoat_adapters::run(&op, &p)?;
    if out.exit_code == 0 && !out.timed_out {
        ctx.ok("adapter run complete");
    } else if out.timed_out {
        ctx.line(&format!("warn: {} hit the timeout and was stopped; partial output captured as evidence for audit", out.adapter));
    } else {
        ctx.line(&format!(
            "warn: {} exited with code {}; output captured as evidence for audit",
            out.adapter, out.exit_code
        ));
    }
    ctx.kv("adapter", out.adapter);
    ctx.kv("capability", out.tier.capability());
    ctx.kv("tier", &(out.tier as u8).to_string());
    ctx.kv("vantage", &format!("{} {}", out.vantage, out.vantage_addr));
    ctx.kv("exit_code", &out.exit_code.to_string());
    ctx.kv("duration_ms", &out.duration_ms.to_string());
    ctx.kv("evidence", &out.evidence_id);
    ctx.kv("sha256", &out.sha256);
    if out.proposed.is_empty() {
        ctx.note("no proposed findings (confirm findings manually with finding add)");
    } else {
        ctx.line("");
        ctx.heading("Proposed Findings (confirm with finding add)");
        for f in &out.proposed {
            ctx.line(&format!(
                "- {} / {} / {}: {}",
                f.severity, f.confidence, f.title, f.detail
            ));
        }
    }
    if out.exit_code != 0 {
        Err(super::CliError::Exit(1))
    } else {
        Ok(())
    }
}
