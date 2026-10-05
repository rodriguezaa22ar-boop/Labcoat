//! `evidence add|list|verify|diff|bundle|bundle-verify`.

use std::path::PathBuf;

use lcoat_core::bundle;
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
        return Err(fail("evidence add|list|verify|diff|bundle|bundle-verify"));
    };
    match verb.as_str() {
        "add" => add(ctx, rest),
        "list" => list(ctx, rest),
        "verify" => verify(ctx, rest),
        "diff" => diff(ctx, rest),
        "bundle" => bundle(ctx, rest),
        "bundle-verify" => bundle_verify(ctx, rest),
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

/// `evidence bundle [bundle-name] [--include-unredacted]`: the shell's
/// command and output, plus the manifest hash the ledger now records.
fn bundle(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    const USAGE: &str = "evidence bundle [bundle-name] [--include-unredacted]";
    let mut name = "";
    let mut include_unredacted = false;
    let mut positional = false;
    for a in args {
        match a.as_str() {
            "--include-unredacted" => include_unredacted = true,
            "--" => positional = true,
            f if f.starts_with('-') && !positional => {
                return Err(fail(format!(
                    "unknown evidence bundle option: {f}\nusage: {USAGE}"
                )));
            }
            n => {
                if !name.is_empty() {
                    return Err(fail(format!("unexpected evidence bundle argument: {n}")));
                }
                name = n;
            }
        }
    }
    let root = mutable_root()?;
    let op = load_active(&root, "")?;
    let b = bundle::write(&op, name, include_unredacted)?;
    ctx.ok("evidence bundle written");
    ctx.kv("bundle", &b.dir.display().to_string());
    ctx.kv("manifest", &b.manifest.display().to_string());
    ctx.kv("files", &b.files.to_string());
    ctx.kv(
        "include_unredacted",
        if b.include_unredacted { "1" } else { "0" },
    );
    ctx.kv("manifest_sha256", &b.manifest_sha256);
    super::next(ctx, &["evidence", "bundle-verify", &b.slug]);
    super::next(ctx, &["op", "handoff", &op.slug]);
    Ok(())
}

/// `evidence bundle-verify [--op operation] [bundle|dir] [--manifest-sha256 sha] [--json]`.
///
/// A bundle name (or nothing, for the latest) is verified inside its
/// operation, anchored by the ledger. An argument with a `/` is a bundle
/// directory, verified on its own with no lab root: what a recipient runs
/// on a copy, with the hash from the packet they were given.
fn bundle_verify(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    use lcoat_format::hash::Sha256Hex;

    const USAGE: &str =
        "evidence bundle-verify [--op operation] [bundle|dir] [--manifest-sha256 sha] [--json]";
    let mut op_name = "";
    let mut target = "";
    let mut expected = "";
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json = true;
                i += 1;
            }
            "--op" | "--operation" => {
                op_name = option(args, i, USAGE)?;
                i += 2;
            }
            "--manifest-sha256" => {
                expected = option(args, i, USAGE)?;
                Sha256Hex::parse(expected).map_err(|_| {
                    fail(format!(
                        "--manifest-sha256 must be 64 lowercase hex characters, got: {expected}"
                    ))
                })?;
                i += 2;
            }
            a if a.starts_with('-') => {
                return Err(fail(format!("unknown option: {a}\nusage: {USAGE}")));
            }
            a => {
                if !target.is_empty() {
                    return Err(fail(format!("usage: {USAGE}")));
                }
                target = a;
                i += 1;
            }
        }
    }
    let standalone = target.contains('/') || target == ".";
    let (v, op_label) = if standalone {
        if !op_name.is_empty() {
            return Err(fail(
                "a bundle directory is verified on its own; drop --op, or name the bundle instead of its path",
            ));
        }
        let dir = std::path::Path::new(target);
        if !dir.is_dir() {
            return Err(fail(format!("not a directory: {target}")));
        }
        (bundle::verify_dir(dir, expected)?, String::new())
    } else {
        let root = root()?;
        let op = Operation::load_named_or_active(&root, op_name)?;
        let dir = bundle::resolve(&op, target)?;
        (bundle::verify_in_op(&op, &dir, expected)?, op.name.clone())
    };

    if json {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("schema_version", s("lcoat.evidence_bundle_verify.v1"));
        o.insert("bundle", s(&v.dir));
        o.insert("operation", s(&v.operation));
        let mut m = Object::new();
        m.insert("status", s(v.manifest_status));
        m.insert("sha256", s(&v.manifest_sha256));
        m.insert("expected_sha256", s(&v.expected_manifest_sha256));
        m.insert("anchor", s(v.anchor));
        m.insert(
            "problems",
            Value::Array(v.manifest_problems.iter().map(|p| s(p)).collect()),
        );
        o.insert("manifest", Value::Object(m));
        o.insert(
            "files",
            Value::Array(
                v.files
                    .iter()
                    .map(|f| {
                        let mut x = Object::new();
                        x.insert("id", s(&f.id));
                        x.insert("path", s(&f.path));
                        x.insert("status", s(f.status));
                        x.insert("detail", s(&f.detail));
                        Value::Object(x)
                    })
                    .collect(),
            ),
        );
        o.insert("checked", Value::Number(v.checked().to_string()));
        o.insert("problems", Value::Number(v.problems.to_string()));
        o.insert("status", s(v.status));
        let mut bytes = compact(&Value::Object(o));
        bytes.push(b'\n');
        ctx.raw(&bytes);
    } else {
        ctx.heading("Evidence Bundle Verification");
        ctx.rule();
        ctx.kv("Bundle", &v.dir);
        if op_label.is_empty() {
            ctx.kv("Operation ID", &v.operation);
        } else {
            ctx.kv("Operation", &op_label);
        }
        ctx.kv("Manifest SHA256", &v.manifest_sha256);
        ctx.kv(
            "Manifest Anchor",
            &format!(
                "{} anchor={} expected={}",
                v.manifest_status,
                v.anchor,
                if v.expected_manifest_sha256.is_empty() {
                    "none"
                } else {
                    &v.expected_manifest_sha256
                }
            ),
        );
        ctx.rule();
        ctx.line(&format!("{:<26} {:<14} {}", "ARTIFACT", "STATUS", "DETAIL"));
        for f in &v.files {
            let detail = if f.detail.is_empty() {
                f.path.clone()
            } else {
                format!("{} {}", f.path, f.detail)
            };
            ctx.line(format!("{:<26} {:<14} {detail}", f.id, f.status).trim_end());
        }
        ctx.rule();
        for p in &v.manifest_problems {
            ctx.line(&format!("problem: {p}"));
        }
        ctx.kv("Files Checked", &v.checked().to_string());
        ctx.kv("Verification Problems", &v.problems.to_string());
        ctx.kv("Verification Status", v.status);
        if v.status == "unanchored" {
            ctx.note("nothing anchors this manifest; pass --manifest-sha256 with the hash on the Evidence bundle manifest line of the handoff, closeout or archive packet");
        }
    }
    if v.problems > 0 {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}

#[cfg(not(feature = "adapters"))]
fn diff(_ctx: &mut Ctx<'_>, _args: &[String]) -> CmdResult {
    Err(fail(
        "evidence diff reads nmap reports; this build was made without the adapters feature",
    ))
}

/// `evidence diff <before> <after> [--op operation] [--json]`: compare two
/// captured nmap reports port by port. Read-only; both artifacts are
/// re-hashed against their records first.
#[cfg(feature = "adapters")]
fn diff(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    use lcoat_adapters::nmap::{compare, summarize};
    use lcoat_format::hash::Sha256Hex;

    const USAGE: &str = "evidence diff <before-id> <after-id> [--op operation] [--json]";
    let mut ids: Vec<&str> = Vec::new();
    let mut op_name = "";
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json = true;
                i += 1;
            }
            "--op" | "--operation" => {
                op_name = option(args, i, USAGE)?;
                i += 2;
            }
            a if a.starts_with('-') => return Err(fail(format!("usage: {USAGE}"))),
            a => {
                ids.push(a);
                i += 1;
            }
        }
    }
    let [before_id, after_id] = ids[..] else {
        return Err(fail(format!("usage: {USAGE}")));
    };
    let root = root()?;
    let op = Operation::load_named_or_active(&root, op_name)?;
    let records = evidence::latest(&op.dir, "")?;
    let load = |id: &str| -> Result<(evidence::Record, String), CliError> {
        let Some(rec) = records.iter().find(|r| r.id == id).cloned() else {
            return Err(fail(format!(
                "unknown evidence id in operation '{}': {id}",
                op.slug
            )));
        };
        let full = op.dir.join(&rec.path);
        if std::path::Path::new(&rec.path).is_absolute() || !full.is_file() {
            return Err(fail(format!("evidence {id} is missing: {}", rec.path)));
        }
        let actual = Sha256Hex::of_file(&full).map_err(|e| fail(e.to_string()))?;
        if actual.as_str() != rec.sha256 {
            return Err(fail(format!(
                "evidence {id} changed since capture (expected_sha={} actual_sha={}); run 'lcoat evidence verify' before comparing",
                rec.sha256,
                actual.as_str()
            )));
        }
        let bytes = std::fs::read(&full).map_err(|e| fail(e.to_string()))?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !text.contains("<nmaprun") {
            return Err(fail(format!(
                "evidence {id} is not an nmap report (no <nmaprun>)"
            )));
        }
        Ok((rec, text))
    };
    let (rb, tb) = load(before_id)?;
    let (ra, ta) = load(after_id)?;
    let (sb, sa) = (summarize(&tb), summarize(&ta));
    let changes = compare(&sb, &sa);
    let count = |c: &str| changes.iter().filter(|x| x.change == c).count();
    let mut warnings = Vec::new();
    for (id, s) in [(before_id, &sb), (after_id, &sa)] {
        if s.hosts_up == Some(0) {
            warnings.push(format!("{id}: nmap reported the host down (0 hosts up); nothing was tested in that run, so this comparison is not evidence of any change"));
        }
        if s.scanned.is_empty() {
            warnings.push(format!("{id}: no scan coverage recorded (<scaninfo>); ports missing from it are shown as closed, not not-scanned"));
        }
    }
    if rb.target != ra.target {
        warnings.push(format!(
            "the scans name different targets ({} and {}): this compares two vantages or addresses, not one host over time",
            rb.target, ra.target
        ));
    }

    if json {
        let s = |v: &str| Value::String(v.to_owned());
        let side = |r: &evidence::Record| {
            let mut o = Object::new();
            o.insert("id", s(&r.id));
            o.insert("target", s(&r.target));
            o.insert("created_at", s(&r.created_at));
            o.insert("sha256", s(&r.sha256));
            o.insert("vantage", s(&r.vantage));
            o.insert("vantage_addr", s(&r.vantage_addr));
            Value::Object(o)
        };
        let mut o = Object::new();
        o.insert("schema_version", s("lcoat.evidence_diff.v1"));
        o.insert("operation", s(&op.slug));
        o.insert("before", side(&rb));
        o.insert("after", side(&ra));
        o.insert(
            "changes",
            Value::Array(
                changes
                    .iter()
                    .map(|c| {
                        let mut x = Object::new();
                        x.insert("port", s(&c.port));
                        x.insert("change", s(c.change));
                        x.insert("before", s(&c.before));
                        x.insert("after", s(&c.after));
                        Value::Object(x)
                    })
                    .collect(),
            ),
        );
        let mut counts = Object::new();
        for c in [
            "opened",
            "closed",
            "changed",
            "unchanged",
            "not-scanned",
            "first-scanned",
        ] {
            counts.insert(c, Value::Number(count(c).to_string()));
        }
        o.insert("counts", Value::Object(counts));
        o.insert(
            "warnings",
            Value::Array(warnings.iter().map(|w| s(w)).collect()),
        );
        let mut bytes = compact(&Value::Object(o));
        bytes.push(b'\n');
        ctx.raw(&bytes);
        return Ok(());
    }

    let who = |r: &evidence::Record| {
        let mut v = format!("{} target={} captured={}", r.id, r.target, r.created_at);
        if !r.vantage.is_empty() {
            v.push_str(&format!(" vantage={} {}", r.vantage, r.vantage_addr));
        }
        v
    };
    ctx.heading("Scan Comparison");
    ctx.rule();
    ctx.kv("Operation", &op.name);
    ctx.kv("Before", &who(&rb));
    ctx.kv("After", &who(&ra));
    ctx.rule();
    if changes.is_empty() {
        ctx.note("no open ports in either scan");
    } else {
        ctx.line(&format!(
            "{:<14} {:<12} {:<32} {}",
            "CHANGE", "PORT", "BEFORE", "AFTER"
        ));
        for c in &changes {
            ctx.line(&format!(
                "{:<14} {:<12} {:<32} {}",
                c.change, c.port, c.before, c.after
            ));
        }
    }
    ctx.rule();
    for (label, c) in [
        ("Opened", "opened"),
        ("Closed", "closed"),
        ("Service Changed", "changed"),
        ("Unchanged", "unchanged"),
        ("Not Scanned After", "not-scanned"),
        ("First Scanned After", "first-scanned"),
    ] {
        ctx.kv(label, &count(c).to_string());
    }
    for w in &warnings {
        ctx.line(&format!("warning: {w}"));
    }
    Ok(())
}
