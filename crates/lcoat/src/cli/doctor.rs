//! `lcoat doctor [--json]`: the build, the tools it drives, the lab root
//! and every operation under it, checked before a run instead of
//! discovered during one. Read-only; exit 1 when any row is `fail`.
//!
//! Rows print as the shell build's `atlas doctor` does (label in 24
//! columns, status in 8, detail), closing with `Status`, `Failures` and
//! `Warnings`. The checks themselves are Lab Coat's own: see
//! `lcoat_core::doctor`.

use lcoat_core::doctor::{self, Report, Status};
use lcoat_format::canonical::compact;
use lcoat_format::json::{Object, Value};

use super::args::{Kind, Spec, parse};
use super::{CliError, CmdResult, Ctx};

/// Tools the adapters drive (Tier 0-2 nmap; the script adapter runs
/// whatever the operator names, so there is nothing fixed to check).
const SECTION_TOOLS: &str = "Tools";

/// `doctor [--json]`.
pub fn run(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    let json = parse(
        &Spec::new("doctor [--json]", 0, Some(0)).flags(&[("--json", Kind::Switch)]),
        args,
    )?
    .has("--json");

    let euid = doctor::effective_uid();
    let mut report = doctor::check(euid);
    tools(&mut report, euid);
    // Print order: root, layout, records, operations, tools, clock.
    let order = [
        doctor::SECTION_ROOT,
        doctor::SECTION_LAYOUT,
        doctor::SECTION_RECORDS,
        doctor::SECTION_OPERATIONS,
        SECTION_TOOLS,
        doctor::SECTION_CLOCK,
    ];
    report.checks.sort_by_key(|c| {
        order
            .iter()
            .position(|s| *s == c.section)
            .unwrap_or(order.len())
    });

    let attention = report.failures() > 0;
    if json {
        emit_json(ctx, &report, euid);
    } else {
        emit_text(ctx, &report, euid, &order);
    }
    if attention {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}

fn commit() -> &'static str {
    env!("LCOAT_BUILD_COMMIT")
}

fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn adapters_built() -> bool {
    cfg!(feature = "adapters")
}

#[cfg(feature = "adapters")]
fn tools(r: &mut Report, euid: Option<u32>) {
    use lcoat_adapters::runner::{SCRUBBED_PATH, look_path, look_path_elsewhere, tool_version};
    match look_path("nmap") {
        Ok(p) => {
            let version = tool_version(&p).unwrap_or_else(|| "version unknown".to_owned());
            r.push(SECTION_TOOLS, "nmap", Status::Ok, format!("{} ({version})", p.display()));
        }
        Err(_) => match look_path_elsewhere("nmap") {
            Some(p) => r.push(
                SECTION_TOOLS,
                "nmap",
                Status::Fail,
                format!(
                    "found at {}, but adapter runs only look in {SCRUBBED_PATH}",
                    p.display()
                ),
            ),
            None => r.push(
                SECTION_TOOLS,
                "nmap",
                Status::Fail,
                "not installed; 'adapter run nmap' needs it (Debian/Parrot: sudo apt install nmap; Fedora: sudo dnf install nmap)",
            ),
        },
    }
    let detail = match euid {
        Some(0) => "root: nmap may use raw-socket scans and ping discovery".to_owned(),
        Some(uid) => format!(
            "uid {uid}, unprivileged: nmap uses TCP connect scans, and a filtered host can look down; add -Pn if it does"
        ),
        None => "unknown on this platform; without root nmap uses TCP connect scans".to_owned(),
    };
    r.push(SECTION_TOOLS, "privileges", Status::Ok, detail);
}

#[cfg(not(feature = "adapters"))]
fn tools(r: &mut Report, _euid: Option<u32>) {
    r.push(
        SECTION_TOOLS,
        "adapters",
        Status::Ok,
        "not in this build: it verifies records but cannot run tools",
    );
}

fn row(ctx: &mut Ctx<'_>, label: &str, status: &str, detail: &str) {
    ctx.line(&format!("{label:<24} {status:<8} {detail}"));
}

fn emit_text(ctx: &mut Ctx<'_>, report: &Report, euid: Option<u32>, order: &[&str]) {
    ctx.heading("Lab Coat Doctor");
    ctx.rule();
    ctx.kv(
        "Version",
        &format!("{} (commit {})", env!("CARGO_PKG_VERSION"), commit()),
    );
    ctx.kv("Platform", &platform());
    ctx.kv(
        "Adapters",
        if adapters_built() {
            "built in"
        } else {
            "not built (verify-only binary)"
        },
    );
    ctx.kv(
        "User",
        &euid.map_or_else(|| "unknown".to_owned(), |u| format!("uid {u}")),
    );
    ctx.rule();
    for section in order {
        let rows: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.section == *section)
            .collect();
        if rows.is_empty() {
            continue;
        }
        ctx.heading(section);
        for c in rows {
            row(ctx, &c.label, c.status.word(), &c.detail);
        }
        ctx.rule();
    }
    if report.failures() > 0 {
        ctx.kv("Status", "attention required");
        ctx.kv("Failures", &report.failures().to_string());
    } else {
        ctx.kv("Status", "ok");
    }
    ctx.kv("Warnings", &report.warnings().to_string());
}

fn emit_json(ctx: &mut Ctx<'_>, report: &Report, euid: Option<u32>) {
    let s = |v: &str| Value::String(v.to_owned());
    let n = |v: usize| Value::Number(v.to_string());
    let mut o = Object::new();
    o.insert("schema_version", s("lcoat.doctor.v1"));
    o.insert("version", s(env!("CARGO_PKG_VERSION")));
    o.insert("commit", s(commit()));
    o.insert("platform", s(&platform()));
    o.insert("adapters", Value::Bool(adapters_built()));
    o.insert(
        "uid",
        euid.map_or(Value::Null, |u| Value::Number(u.to_string())),
    );
    o.insert(
        "status",
        s(if report.failures() > 0 {
            "attention-required"
        } else {
            "ok"
        }),
    );
    o.insert("failures", n(report.failures()));
    o.insert("warnings", n(report.warnings()));
    o.insert(
        "checks",
        Value::Array(
            report
                .checks
                .iter()
                .map(|c| {
                    let mut row = Object::new();
                    row.insert("section", s(c.section));
                    row.insert("label", s(&c.label));
                    row.insert("status", s(c.status.word()));
                    row.insert("detail", s(&c.detail));
                    Value::Object(row)
                })
                .collect(),
        ),
    );
    let mut bytes = compact(&Value::Object(o));
    bytes.push(b'\n');
    ctx.raw(&bytes);
}
