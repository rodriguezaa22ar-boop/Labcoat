//! The adapter runner: classify, refuse above the ceiling, preflight, run
//! with a scrubbed environment and a hard timeout, capture output as
//! evidence, record both ledger events.
//!
//! Order of events, which the audit packet makes visible:
//!
//! 1. `adapter.refused` (Tier 4/5, before any preflight) — or —
//! 2. `scope.preflight` (allowed/denied; denied stops here),
//! 3. `adapter.started` with the vantage,
//! 4. `artifact.created` for the captured output,
//! 5. `adapter.finished` with exit code, duration, evidence id and hash.
//!
//! A capture that fails still closes the run with `adapter.finished`
//! (`status=error`, `evidence=none`), so the ledger never shows a run that
//! began and vanished.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lcoat_core::error::Result;
use lcoat_core::evidence::{self, AddParams, KIND_ADAPTER_OUTPUT};
use lcoat_core::fail;
use lcoat_core::metadata::MetadataOnly;
use lcoat_core::operation::{Active, Operation};
use lcoat_core::scope::ScopedTarget;
use lcoat_core::tier::Tier;
use lcoat_format::fsutil::{mkdir_private, write_private};

use crate::{Adapter, ProposedFinding, RunWarning, lookup, vantage};

/// Inputs to [`run`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunParams {
    /// `nmap` or `script`.
    pub adapter: String,
    /// Target identifier (name, label or address); the operation's target
    /// when empty.
    pub target: String,
    /// Tool arguments.
    pub args: Vec<String>,
    /// Hard timeout; the adapter's default when `None`.
    pub timeout: Option<Duration>,
}

/// The result of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Adapter name.
    pub adapter: &'static str,
    /// Tier the run was classified at.
    pub tier: Tier,
    /// The argv executed (resolved tool path first).
    pub argv: Vec<String>,
    /// Exit code; `-1` when killed by the timeout or a signal.
    pub exit_code: i32,
    /// Wall-clock duration.
    pub duration_ms: u128,
    /// Whether the timeout fired.
    pub timed_out: bool,
    /// Evidence ID of the captured output.
    pub evidence_id: String,
    /// sha256 of the captured output.
    pub sha256: String,
    /// Hostname the run happened on.
    pub vantage: String,
    /// Source address the run used.
    pub vantage_addr: String,
    /// Findings the adapter proposes.
    pub proposed: Vec<ProposedFinding>,
    /// Coverage warnings (e.g. nmap saw the host as down).
    pub warnings: Vec<RunWarning>,
}

/// The only PATH a tool sees.
pub const SCRUBBED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Resolve a tool against [`SCRUBBED_PATH`] (not the caller's PATH), or
/// check it directly when it contains a slash.
pub fn look_path(name: &str) -> Result<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        if is_executable(&p) {
            return Ok(p);
        }
        fail!("tool not found or not executable: {name}");
    }
    for dir in SCRUBBED_PATH.split(':') {
        let p = Path::new(dir).join(name);
        if is_executable(&p) {
            return Ok(p);
        }
    }
    fail!("tool {name:?} not found in {SCRUBBED_PATH}; install it or pass an absolute path")
}

/// Where `name` would be found outside [`SCRUBBED_PATH`]: on the caller's
/// `PATH`, or in Homebrew's prefixes. For `lcoat doctor`, to say "installed,
/// but where Lab Coat does not look" instead of "not installed".
pub fn look_path_elsewhere(name: &str) -> Option<PathBuf> {
    let caller = std::env::var("PATH").unwrap_or_default();
    caller
        .split(':')
        .chain(["/opt/homebrew/bin", "/opt/homebrew/sbin"])
        .filter(|d| !d.is_empty() && !SCRUBBED_PATH.split(':').any(|s| s == *d))
        .map(|d| Path::new(d).join(name))
        .find(|p| is_executable(p))
}

/// The first line of `<tool> --version`, run like an adapter run (argv
/// only, scrubbed environment, stdin closed) with a short timeout. Asks the
/// tool about itself and contacts nothing. Control characters are replaced
/// so a strange binary cannot write escapes to the terminal.
pub fn tool_version(path: &Path) -> Option<String> {
    let argv = [path.display().to_string(), "--version".to_owned()];
    let out = execute(&argv, Duration::from_secs(5)).ok()?;
    if out.timed_out {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line: String = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())?
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(120)
        .collect();
    Some(line)
}

struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: i32,
    timed_out: bool,
    duration: Duration,
}

/// Run argv directly (never via a shell) with a scrubbed environment, stdin
/// closed, a hard timeout, and stdout/stderr captured separately.
fn execute(argv: &[String], timeout: Duration) -> Result<Captured> {
    let Some((program, rest)) = argv.split_first() else {
        fail!("adapter produced an empty command");
    };
    let start = Instant::now();
    let mut child = Command::new(program)
        .args(rest)
        .env_clear()
        .env("PATH", SCRUBBED_PATH)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Readers hand their buffers back over channels so a grandchild that
    // inherited the pipes (and survives the kill) cannot hang the run: after
    // the timeout we take what arrived within a grace period.
    let read_pipe = |mut pipe: Option<Box<dyn Read + Send>>| {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = pipe.as_mut() {
                let _ = p.read_to_end(&mut buf);
            }
            let _ = tx.send(buf);
        });
        rx
    };
    let out_rx = read_pipe(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err_rx = read_pipe(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let grace = if timed_out {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(30)
    };
    let stdout = out_rx.recv_timeout(grace).unwrap_or_default();
    let stderr = err_rx.recv_timeout(grace).unwrap_or_default();
    let exit_code = if timed_out {
        -1
    } else {
        status.code().unwrap_or(-1)
    };
    Ok(Captured {
        stdout,
        stderr,
        exit_code,
        timed_out,
        duration: start.elapsed(),
    })
}

fn meta(s: String) -> Result<MetadataOnly> {
    MetadataOnly::scan(&s)
        .map_err(|e| lcoat_core::error::Error::user(format!("refusing to record: {e}")))
}

/// Classify, preflight, execute, capture, record. See the module docs for
/// the event order.
pub fn run(op: &Operation<Active>, p: &RunParams) -> Result<Outcome> {
    let Some(adapter) = lookup(&p.adapter) else {
        if p.adapter == "metasploit" {
            fail!("adapter 'metasploit' is refused: exploit modules are Tier 4 or above");
        }
        fail!("unknown adapter: {}", p.adapter);
    };
    let adapter: Box<dyn Adapter> = adapter;
    let name = adapter.name();
    let tier = adapter.classify(&p.args)?;
    // One lock for the whole run, refusal included: preflight, start,
    // execution, capture and finish are one transaction in the ledger, and
    // `op close` cannot slip in between them (review 2026-10-05). Other
    // mutating commands in this operation wait, and say they are waiting.
    let lock = op.lock()?;
    let target = if p.target.is_empty() {
        op.target.clone()
    } else {
        p.target.clone()
    };

    if !tier.executable() {
        op.append_event(
            "adapter.refused",
            tier,
            name,
            "denied",
            &meta(format!(
                "adapter={name} tier={} reason=above-ceiling",
                tier as u8
            ))?,
        )?;
        fail!(
            "adapter {name} classified as {tier}; Lab Coat refuses anything above {}",
            lcoat_core::tier::MAX_EXECUTABLE_TIER
        );
    }

    // The preflight records allowed/denied and is the only source of a ScopedTarget.
    let scoped: ScopedTarget =
        op.scoped_target(tier, name, &target, &format!("run adapter {name}"))?;
    let mut argv = adapter.command(&scoped, &p.args)?;
    let resolved = look_path(&argv[0])?;
    argv[0] = resolved.display().to_string();

    let host = vantage::hostname();
    let addr = vantage::source_address(scoped.address());
    op.append_event(
        "adapter.started",
        tier,
        name,
        "ok",
        &meta(format!(
            "adapter={name} tier={} target={target} vantage={host} vantage_addr={addr}",
            tier as u8
        ))?,
    )?;

    // From here on every failure still closes the run in the ledger, so an
    // `adapter.started` is never left without its `adapter.finished`.
    let finish_failed = |exit: i32, reason: &str| -> Result<()> {
        op.append_event(
            "adapter.finished",
            tier,
            name,
            "error",
            &meta(format!(
                "adapter={name} exit={exit} evidence=none reason={reason}"
            ))?,
        )
    };

    let timeout = p.timeout.unwrap_or_else(|| adapter.default_timeout());
    let captured = match execute(&argv, timeout) {
        Ok(c) => c,
        Err(e) => {
            finish_failed(-1, "spawn-failed")?;
            return Err(e);
        }
    };

    // Capture whatever came back, inside the operation's tmp/ (never /tmp),
    // in a directory no other run shares; the file name is what the
    // evidence record keeps, so it stays `<adapter>-output.txt`.
    let tmp = op
        .dir
        .join("tmp")
        .join(format!("run-{}", std::process::id()));
    let capture = tmp.join(format!("{name}-output.txt"));
    let mut body = captured.stdout.clone();
    if !captured.stderr.is_empty() {
        body.extend_from_slice(b"\n--- stderr ---\n");
        body.extend_from_slice(&captured.stderr);
    }
    if let Err(e) = mkdir_private(&tmp).and_then(|()| write_private(&capture, &body)) {
        finish_failed(captured.exit_code, "capture-failed")?;
        return Err(e.into());
    }
    let added = evidence::add_locked(
        op,
        &AddParams {
            source: capture.clone(),
            kind: Some(meta(KIND_ADAPTER_OUTPUT.to_owned())?),
            target: Some(meta(target.clone())?),
            classification: Some(meta("internal".to_owned())?),
            redacted: false,
            tool: name.to_owned(),
            vantage: Some((meta(host.clone())?, meta(addr.clone())?)),
        },
        &lock,
    );
    let _ = std::fs::remove_file(&capture);
    let _ = std::fs::remove_dir(&tmp);
    let rec = match added {
        Ok(r) => r,
        Err(e) => {
            finish_failed(captured.exit_code, "capture-failed")?;
            return Err(e);
        }
    };

    let status = if captured.exit_code == 0 && !captured.timed_out {
        "ok"
    } else {
        "error"
    };
    let mut detail = format!(
        "adapter={name} exit={} duration_ms={} evidence={} sha256={}",
        captured.exit_code,
        captured.duration.as_millis(),
        rec.id,
        rec.sha256
    );
    if captured.timed_out {
        detail.push_str(&format!(" timeout_s={}", timeout.as_secs()));
    }
    let warnings = adapter.warnings(&captured.stdout);
    for w in &warnings {
        detail.push_str(&format!(" warning={}", w.code));
    }
    op.append_event("adapter.finished", tier, name, status, &meta(detail)?)?;

    Ok(Outcome {
        adapter: name,
        tier,
        argv,
        exit_code: captured.exit_code,
        duration_ms: captured.duration.as_millis(),
        timed_out: captured.timed_out,
        evidence_id: rec.id,
        sha256: rec.sha256,
        vantage: host,
        vantage_addr: addr,
        proposed: adapter.parse(&captured.stdout),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_scrubs_the_environment_and_enforces_the_timeout() {
        let argv: Vec<String> = [
            "/bin/sh",
            "-c",
            "echo \"$PATH:$HOME:$SECRET\"; echo err >&2; exit 3",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        // SECRET and HOME from our environment must not reach the child.
        let c = execute(&argv, Duration::from_secs(5)).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&c.stdout).trim(),
            format!("{SCRUBBED_PATH}::")
        );
        assert_eq!(String::from_utf8_lossy(&c.stderr).trim(), "err");
        assert_eq!(c.exit_code, 3);
        assert!(!c.timed_out);
        let slow: Vec<String> = ["/bin/sh", "-c", "sleep 5"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let c = execute(&slow, Duration::from_millis(200)).unwrap();
        assert!(c.timed_out);
        assert_eq!(c.exit_code, -1);
        assert!(c.duration < Duration::from_secs(3));
    }

    #[test]
    fn look_path_uses_the_scrubbed_path_only() {
        assert!(look_path("sh").is_ok());
        assert!(
            look_path("definitely-not-a-tool-xyz")
                .unwrap_err()
                .to_string()
                .contains("not found")
        );
        assert!(look_path("/nonexistent/tool").is_err());
    }
}
