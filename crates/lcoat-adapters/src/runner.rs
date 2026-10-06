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
    /// Streams cut at [`MAX_CAPTURE_BYTES`] (`"stdout"`, `"stderr"`).
    truncated: Vec<&'static str>,
    /// A stream was still open after the run's process group was killed
    /// (a descendant that left the group kept it): what arrived is kept, but
    /// the output may be incomplete.
    incomplete: bool,
}

/// Most bytes kept per stream. The rest is read and dropped (so the child
/// never blocks on a full pipe) and the capture ends with a marker line.
pub const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

/// How long to wait for the pipes to close once the run's processes are gone.
const PIPE_GRACE: Duration = Duration::from_secs(2);

/// One pipe drained into a buffer the runner can take at any time.
struct Drain {
    buf: std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>,
    eof: std::sync::mpsc::Receiver<()>,
}

impl Drain {
    fn start(pipe: Option<Box<dyn Read + Send>>, cap: usize) -> Self {
        let buf = std::sync::Arc::new(std::sync::Mutex::new((Vec::new(), false)));
        let (tx, eof) = std::sync::mpsc::channel();
        let shared = std::sync::Arc::clone(&buf);
        std::thread::spawn(move || {
            if let Some(mut p) = pipe {
                let mut chunk = [0u8; 64 * 1024];
                loop {
                    match p.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            let Ok(mut g) = shared.lock() else { break };
                            let room = cap.saturating_sub(g.0.len());
                            g.0.extend_from_slice(&chunk[..n.min(room)]);
                            if n > room {
                                g.1 = true;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
            let _ = tx.send(());
        });
        Self { buf, eof }
    }

    /// Wait up to `grace` for end of file, then take what arrived:
    /// `(bytes, truncated, reached_eof)`.
    fn take(self, grace: Duration) -> (Vec<u8>, bool, bool) {
        let done = self.eof.recv_timeout(grace).is_ok();
        let mut g = match self.buf.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        (std::mem::take(&mut g.0), g.1, done)
    }
}

/// SIGKILL every process in group `pgid` (best effort; the direct child is
/// also killed through its handle). Std has no `killpg`, and the workspace
/// forbids `unsafe`, so this runs the system `kill`, found on the scrubbed
/// PATH, with a negative pid.
fn kill_group(pgid: u32) {
    if let Ok(kill) = look_path("kill") {
        let _ = Command::new(kill)
            .args(["-9", "--", &format!("-{pgid}")])
            .env_clear()
            .env("PATH", SCRUBBED_PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Run argv directly (never via a shell) with a scrubbed environment, stdin
/// closed, a hard timeout, and stdout/stderr captured separately.
///
/// The child leads a new process group. When it exits or the timeout fires,
/// the whole group is killed, so nothing it started outlives the run (a
/// script's background `sleep`, a tool's helper) or holds the pipes open.
fn execute(argv: &[String], timeout: Duration) -> Result<Captured> {
    execute_capped(argv, timeout, MAX_CAPTURE_BYTES)
}

fn execute_capped(argv: &[String], timeout: Duration, cap: usize) -> Result<Captured> {
    use std::os::unix::process::CommandExt;
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
        .process_group(0)
        .spawn()?;
    let pgid = child.id();
    let out = Drain::start(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
        cap,
    );
    let err = Drain::start(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
        cap,
    );
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            kill_group(pgid);
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // The leader is gone; whatever it left behind in its group goes too.
    // (The group id cannot name an unrelated process while any member is
    // alive; with none left the kill finds nothing.)
    kill_group(pgid);
    let duration = start.elapsed();
    let (stdout, out_cut, out_eof) = out.take(PIPE_GRACE);
    let (stderr, err_cut, err_eof) = err.take(PIPE_GRACE);
    let mut truncated = Vec::new();
    if out_cut {
        truncated.push("stdout");
    }
    if err_cut {
        truncated.push("stderr");
    }
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
        duration,
        truncated,
        incomplete: !(out_eof && err_eof),
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
    let marker = |stream: &str| {
        format!("\n--- lcoat: {stream} truncated after {MAX_CAPTURE_BYTES} bytes ---\n")
    };
    let mut body = captured.stdout.clone();
    if captured.truncated.contains(&"stdout") {
        body.extend_from_slice(marker("stdout").as_bytes());
    }
    if !captured.stderr.is_empty() {
        body.extend_from_slice(b"\n--- stderr ---\n");
        body.extend_from_slice(&captured.stderr);
        if captured.truncated.contains(&"stderr") {
            body.extend_from_slice(marker("stderr").as_bytes());
        }
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

    let status = if captured.exit_code == 0 && !captured.timed_out && !captured.incomplete {
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
    for stream in &captured.truncated {
        detail.push_str(&format!(" truncated={stream}"));
    }
    if captured.incomplete {
        detail.push_str(" output=incomplete");
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

    fn argv(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Running, as opposed to gone or a zombie waiting for init to reap it
    /// (`kill -0` succeeds on a zombie).
    fn alive(pid: &str) -> bool {
        Command::new("ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .map(|o| {
                let stat = String::from_utf8_lossy(&o.stdout).trim().to_owned();
                !stat.is_empty() && !stat.starts_with('Z')
            })
            .unwrap_or(false)
    }

    /// Review 2026-10-05: the timeout killed only the direct child, so a
    /// script's background `sleep` survived the run.
    #[test]
    fn the_timeout_kills_the_whole_process_group() {
        let c = execute(
            &argv(&["/bin/sh", "-c", "sleep 30 & echo $!; exec sleep 30"]),
            Duration::from_millis(300),
        )
        .unwrap();
        assert!(c.timed_out);
        assert!(c.duration < Duration::from_secs(5), "{:?}", c.duration);
        let pid = String::from_utf8_lossy(&c.stdout).trim().to_owned();
        assert!(!pid.is_empty());
        std::thread::sleep(Duration::from_millis(100));
        assert!(!alive(&pid), "background child {pid} outlived the run");
    }

    /// Review 2026-10-05: a grandchild holding the pipe made the evidence
    /// empty (after a 30 s wait) while the run reported `ok`.
    #[test]
    fn a_background_child_cannot_hold_the_output_hostage() {
        let c = execute(
            &argv(&["/bin/sh", "-c", "sleep 30 & echo $!; echo done"]),
            Duration::from_secs(20),
        )
        .unwrap();
        assert!(!c.timed_out);
        assert_eq!(c.exit_code, 0);
        assert!(!c.incomplete);
        assert!(c.duration < Duration::from_secs(5), "{:?}", c.duration);
        let out = String::from_utf8_lossy(&c.stdout).into_owned();
        let mut lines = out.lines();
        let pid = lines.next().unwrap().to_owned();
        assert_eq!(lines.next(), Some("done"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!alive(&pid), "background child {pid} outlived the run");
    }

    /// A descendant that leaves the group keeps the pipe open: the run ends
    /// anyway, keeps what arrived, and says the output may be incomplete.
    #[test]
    fn output_from_an_escaped_descendant_is_flagged_incomplete() {
        let Ok(setsid) = look_path("setsid") else {
            return; // no setsid(1) here (macOS); the other tests cover the rest
        };
        // setsid(1) execs in place when it is not a group leader, so `$!` is
        // the escaped sleep itself.
        let script = format!("{} sleep 30 & echo $!", setsid.display());
        let c = execute(&argv(&["/bin/sh", "-c", &script]), Duration::from_secs(20)).unwrap();
        let pid = String::from_utf8_lossy(&c.stdout).trim().to_owned();
        let _ = Command::new("kill").args(["-9", &pid]).status();
        assert!(c.incomplete);
        assert!(!pid.is_empty());
        assert!(c.duration < Duration::from_secs(5), "{:?}", c.duration);
    }

    /// Review 2026-10-05: captured output had no size limit.
    #[test]
    fn captured_output_is_capped_and_says_so() {
        let c = execute_capped(
            &argv(&["/bin/sh", "-c", "printf 0123456789abcdef; printf xyz >&2"]),
            Duration::from_secs(5),
            10,
        )
        .unwrap();
        assert_eq!(c.stdout, b"0123456789");
        assert_eq!(c.stderr, b"xyz");
        assert_eq!(c.truncated, ["stdout"]);
        assert!(!c.incomplete);
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
