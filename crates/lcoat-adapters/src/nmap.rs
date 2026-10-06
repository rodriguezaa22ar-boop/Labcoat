//! The nmap adapter: typed arguments, tier from the arguments, XML parsed
//! into proposed findings.
//!
//! The operator supplies flags only; the target address comes from the
//! [`ScopedTarget`]. Every accepted flag is a variant of [`NmapArg`], so
//! `-iL`, `-iR`, `-o*`, `--script` outside the safe categories, spoofing and
//! evasion options, and bare positionals are all parse errors, not
//! allowlist misses. The tier is derived: a host-discovery sweep (`-sn` with
//! timing and verbosity only) is Tier 1; anything else that parses is
//! Tier 2. Nothing here can parse to Tier 3 or above.

use std::time::Duration;

use lcoat_core::error::Result;
use lcoat_core::fail;
use lcoat_core::scope::ScopedTarget;
use lcoat_core::tier::Tier;

use crate::{Adapter, ProposedFinding, RunWarning};

/// nmap, as Lab Coat runs it.
pub struct Nmap;

/// One accepted nmap argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NmapArg {
    /// A flag that takes no value: `-sn`, `-sV`, `-Pn`, `-T4`, `--open`, ...
    Bare(BareFlag),
    /// `--top-ports N`
    TopPorts(u32),
    /// `--version-intensity 0..=9`
    VersionIntensity(u8),
    /// `--max-retries N`
    MaxRetries(u32),
    /// `--max-rate N`
    MaxRate(u32),
    /// `--host-timeout <n>[ms|s|m|h]`
    HostTimeout(String),
    /// `--exclude-ports <spec>`
    ExcludePorts(String),
    /// `--script <categories>`: `default`, `safe`, `discovery`, `version` only.
    Script(Vec<ScriptCategory>),
    /// `-p <spec>`
    Ports(String),
}

/// Flags that take no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum BareFlag {
    Sn,
    Ss,
    St,
    Su,
    Sv,
    Sc,
    A,
    O,
    F,
    R,
    Pn,
    N,
    Six,
    V,
    Vv,
    Open,
    Reason,
    Traceroute,
    VersionLight,
    VersionAll,
    T0,
    T1,
    T2,
    T3,
    T4,
    T5,
}

impl BareFlag {
    fn parse(a: &str) -> Option<Self> {
        Some(match a {
            "-sn" => Self::Sn,
            "-sS" => Self::Ss,
            "-sT" => Self::St,
            "-sU" => Self::Su,
            "-sV" => Self::Sv,
            "-sC" => Self::Sc,
            "-A" => Self::A,
            "-O" => Self::O,
            "-F" => Self::F,
            "-r" => Self::R,
            "-Pn" => Self::Pn,
            "-n" => Self::N,
            "-6" => Self::Six,
            "-v" => Self::V,
            "-vv" => Self::Vv,
            "--open" => Self::Open,
            "--reason" => Self::Reason,
            "--traceroute" => Self::Traceroute,
            "--version-light" => Self::VersionLight,
            "--version-all" => Self::VersionAll,
            "-T0" => Self::T0,
            "-T1" => Self::T1,
            "-T2" => Self::T2,
            "-T3" => Self::T3,
            "-T4" => Self::T4,
            "-T5" => Self::T5,
            _ => return None,
        })
    }

    /// Flags that may accompany `-sn` without raising it above Tier 1.
    fn passive(self) -> bool {
        matches!(
            self,
            Self::Sn
                | Self::N
                | Self::Six
                | Self::V
                | Self::Vv
                | Self::Reason
                | Self::T0
                | Self::T1
                | Self::T2
                | Self::T3
                | Self::T4
                | Self::T5
        )
    }
}

/// NSE categories that stay at Tier 2. `vuln`, `brute`, `exploit`,
/// `intrusive`, `dos`, `malware`, `external`, `auth`, `broadcast` and named
/// scripts do not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ScriptCategory {
    Default,
    Safe,
    Discovery,
    Version,
}

impl ScriptCategory {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "default" => Self::Default,
            "safe" => Self::Safe,
            "discovery" => Self::Discovery,
            "version" => Self::Version,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Safe => "safe",
            Self::Discovery => "discovery",
            Self::Version => "version",
        }
    }
}

fn positive(v: &str, flag: &str) -> Result<u32> {
    match v.parse::<u32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => fail!("nmap adapter: invalid value for {flag}: {v:?}"),
    }
}

fn non_negative(v: &str, flag: &str) -> Result<u32> {
    match v.parse::<u32>() {
        Ok(n) => Ok(n),
        Err(_) => fail!("nmap adapter: invalid value for {flag}: {v:?}"),
    }
}

/// nmap time specs: digits with an optional `ms`, `s`, `m`, `h` unit.
fn duration(v: &str, flag: &str) -> Result<String> {
    let num = v.trim_end_matches(['s', 'm', 'h']);
    if num.is_empty()
        || v.len() - num.len() > 2
        || !num.bytes().all(|b| b.is_ascii_digit())
        || num.parse::<u64>().is_err()
    {
        fail!("nmap adapter: invalid value for {flag}: {v:?}");
    }
    Ok(v.to_owned())
}

/// Port specs: digits, commas, dashes and `T:`/`U:` prefixes.
fn port_spec(v: &str, flag: &str) -> Result<String> {
    if v.is_empty()
        || !v
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ',' | '-' | ':' | 'T' | 'U'))
    {
        fail!("nmap adapter: invalid value for {flag}: {v:?}");
    }
    Ok(v.to_owned())
}

impl NmapArg {
    /// Parse the operator's arguments. Values may follow the flag or be
    /// joined with `=` (`--top-ports=100`, `-p22`).
    pub fn parse_all(args: &[String]) -> Result<Vec<NmapArg>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if let Some(flag) = BareFlag::parse(a) {
                out.push(NmapArg::Bare(flag));
                i += 1;
                continue;
            }
            let (name, joined): (&str, Option<&str>) = if let Some(rest) = a
                .strip_prefix("-p")
                .filter(|r| !r.is_empty() && !a.starts_with("--"))
            {
                ("-p", Some(rest))
            } else if let Some((k, v)) = a.split_once('=').filter(|_| a.starts_with("--")) {
                (k, Some(v))
            } else {
                (a, None)
            };
            let takes_value = matches!(
                name,
                "--top-ports"
                    | "--version-intensity"
                    | "--max-retries"
                    | "--max-rate"
                    | "--host-timeout"
                    | "--exclude-ports"
                    | "--script"
                    | "-p"
            );
            if !takes_value {
                if !a.starts_with('-') {
                    fail!(
                        "nmap adapter: positional argument {a:?} refused; the target comes from the operation scope"
                    );
                }
                fail!(
                    "nmap adapter: flag {a:?} is not accepted (allowed: scan type, timing, -p, --top-ports, --script default|safe|discovery|version, --open, --reason)"
                );
            }
            let value: &str = match joined {
                Some(v) => v,
                None => {
                    i += 1;
                    match args.get(i) {
                        Some(v) => v.as_str(),
                        None => fail!("nmap adapter: {name} requires a value"),
                    }
                }
            };
            out.push(match name {
                "--top-ports" => NmapArg::TopPorts(positive(value, name)?),
                "--version-intensity" => match value.parse::<u8>() {
                    Ok(n) if n <= 9 => NmapArg::VersionIntensity(n),
                    _ => fail!("nmap adapter: invalid value for {name}: {value:?}"),
                },
                "--max-retries" => NmapArg::MaxRetries(non_negative(value, name)?),
                "--max-rate" => NmapArg::MaxRate(positive(value, name)?),
                "--host-timeout" => NmapArg::HostTimeout(duration(value, name)?),
                "--exclude-ports" => NmapArg::ExcludePorts(port_spec(value, name)?),
                "--script" => {
                    let mut cats = Vec::new();
                    for part in value.split(',') {
                        match ScriptCategory::parse(part) {
                            Some(c) => cats.push(c),
                            None => fail!("nmap adapter: --script category {part:?} is not accepted (default, safe, discovery, version)"),
                        }
                    }
                    if cats.is_empty() {
                        fail!("nmap adapter: invalid value for --script: {value:?}");
                    }
                    NmapArg::Script(cats)
                }
                _ => NmapArg::Ports(port_spec(value, name)?),
            });
            i += 1;
        }
        Ok(out)
    }

    /// The argv form of this argument.
    pub fn argv(&self) -> Vec<String> {
        match self {
            NmapArg::Bare(f) => vec![bare_str(*f).to_owned()],
            NmapArg::TopPorts(n) => vec!["--top-ports".into(), n.to_string()],
            NmapArg::VersionIntensity(n) => vec!["--version-intensity".into(), n.to_string()],
            NmapArg::MaxRetries(n) => vec!["--max-retries".into(), n.to_string()],
            NmapArg::MaxRate(n) => vec!["--max-rate".into(), n.to_string()],
            NmapArg::HostTimeout(v) => vec!["--host-timeout".into(), v.clone()],
            NmapArg::ExcludePorts(v) => vec!["--exclude-ports".into(), v.clone()],
            NmapArg::Script(cats) => vec![
                "--script".into(),
                cats.iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
            NmapArg::Ports(v) => vec!["-p".into(), v.clone()],
        }
    }

    /// Tier of a parsed invocation: `-sn` with passive companions is Tier 1,
    /// everything else Tier 2.
    pub fn tier(args: &[NmapArg]) -> Tier {
        let has_sn = args
            .iter()
            .any(|a| matches!(a, NmapArg::Bare(BareFlag::Sn)));
        let passive = args.iter().all(|a| match a {
            NmapArg::Bare(f) => f.passive(),
            NmapArg::MaxRetries(_) | NmapArg::HostTimeout(_) | NmapArg::MaxRate(_) => true,
            _ => false,
        });
        if has_sn && passive {
            Tier::PassiveRecon
        } else {
            Tier::ActiveRecon
        }
    }
}

fn bare_str(f: BareFlag) -> &'static str {
    match f {
        BareFlag::Sn => "-sn",
        BareFlag::Ss => "-sS",
        BareFlag::St => "-sT",
        BareFlag::Su => "-sU",
        BareFlag::Sv => "-sV",
        BareFlag::Sc => "-sC",
        BareFlag::A => "-A",
        BareFlag::O => "-O",
        BareFlag::F => "-F",
        BareFlag::R => "-r",
        BareFlag::Pn => "-Pn",
        BareFlag::N => "-n",
        BareFlag::Six => "-6",
        BareFlag::V => "-v",
        BareFlag::Vv => "-vv",
        BareFlag::Open => "--open",
        BareFlag::Reason => "--reason",
        BareFlag::Traceroute => "--traceroute",
        BareFlag::VersionLight => "--version-light",
        BareFlag::VersionAll => "--version-all",
        BareFlag::T0 => "-T0",
        BareFlag::T1 => "-T1",
        BareFlag::T2 => "-T2",
        BareFlag::T3 => "-T3",
        BareFlag::T4 => "-T4",
        BareFlag::T5 => "-T5",
    }
}

impl Adapter for Nmap {
    fn name(&self) -> &'static str {
        "nmap"
    }

    fn classify(&self, args: &[String]) -> Result<Tier> {
        Ok(NmapArg::tier(&NmapArg::parse_all(args)?))
    }

    /// `nmap <args> -oX - <address>`: XML on stdout, address last and from
    /// the scope only.
    fn command(&self, target: &ScopedTarget, args: &[String]) -> Result<Vec<String>> {
        let parsed = NmapArg::parse_all(args)?;
        let address = target.address();
        if address.is_empty() || address.starts_with('-') {
            fail!("nmap adapter: invalid target address {address:?}");
        }
        let mut argv = vec!["nmap".to_owned()];
        for a in &parsed {
            argv.extend(a.argv());
        }
        argv.push("-oX".into());
        argv.push("-".into());
        argv.push(address.to_owned());
        Ok(argv)
    }

    fn parse(&self, stdout: &[u8]) -> Vec<ProposedFinding> {
        // Lossy, not strict: one invalid byte in a banner must not hide
        // every other open port (the bad byte becomes U+FFFD).
        let text = String::from_utf8_lossy(stdout);
        open_ports(&text)
            .into_iter()
            .map(|p| {
                let mut title = format!("Open {}/{}", p.protocol, p.port);
                let svc = match (p.service.as_str(), p.product.as_str()) {
                    ("", "") => String::new(),
                    (s, "") => s.to_owned(),
                    (s, prod) => format!("{s} {prod}").trim().to_owned(),
                };
                if !svc.is_empty() {
                    title.push_str(&format!(" ({svc})"));
                }
                ProposedFinding {
                    title,
                    severity: "info",
                    confidence: "high",
                    detail: format!("nmap reported {}/{} open", p.port, p.protocol),
                }
            })
            .collect()
    }

    fn warnings(&self, stdout: &[u8]) -> Vec<RunWarning> {
        let text = String::from_utf8_lossy(stdout);
        match hosts_up(&text) {
            Some(0) => vec![RunWarning {
                code: "host-down",
                message: "nmap reports the host as down (0 hosts up), so no port was tested: this run is not evidence that ports are closed. If the host answers ping, a firewall is rejecting nmap's discovery probes; rerun with -Pn.".into(),
            }],
            None if !text.contains("<nmaprun") => vec![RunWarning {
                code: "no-xml",
                message: "nmap produced no XML report (it may have failed before scanning); check the captured output before trusting this run.".into(),
            }],
            _ => Vec::new(),
        }
    }

    /// Longer than the runner's default: in the field, `-sV` across 1,000
    /// ports took over three minutes.
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }

    fn note(&self) -> &'static str {
        "tier from arguments (-sn → 1, else 2); parses XML into proposed findings"
    }
}

/// One open port from nmap XML.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenPort {
    /// `tcp`/`udp`.
    pub protocol: String,
    /// Port number as printed.
    pub port: String,
    /// `service name=`.
    pub service: String,
    /// `service product=`.
    pub product: String,
}

/// Extract open ports from nmap XML with a small, fuzz-tested tag scanner:
/// `<port protocol=".." portid="..">` elements whose `<state state="open">`
/// child says open, with the optional `<service name=".." product="..">`.
/// Anything malformed is skipped; this never fails.
///
/// The document comes back from the network, and `-sV` service and product
/// strings are chosen by the scanned host. So a port is kept only when its
/// protocol is one nmap emits and its number is a plain decimal in
/// 1..=65535, and the two banner fields are passed through [`banner`]
/// before they can reach a terminal or a finding title.
pub fn open_ports(xml: &str) -> Vec<OpenPort> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<port ") {
        let after = &rest[start..];
        let end = after
            .find("</port>")
            .map(|e| e + "</port>".len())
            .unwrap_or(after.len());
        let element = &after[..end];
        let head_end = element.find('>').unwrap_or(element.len());
        let head = &element[..head_end];
        let protocol = attr(head, "protocol");
        let port = attr(head, "portid");
        let state = element
            .find("<state ")
            .map(|i| attr(&element[i..], "state"))
            .unwrap_or_default();
        if state == "open" && valid_protocol(&protocol) && valid_port(&port) {
            let (service, product) = match element.find("<service ") {
                Some(i) => {
                    let s = &element[i..];
                    let s = &s[..s.find("/>").or_else(|| s.find('>')).unwrap_or(s.len())];
                    (banner(&attr(s, "name")), banner(&attr(s, "product")))
                }
                None => (String::new(), String::new()),
            };
            out.push(OpenPort {
                protocol,
                port,
                service,
                product,
            });
        }
        rest = &after[end.min(after.len())..];
        if end == 0 {
            break;
        }
    }
    out
}

/// `<runstats><hosts up="N" ...>`: how many hosts nmap considered up, or
/// `None` when the report has no run statistics (cut short, not nmap).
pub fn hosts_up(xml: &str) -> Option<u32> {
    let i = xml.find("<runstats>")?;
    let rest = &xml[i..];
    let j = rest.find("<hosts ")?;
    let head = &rest[j..];
    let head = &head[..head.find('>').unwrap_or(head.len())];
    let up = attr(head, "up");
    if up.is_empty() || !up.bytes().all(|b| b.is_ascii_digit()) || up.len() > 9 {
        return None;
    }
    up.parse().ok()
}

/// What one nmap report says, as metadata: open ports, how many hosts
/// were up, and which ports were probed per protocol (`<scaninfo
/// services="22,80,1000-2000">`), so a comparison can tell "closed" from
/// "never probed".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Open ports (validated, banners defanged).
    pub ports: Vec<OpenPort>,
    /// `<runstats><hosts up=..>`, when present.
    pub hosts_up: Option<u32>,
    /// Per protocol, the probed port ranges (inclusive).
    pub scanned: Vec<(String, Vec<(u32, u32)>)>,
}

impl ScanSummary {
    /// Whether `port`/`protocol` was probed: `None` when the report has no
    /// scan information for that protocol.
    pub fn covers(&self, protocol: &str, port: u32) -> Option<bool> {
        self.scanned
            .iter()
            .find(|(p, _)| p == protocol)
            .map(|(_, ranges)| ranges.iter().any(|(a, b)| (*a..=*b).contains(&port)))
    }
}

/// Summarize an nmap XML report. Never fails; malformed parts are skipped.
pub fn summarize(xml: &str) -> ScanSummary {
    let mut scanned: Vec<(String, Vec<(u32, u32)>)> = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<scaninfo ") {
        let head = &rest[i..];
        let end = head.find('>').unwrap_or(head.len());
        let tag = &head[..end];
        let protocol = attr(tag, "protocol");
        let ranges = parse_services(&attr(tag, "services"));
        if valid_protocol(&protocol) && !ranges.is_empty() {
            match scanned.iter_mut().find(|(p, _)| *p == protocol) {
                Some((_, r)) => r.extend(ranges),
                None => scanned.push((protocol, ranges)),
            }
        }
        rest = &head[end.max(1).min(head.len())..];
    }
    ScanSummary {
        ports: open_ports(xml),
        hosts_up: hosts_up(xml),
        scanned,
    }
}

/// `22,80,1000-2000` into inclusive ranges; anything invalid is dropped.
/// At most 4096 ranges are kept (nmap writes far fewer).
fn parse_services(v: &str) -> Vec<(u32, u32)> {
    let num = |s: &str| -> Option<u32> {
        if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<u32>().ok().filter(|n| *n <= 65_535)
    };
    v.split(',')
        .filter_map(|part| match part.split_once('-') {
            Some((a, b)) => Some((num(a)?, num(b)?)).filter(|(a, b)| a <= b),
            None => num(part).map(|n| (n, n)),
        })
        .take(4096)
        .collect()
}

/// One port's change between two scans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortChange {
    /// `22/tcp`.
    pub port: String,
    /// `opened`, `closed`, `changed`, `unchanged`, `not-scanned` (open
    /// before, not probed after) or `first-scanned` (open after, not
    /// probed before).
    pub change: &'static str,
    /// Service before, or `-`.
    pub before: String,
    /// Service after, or `-`.
    pub after: String,
}

fn label(p: &OpenPort) -> String {
    let s = format!("{} {}", p.service, p.product);
    let s = s.trim();
    if s.is_empty() {
        "open".to_owned()
    } else {
        s.to_owned()
    }
}

/// Port-by-port comparison of two reports, by port number then protocol.
pub fn compare(before: &ScanSummary, after: &ScanSummary) -> Vec<PortChange> {
    let key = |p: &OpenPort| (p.port.parse::<u32>().unwrap_or(0), p.protocol.clone());
    let mut keys: Vec<(u32, String)> = before
        .ports
        .iter()
        .chain(after.ports.iter())
        .map(key)
        .collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .map(|(n, proto)| {
            let find = |s: &ScanSummary| {
                s.ports
                    .iter()
                    .find(|p| key(p) == (n, proto.clone()))
                    .cloned()
            };
            let (b, a) = (find(before), find(after));
            let (change, before_l, after_l) = match (&b, &a) {
                (Some(b), Some(a)) if label(b) == label(a) => ("unchanged", label(b), label(a)),
                (Some(b), Some(a)) => ("changed", label(b), label(a)),
                (Some(b), None) if after.covers(&proto, n) == Some(false) => {
                    ("not-scanned", label(b), "-".to_owned())
                }
                (Some(b), None) => ("closed", label(b), "-".to_owned()),
                (None, Some(a)) if before.covers(&proto, n) == Some(false) => {
                    ("first-scanned", "-".to_owned(), label(a))
                }
                (None, Some(a)) => ("opened", "-".to_owned(), label(a)),
                (None, None) => ("unchanged", "-".to_owned(), "-".to_owned()),
            };
            PortChange {
                port: format!("{n}/{proto}"),
                change,
                before: before_l,
                after: after_l,
            }
        })
        .collect()
}

/// Protocols nmap writes in `<port protocol=..>`.
fn valid_protocol(p: &str) -> bool {
    matches!(p, "tcp" | "udp" | "sctp" | "ip")
}

/// A plain decimal port number in 1..=65535 (no sign, no spaces).
fn valid_port(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 5
        && p.bytes().all(|b| b.is_ascii_digit())
        && p.parse::<u32>().is_ok_and(|n| (1..=65_535).contains(&n))
}

/// Longest banner field kept, in characters.
pub const BANNER_MAX: usize = 128;

/// A service or product string chosen by the scanned host, made safe to
/// print: control characters (C0, DEL, C1, line and paragraph separators),
/// every Unicode format character (Cf: bidirectional overrides, zero-width
/// characters, the soft hyphen, tag characters), variation selectors and
/// noncharacters become `?`, and the result is cut to [`BANNER_MAX`]
/// characters with a trailing `~`.
pub fn banner(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| if unsafe_char(c) { '?' } else { c })
        .collect();
    if out.chars().count() > BANNER_MAX {
        out = out.chars().take(BANNER_MAX - 1).collect();
        out.push('~');
    }
    out
}

fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // General category Cf (Unicode 16), plus the line and paragraph
            // separators.
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
                // Variation selectors: invisible, and used to smuggle data.
                | '\u{180b}'..='\u{180d}'
                | '\u{180f}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{e0100}'..='\u{e01ef}'
                // Noncharacters.
                | '\u{fdd0}'..='\u{fdef}'
        )
        || (c as u32) & 0xfffe == 0xfffe
}

/// The value of `name="..."` in a tag head, with the five XML entities
/// decoded; empty when absent.
fn attr(head: &str, name: &str) -> String {
    let key = format!(" {name}=\"");
    let Some(i) = head.find(&key) else {
        return String::new();
    };
    let v = &head[i + key.len()..];
    let Some(j) = v.find('"') else {
        return String::new();
    };
    v[..j]
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn tiers_follow_the_arguments() {
        let n = Nmap;
        assert_eq!(n.classify(&args(&["-sn"])).unwrap(), Tier::PassiveRecon);
        assert_eq!(
            n.classify(&args(&["-sn", "-T4", "--max-retries", "2"]))
                .unwrap(),
            Tier::PassiveRecon
        );
        assert_eq!(
            n.classify(&args(&["-sn", "-p", "22"])).unwrap(),
            Tier::ActiveRecon
        );
        assert_eq!(
            n.classify(&args(&["-sV", "--top-ports=1000"])).unwrap(),
            Tier::ActiveRecon
        );
        assert_eq!(n.classify(&args(&[])).unwrap(), Tier::ActiveRecon);
        assert_eq!(
            n.classify(&args(&["--script", "default,safe,version"]))
                .unwrap(),
            Tier::ActiveRecon
        );
    }

    #[test]
    fn everything_outside_the_enum_is_refused() {
        let n = Nmap;
        for bad in [
            &["10.0.0.1"][..],
            &["-iL", "hosts.txt"],
            &["-oN", "out.txt"],
            &["--script", "vuln"],
            &["--script", "default,exploit"],
            &["--script=http-shellshock"],
            &["-S", "1.2.3.4"],
            &["-D", "RND:10"],
            &["--top-ports", "0"],
            &["--version-intensity", "10"],
            &["-p", "22;rm"],
            &["--host-timeout", "5x"],
            &["--top-ports"],
            &["600"],
        ] {
            let err = n.classify(&args(bad)).unwrap_err().to_string();
            assert!(err.starts_with("nmap adapter:"), "{bad:?} -> {err}");
        }
        assert!(
            n.classify(&args(&["600"]))
                .unwrap_err()
                .to_string()
                .contains("positional argument")
        );
    }

    #[test]
    fn command_puts_the_scoped_address_last() {
        let t = ScopedTarget::new_for_test("node", "10.10.10.5", Tier::ActiveRecon);
        let argv = Nmap
            .command(
                &t,
                &args(&["-sV", "--top-ports=100", "-p22,80", "--script", "safe"]),
            )
            .unwrap();
        assert_eq!(
            argv,
            [
                "nmap",
                "-sV",
                "--top-ports",
                "100",
                "-p",
                "22,80",
                "--script",
                "safe",
                "-oX",
                "-",
                "10.10.10.5"
            ]
        );
    }

    /// Field run 1: from a NAT'd VM, firewalld rejected nmap's unprivileged
    /// discovery probes, nmap reported 0 hosts up in 80 ms, and the run
    /// printed "no proposed findings" like a clean result.
    #[test]
    fn host_down_is_a_warning_not_a_clean_result() {
        let down = r#"<?xml version="1.0"?><nmaprun scanner="nmap"><runstats><finished time="1791097585" summary="Nmap done at Sun Oct 4 07:06:25 2026; 1 IP address (0 hosts up) scanned in 0.08 seconds" elapsed="0.08"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>"#;
        assert_eq!(hosts_up(down), Some(0));
        let w = Nmap.warnings(down.as_bytes());
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].code, "host-down");
        assert!(w[0].message.contains("-Pn"));
        let up = down.replace(r#"up="0" down="1""#, r#"up="1" down="0""#);
        assert_eq!(hosts_up(&up), Some(1));
        assert!(Nmap.warnings(up.as_bytes()).is_empty());
        // No XML at all (nmap failed before writing a report).
        assert_eq!(Nmap.warnings(b"Failed to open device")[0].code, "no-xml");
        // A report cut short before run statistics: no claim either way.
        assert!(Nmap.warnings(b"<nmaprun><host>").is_empty());
        assert_eq!(hosts_up(r#"<runstats><hosts up="-1"/></runstats>"#), None);
    }

    /// Field run 1: three comparisons (LAN vs tailnet, before vs after a
    /// firewall change) were done by eye. A port the second scan never
    /// probed is `not-scanned`, not `closed`.
    #[test]
    fn scans_compare_port_by_port_and_respect_coverage() {
        let report = |services: &str, ports: &[(&str, &str, &str)]| {
            let mut x = format!(
                r#"<nmaprun><scaninfo type="connect" protocol="tcp" numservices="9" services="{services}"/>"#
            );
            for (id, name, product) in ports {
                x.push_str(&format!(r#"<port protocol="tcp" portid="{id}"><state state="open"/><service name="{name}" product="{product}"/></port>"#));
            }
            x.push_str(r#"<runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>"#);
            summarize(&x)
        };
        let before = report(
            "22,80,514,8080",
            &[
                ("22", "ssh", "OpenSSH"),
                ("514", "shell", ""),
                ("8080", "http", "a"),
            ],
        );
        let after = report(
            "22,80,514",
            &[("22", "ssh", "OpenSSH"), ("80", "http", "nginx")],
        );
        assert_eq!(after.covers("tcp", 514), Some(true));
        assert_eq!(after.covers("tcp", 8080), Some(false));
        assert_eq!(after.covers("udp", 53), None);
        let changes: Vec<(String, &str)> = compare(&before, &after)
            .into_iter()
            .map(|c| (c.port, c.change))
            .collect();
        assert_eq!(
            changes,
            vec![
                ("22/tcp".to_owned(), "unchanged"),
                ("80/tcp".to_owned(), "opened"),
                ("514/tcp".to_owned(), "closed"),
                ("8080/tcp".to_owned(), "not-scanned"),
            ]
        );
        let svc = report("1-1024", &[("22", "ssh", "Dropbear")]);
        assert_eq!(compare(&before, &svc)[0].change, "changed");
        assert_eq!(
            parse_services("1-10,x,20,30-25,99999"),
            vec![(1, 10), (20, 20)]
        );
    }

    /// Found by fuzz target `nmap_xml`: the scanned host chooses these
    /// strings, and they used to reach the terminal unchanged.
    /// Review 2026-10-05: the soft hyphen, Arabic and Mongolian format
    /// characters, tag characters and variation selectors passed the
    /// banner filter and could hide or smuggle text in a finding title.
    #[test]
    fn every_format_character_is_defanged() {
        for c in [
            '\u{ad}',
            '\u{61c}',
            '\u{180e}',
            '\u{2064}',
            '\u{206a}',
            '\u{fff9}',
            '\u{e0001}',
            '\u{e0041}',
            '\u{e007f}',
            '\u{fe0f}',
            '\u{e0100}',
            '\u{fdd0}',
            '\u{fffe}',
            '\u{1fffe}',
        ] {
            assert_eq!(banner(&format!("ssh{c}d")), "ssh?d", "U+{:04X}", c as u32);
        }
        assert_eq!(
            banner("OpenSSH 9.6p1 Ubuntu-3ubuntu13"),
            "OpenSSH 9.6p1 Ubuntu-3ubuntu13"
        );
        assert_eq!(
            banner("caf\u{e9} \u{65e5}\u{672c}"),
            "caf\u{e9} \u{65e5}\u{672c}"
        );
    }

    #[test]
    fn hostile_xml_is_validated_and_banners_are_defanged() {
        let port = |proto: &str, id: &str, product: &str| {
            format!(
                r#"<port protocol="{proto}" portid="{id}"><state state="open"/><service name="http" product="{product}"/></port>"#
            )
        };
        // Protocol and port must be what nmap writes.
        for (proto, id) in [
            ("tbp", "22"),
            ("tcp", "v0"),
            ("tcp", "0"),
            ("tcp", "65536"),
            ("tcp", "+22"),
            ("tcp", " 22"),
        ] {
            assert!(
                open_ports(&port(proto, id, "x")).is_empty(),
                "{proto}/{id} accepted"
            );
        }
        assert_eq!(open_ports(&port("sctp", "65535", "x")).len(), 1);
        // An ANSI screen-clear and a fake status line become inert text.
        let p = &open_ports(&port("tcp", "80", "\u{1b}[2J\u{1b}[1;1Hok: all clear"))[0];
        assert_eq!(p.product, "?[2J?[1;1Hok: all clear");
        // Bidi override and line separator.
        let p = &open_ports(&port("tcp", "80", "Apache\u{202e}\u{2028}x"))[0];
        assert_eq!(p.product, "Apache??x");
        // Length is capped.
        let p = &open_ports(&port("tcp", "80", &"A".repeat(5000)))[0];
        assert_eq!(p.product.chars().count(), BANNER_MAX);
        assert!(p.product.ends_with('~'));
        // One invalid byte no longer hides every other finding.
        let mut xml = port("tcp", "22", "Open").into_bytes();
        xml.extend_from_slice(
            b"<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/></port>\xff",
        );
        assert_eq!(Nmap.parse(&xml).len(), 2);
    }

    #[test]
    fn xml_open_ports_become_proposed_findings() {
        let xml = r#"<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port>
<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
<port protocol="tcp" portid="443"><state state="open"/></port>
</ports></host></nmaprun>"#;
        let found = Nmap.parse(xml.as_bytes());
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].title, "Open tcp/22 (ssh OpenSSH)");
        assert_eq!(found[0].detail, "nmap reported 22/tcp open");
        assert_eq!(found[1].title, "Open udp/53 (domain)");
        assert_eq!(found[2].title, "Open tcp/443");
        assert!(Nmap.parse(b"not xml").is_empty());
        assert!(Nmap.parse(b"<port <port <state state=\"open\"").is_empty());
        assert_eq!(attr(r#"<x a="1 &amp; 2""#, "a"), "1 & 2");
    }
}
