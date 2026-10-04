//! The fuzz targets. Each one feeds untrusted bytes to a parser the way the
//! binary does, and asserts the invariants that make the parser safe to
//! trust: it never panics, it terminates quickly, and what it accepts is
//! well-formed (round-trips, stays in range, cannot smuggle a second record
//! or a control sequence through).
//!
//! The same functions back the cargo-fuzz harness in `fuzz/`, so the
//! invariants are checked identically by both engines.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use lcoat_adapters::Adapter;
use lcoat_adapters::nmap::{Nmap, NmapArg, open_ports};
use lcoat_adapters::script::ScriptArgs;
use lcoat_core::chain::{self, ChainStatus};
use lcoat_core::metadata::{self, MetadataOnly};
use lcoat_core::packet;
use lcoat_core::tier::Tier;
use lcoat_format::canonical::{canonical, compact, pretty_sorted};
use lcoat_format::clock::Utc;
use lcoat_format::envfile;
use lcoat_format::ids::{is_safe_slug, slugify};
use lcoat_format::json::{Object, Value};
use lcoat_format::ndjson;

use crate::engine::{Target, fnv};

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

/// Split an input into argv words on NUL or newline (so the mutator can
/// add and remove whole arguments).
fn words(data: &[u8]) -> Vec<String> {
    text(data)
        .split(['\0', '\n'])
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn shape_of<T, E: std::fmt::Display>(r: &Result<T, E>, ok: impl Fn(&T) -> u64) -> u64 {
    match r {
        Ok(v) => ok(v) << 1,
        // Shape an error by its wording only: words made of letters, so a
        // new kind of error grows the corpus and a new offending value
        // (a number, a flag, a quoted string) does not.
        Err(e) => {
            let msg = e.to_string();
            let words: Vec<&str> = msg
                .split(|c: char| c.is_whitespace() || c == ':' || c == ',')
                .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_alphabetic()))
                .take(10)
                .collect();
            let cut = words.join(" ");
            fnv(cut.as_bytes()) | 1
        }
    }
}

fn is_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

// --- nmap XML ----------------------------------------------------------------

/// `open_ports` and the nmap adapter's finding proposals: the XML comes back
/// from the network (service banners are chosen by the scanned host).
pub fn nmap_xml(data: &[u8]) -> u64 {
    let xml = text(data);
    let ports = open_ports(&xml);
    let elements = xml.matches("<port ").count();
    assert!(
        ports.len() <= elements,
        "more ports ({}) than <port elements ({elements})",
        ports.len()
    );
    for p in &ports {
        // The port number and protocol come from a hostile document; they
        // must be what they claim to be before they reach a terminal or a
        // finding title.
        let n: u32 = p
            .port
            .parse()
            .unwrap_or_else(|_| panic!("non-numeric port accepted: {:?}", p.port));
        assert!((1..=65_535).contains(&n), "port out of range: {n}");
        assert!(
            p.port.bytes().all(|b| b.is_ascii_digit()),
            "port not plain digits: {:?}",
            p.port
        );
        assert!(
            matches!(p.protocol.as_str(), "tcp" | "udp" | "sctp" | "ip"),
            "unexpected protocol accepted: {:?}",
            p.protocol
        );
        for (field, v) in [("service", &p.service), ("product", &p.product)] {
            assert!(
                !v.chars().any(is_control),
                "{field} carries a control or bidi character: {v:?}"
            );
            assert!(v.chars().count() <= 128, "{field} longer than 128 chars");
        }
    }
    let up = lcoat_adapters::nmap::hosts_up(&xml);
    for w in Nmap.warnings(data) {
        assert!(
            matches!(w.code, "host-down" | "no-xml"),
            "unknown warning code {}",
            w.code
        );
        if w.code == "host-down" {
            assert_eq!(up, Some(0));
        }
    }
    let proposed = Nmap.parse(data);
    assert_eq!(proposed.len(), ports.len());
    for f in &proposed {
        assert!(
            !f.title.chars().any(is_control) && !f.detail.chars().any(is_control),
            "proposed finding carries a control character: {:?}",
            f.title
        );
    }
    (ports.len() as u64) << 8 | (elements.min(255) as u64)
}

// --- nmap and script arguments ---------------------------------------------

/// `NmapArg::parse_all`: operator input, but the gate between a typo and an
/// out-of-scope or intrusive scan.
pub fn nmap_args(data: &[u8]) -> u64 {
    let args = words(data);
    let parsed = NmapArg::parse_all(&args);
    if let Ok(list) = &parsed {
        let argv: Vec<String> = list.iter().flat_map(NmapArg::argv).collect();
        // What we pass to nmap must parse back to exactly the same
        // arguments: no value can turn into a flag or a target.
        let again = NmapArg::parse_all(&argv)
            .unwrap_or_else(|e| panic!("argv {argv:?} does not re-parse: {e}"));
        assert_eq!(&again, list, "argv round trip changed the arguments");
        let tier = NmapArg::tier(list);
        assert!(
            matches!(tier, Tier::PassiveRecon | Tier::ActiveRecon),
            "nmap tier outside 1..=2: {tier:?}"
        );
        for a in &argv {
            assert!(!a.contains('\0'), "NUL in argv");
        }
        // Positionals (targets) and file/output flags never survive.
        for w in [
            "-iL",
            "-iR",
            "-oN",
            "-oG",
            "-oA",
            "-oS",
            "-D",
            "-S",
            "--spoof-mac",
            "--resume",
            "--datadir",
            "--script-args",
        ] {
            assert!(
                !argv.iter().any(|a| a == w),
                "forbidden flag {w} in argv {argv:?}"
            );
        }
    }
    shape_of(&parsed, |list| {
        list.iter().fold(list.len() as u64, |h, a| {
            h.wrapping_mul(31) ^ fnv(format!("{:?}", std::mem::discriminant(a)).as_bytes())
        })
    })
}

/// `ScriptArgs::parse`: the declared tier must be 1..=3 whatever the input.
pub fn script_args(data: &[u8]) -> u64 {
    let args = words(data);
    let parsed = ScriptArgs::parse(&args);
    if let Ok(s) = &parsed {
        assert!(
            matches!(
                s.tier,
                Tier::PassiveRecon | Tier::ActiveRecon | Tier::SafeValidation
            ),
            "script tier outside 1..=3"
        );
        assert!(!s.argv.is_empty(), "empty command accepted");
    }
    shape_of(&parsed, |s| {
        s.tier as u64 * 64 + s.argv.len().min(63) as u64
    })
}

// --- JSON, canonical form, NDJSON ---------------------------------------------

/// Strict JSON parser and the three serializations. Receipts, ledgers and
/// every NDJSON index go through this.
pub fn json(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else {
        return 0;
    };
    let parsed = Value::parse(s);
    if let Ok(v) = &parsed {
        for form in [canonical(v), compact(v), pretty_sorted(v)] {
            let out = String::from_utf8(form).expect("serializer emitted invalid UTF-8");
            let back = Value::parse(&out)
                .unwrap_or_else(|e| panic!("serialized form does not re-parse: {e}: {out:?}"));
            // Canonical bytes are the hash input: they must be a fixed point.
            assert_eq!(
                canonical(&back),
                canonical(v),
                "canonical form is not stable"
            );
        }
        let line = canonical(v);
        assert!(
            !line.contains(&b'\n'),
            "canonical form contains a raw newline"
        );
        let _ = metadata::forbidden_paths(v);
    }
    shape_of(&parsed, |v| fnv(&canonical(v)) & 0xffff)
}

/// NDJSON reader used for every index and the ledger; then the ledger
/// helpers on whatever parsed.
pub fn ndjson(data: &[u8]) -> u64 {
    let s = text(data);
    let parsed = ndjson::parse_lines(&s, "fuzz");
    if let Ok(objs) = &parsed {
        let _ = ndjson::latest(objs);
        let _ = chain::verify(objs);
        for o in objs {
            let line = canonical(&Value::Object(o.clone()));
            assert!(!line.contains(&b'\n'));
        }
    }
    shape_of(&parsed, |objs| objs.len().min(255) as u64)
}

/// Hash chain: linking any events then verifying must say Verified; changing
/// any linked event's content must not.
pub fn ledger_chain(data: &[u8]) -> u64 {
    let s = text(data);
    let Ok(objs) = ndjson::parse_lines(&s, "fuzz") else {
        return 0;
    };
    let mut linked: Vec<Object> = Vec::new();
    for o in objs.iter().take(64) {
        let mut o = o.clone();
        o.remove("prev_hash");
        o.remove("event_hash");
        let prev = linked
            .last()
            .and_then(|e| e.get("event_hash"))
            .and_then(Value::as_str)
            .and_then(|h| lcoat_format::hash::Sha256Hex::parse(h).ok());
        linked.push(chain::link(o, prev.as_ref()));
    }
    if linked.is_empty() {
        return 1;
    }
    assert!(
        matches!(chain::verify(&linked), ChainStatus::Verified),
        "a freshly linked chain does not verify"
    );
    // Tamper with one event's content (a field that is not a chain field).
    let i = (fnv(data) as usize) % linked.len();
    let mut tampered = linked.clone();
    tampered[i].insert("fuzz_tamper", Value::String(format!("{i}")));
    assert!(
        matches!(chain::verify(&tampered), ChainStatus::Broken { index, .. } if index == i),
        "tampering event {i} was not reported at {i}"
    );
    linked.len() as u64
}

// --- env files ---------------------------------------------------------------

/// Env-file parser (operation records, scope snapshots, targets, profiles)
/// and the quoting used to write them.
pub fn envfile(data: &[u8]) -> u64 {
    let parsed = envfile::parse(data);
    if let Ok(rec) = &parsed {
        // What we write back must read back identically.
        let bytes = rec.to_bytes();
        let again = envfile::parse(&bytes).unwrap_or_else(|e| {
            panic!(
                "re-serialized record does not parse: {e}: {:?}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert_eq!(&again, rec, "env file round trip changed the record");
    }
    // Any string (an operator's notes, a target name) quoted as one value
    // must come back as that one value and nothing else: no second key.
    let value = text(data);
    let line = format!("NOTES={}\n", envfile::quote(&value));
    let rec = envfile::parse(line.as_bytes())
        .unwrap_or_else(|e| panic!("quoted value does not parse: {e}: {line:?}"));
    assert_eq!(
        rec.keys().count(),
        1,
        "quoted value produced extra keys: {line:?}"
    );
    assert_eq!(rec.get("NOTES"), value, "quoted value did not round-trip");
    shape_of(&parsed, |r| r.keys().count().min(255) as u64)
}

// --- metadata scanner, timestamps, slugs -------------------------------------

/// The forbidden-content scanner that guards every writer.
pub fn metadata_scan(data: &[u8]) -> u64 {
    let s = text(data);
    let r = MetadataOnly::scan(&s);
    let shape = shape_of(&r, |_| 1);
    if let Ok(m) = &r {
        assert_eq!(m.as_str(), s);
        assert!(
            !metadata::value_is_forbidden(&s),
            "scan and value_is_forbidden disagree"
        );
        // Accepted text stays accepted (no state, no order dependence).
        assert!(MetadataOnly::scan(m.as_str()).is_ok());
    }
    let _ = MetadataOnly::scan_key(&s);
    let _ = metadata::key_is_forbidden(&s);
    let _ = lcoat_core::ledger::ledger_value_is_forbidden(&s);
    shape
}

/// RFC 3339 timestamps (approval expiry, ledger times, `LCOAT_NOW`).
pub fn timestamp(data: &[u8]) -> u64 {
    let s = text(data);
    match Utc::parse(&s) {
        Some(t) => {
            // Accepted timestamps are canonical: printing gives the input
            // back, so two spellings of one instant cannot both be on disk.
            assert_eq!(
                t.timestamp(),
                s,
                "timestamp accepted in a non-canonical form"
            );
            assert_eq!(Utc::from_unix(t.unix()), t);
            let _ = (t.compact(), t.date());
            1
        }
        None => 0,
    }
}

/// `parse_expiry`: operator-typed expiries for approvals and accepted risks.
pub fn expiry(data: &[u8]) -> u64 {
    use lcoat_format::clock::{MAX_EXPIRY_SECS, parse_expiry};
    let s = text(data);
    let now = Utc::from_unix(1_790_000_000);
    match parse_expiry(&s, now) {
        Some(t) => {
            assert!(t.unix() <= MAX_EXPIRY_SECS, "expiry past year 9999: {s:?}");
            let printed = t.timestamp();
            assert_eq!(
                Utc::parse(&printed),
                Some(t),
                "expiry does not print canonically"
            );
            if s.ends_with('h') || s.ends_with('d') {
                assert!(
                    t.unix() > now.unix(),
                    "relative expiry not in the future: {s:?}"
                );
            }
            2
        }
        None => 1,
    }
}

/// `slugify`: names become directory and file names under the lab root.
pub fn slug(data: &[u8]) -> u64 {
    let s = text(data);
    let out = slugify(&s);
    assert!(
        out.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')),
        "slug has a character outside [a-z0-9._-]: {out:?}"
    );
    assert!(!out.contains('/') && !out.contains('\\'));
    assert!(!out.starts_with('-') && !out.ends_with('-') && !out.contains("--"));
    assert_eq!(slugify(&out), out, "slugify is not idempotent");
    if is_safe_slug(&out) {
        assert!(
            !out.is_empty() && !out.starts_with('.'),
            "unsafe slug accepted: {out:?}"
        );
        assert!(out.chars().any(|c| c != '.'));
    }
    u64::from(is_safe_slug(&out)) | (out.len().min(64) as u64) << 1
}

// --- packets and receipts ----------------------------------------------------

/// The Markdown packet line readers the verifiers use.
pub fn packet_text(data: &[u8]) -> u64 {
    let s = text(data);
    let mut shape = 0u64;
    for label in [
        "Operation ledger",
        "Latest report",
        "Evidence manifest",
        "Closeout manifest",
        "Audit packet",
    ] {
        if let Some(line) = packet::anchor_line(&s, label) {
            shape += 1;
            assert!(!line.contains('\n'));
            let path = packet::anchor_path(line);
            assert!(!path.contains('`') && line.contains(path));
            for key in ["sha256", "events", "rel", "manifest"] {
                let v = packet::anchor_token(line, key);
                assert!(!v.chars().any(char::is_whitespace));
            }
        }
        let _ = packet::bullet_value(&s, label);
    }
    let _ = packet::field(&s, "Operation ID");
    shape
}

/// Receipt validation (`receipt verify`, `receipt replay` inputs).
pub fn receipt(data: &[u8]) -> u64 {
    let r = lcoat_core::receipt::validate(data);
    shape_of(&r, |v| fnv(format!("{v:?}").as_bytes()) & 0xff)
}

// --- a whole operation directory, tampered ------------------------------------

/// Files of a real closed operation, built once with the library itself.
struct Template {
    /// (root-relative path, original bytes)
    files: Vec<(PathBuf, Vec<u8>)>,
}

fn scratch_base() -> PathBuf {
    std::env::temp_dir().join(format!("lcoat-fuzz-{}", std::process::id()))
}

fn build_template() -> Template {
    use lcoat_core::evidence;
    use lcoat_core::findings;
    use lcoat_core::operation::{NewTarget, Operation, StartParams, add_target};
    use lcoat_core::root::LabRoot;

    let dir = scratch_base().join("template");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("template dir");
    let root = LabRoot::at(&dir).expect("lab root");
    root.ensure_layout().expect("layout");
    add_target(
        &root,
        &NewTarget {
            name: "node".into(),
            address: "10.10.10.5".into(),
            scope_status: "in-scope".into(),
            criticality: "medium".into(),
            ..Default::default()
        },
    )
    .expect("target");
    let (op, _) = Operation::start(
        &root,
        &StartParams {
            name: "fuzz-op".into(),
            target: "node".into(),
            profile: "default".into(),
            ..Default::default()
        },
    )
    .expect("start");
    let src = dir.join("recon.txt");
    std::fs::write(&src, "PORT 22 open ssh\n").expect("artifact");
    let rec = evidence::add(
        &op,
        &evidence::AddParams {
            source: src,
            kind: None,
            target: None,
            classification: None,
            redacted: false,
            tool: String::new(),
            vantage: None,
        },
    )
    .expect("evidence");
    let f = findings::add(
        &op,
        &findings::AddParams {
            title: Some(MetadataOnly::scan("SSH exposed").expect("title")),
            evidence: vec![rec.id.clone()],
            ..Default::default()
        },
    )
    .expect("finding");
    findings::resolve(&op, &f.id, &[], None).expect("resolve");
    lcoat_core::report::write(&op, "").expect("report");
    lcoat_core::packet::handoff(&op, "").expect("handoff");
    let closed = op.close("ready", "fuzz").expect("close");
    let c = lcoat_core::packet::closeout(&closed, "").expect("closeout");
    let a = lcoat_core::packet::audit(&closed, &c, "").expect("audit");
    lcoat_core::packet::archive(&closed, &a, "").expect("archive");

    let mut files = Vec::new();
    collect_files(&dir, &dir, &mut files);
    Template { files }
}

fn collect_files(base: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_files(base, &p, out);
        } else if let (Ok(rel), Ok(bytes)) = (p.strip_prefix(base), std::fs::read(&p)) {
            out.push((rel.to_path_buf(), bytes));
        }
    }
}

fn template() -> &'static Template {
    static T: OnceLock<Template> = OnceLock::new();
    T.get_or_init(build_template)
}

/// Every reader and verifier over a lab root where one file was replaced by
/// fuzz bytes: a tampered or corrupted root must produce verdicts, never a
/// crash. The first input byte picks the file; the rest is either spliced
/// into the original (odd selector) or replaces it (even).
pub fn op_files(data: &[u8]) -> u64 {
    use lcoat_core::operation::Operation;
    use lcoat_core::root::LabRoot;

    let t = template();
    let Some((&sel, rest)) = data.split_first() else {
        return 0;
    };
    // Every file of the template is a candidate, the evidence artifact and
    // the target and state records included.
    let which = t.files[(sel as usize / 2) % t.files.len()].0.as_path();
    let dir = scratch_base().join("run");
    let _ = std::fs::remove_dir_all(&dir);
    for (rel, bytes) in &t.files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let content = if rel.as_path() == which {
            if sel % 2 == 1 {
                let cut = (fnv(rest) as usize) % (bytes.len() + 1);
                let mut v = bytes[..cut].to_vec();
                v.extend_from_slice(rest);
                v
            } else {
                rest.to_vec()
            }
        } else {
            bytes.clone()
        };
        let _ = std::fs::write(&p, content);
    }
    let Ok(root) = LabRoot::at(&dir) else {
        return 1;
    };
    let mut shape = 2u64;
    let _ = Operation::list(&root);
    if let Ok(op) = Operation::load(&root, "fuzz-op") {
        shape |= 4;
        let _ = op.snapshot();
        let _ = op.events();
        let _ = lcoat_core::readiness::collect(&op).map(|st| st.lines(&op));
        let _ = lcoat_core::packet::collect_trust_chain(&op);
        for kind in ["closeout", "audit", "archive"] {
            if let Ok(p) = lcoat_core::packet::latest_in_ledger(&op, kind) {
                let r = match kind {
                    "closeout" => lcoat_core::packet::closeout_verify(&op, &p),
                    "audit" => lcoat_core::packet::audit_verify(&op, &p),
                    _ => lcoat_core::packet::archive_verify(&op, &p),
                };
                if let Ok(r) = r {
                    shape |= u64::from(r.problems.min(7) as u8) << 4;
                }
            }
        }
        let _ = lcoat_core::evidence::verify_artifacts(&op.dir);
        let _ = lcoat_core::evidence::manifest(&op.dir);
        let _ = lcoat_core::findings::rows(&op.dir, &op.target, 100);
        let _ = lcoat_core::approval::list(&op.dir);
        let _ = lcoat_core::history::read(&op.dir);
        let _ = lcoat_core::ledger::verify_operation_ledger(&lcoat_core::ledger::file(&op.dir));
        if let Ok(objs) = lcoat_core::ledger::read_objects(&lcoat_core::ledger::file(&op.dir)) {
            shape |= match chain::verify(&objs) {
                ChainStatus::Verified => 0x100,
                ChainStatus::Broken { .. } => 0x200,
                ChainStatus::Partial { .. } => 0x400,
                ChainStatus::Unchained => 0x800,
            };
        }
        let _ = op.classify();
    }
    shape | ((sel as u64 / 2) % t.files.len() as u64) << 12
}

// --- registry ------------------------------------------------------------------

fn golden(rel: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/golden")
        .join(rel);
    std::fs::read(p).unwrap_or_default()
}

fn s(v: &[&str]) -> Vec<Vec<u8>> {
    v.iter().map(|x| x.as_bytes().to_vec()).collect()
}

/// Every target.
pub static TARGETS: &[Target] = &[
    Target {
        name: "nmap_xml",
        about: "nmap -oX output from the network: open_ports and proposed findings",
        run: nmap_xml,
        seeds: || {
            let mut v = vec![golden("nmap/sample.xml")];
            v.extend(s(&[
                r#"<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>"#,
                r#"<port protocol="udp" portid="53"><state state="open|filtered"/></port>"#,
                r#"<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="a &amp; b &lt;x&gt;"/></port>"#,
            ]));
            v
        },
        dict: &[
            b"<port ",
            b"</port>",
            b"<state ",
            b"state=\"open\"",
            b"<service ",
            b"name=\"",
            b"product=\"",
            b"protocol=\"tcp\"",
            b"portid=\"",
            b"\"",
            b"/>",
            b">",
            b"&amp;",
            b"&lt;",
            b"&quot;",
            b"&#x1b;",
            b"\x1b[31m",
            b"\n",
            b"65536",
            b"0",
            b"-1",
            b"<host>",
            b"</host>",
            b"<ports>",
            b"<runstats>",
            b"<hosts up=\"0\" down=\"1\"/>",
            b"up=\"",
        ],
        cost: 1,
    },
    Target {
        name: "nmap_args",
        about: "operator nmap arguments: allowlist, tier, argv round trip",
        run: nmap_args,
        seeds: || {
            s(&[
                "-sV\0-p\x0022,80",
                "-sn\0-T4",
                "--script\0safe,discovery\0--top-ports\x00100",
                "-Pn\0-sS\0--max-rate\x0050",
                "-O",
            ])
        },
        dict: &[
            b"\0",
            b"-sV",
            b"-sn",
            b"-sS",
            b"-sU",
            b"-O",
            b"-A",
            b"-p",
            b"--script",
            b"safe",
            b"vuln",
            b"default,safe",
            b"--top-ports",
            b"--max-rate",
            b"--host-timeout",
            b"30s",
            b"-iL",
            b"-oN",
            b"10.0.0.1",
            b"--exclude-ports",
            b"-D",
            b"--script-args",
            b"-T4",
            b"-T5",
            b"-Pn",
            b"1-65535",
            b"--version-intensity",
            b"--max-retries",
            b"=",
            b",",
        ],
        cost: 1,
    },
    Target {
        name: "script_args",
        about: "script adapter: declared tier and command",
        run: script_args,
        seeds: || {
            s(&[
                "--tier\x001\0--\0/usr/bin/uname\0-a",
                "--tier\x003\0/bin/echo\0x",
            ])
        },
        dict: &[
            b"\0", b"--tier", b"1", b"2", b"3", b"4", b"0", b"--", b"/bin/sh", b"-c",
        ],
        cost: 1,
    },
    Target {
        name: "json",
        about: "strict JSON parser and canonical/compact/pretty serializers",
        run: json,
        seeds: || {
            let mut v = s(&[
                r#"{"a":1,"b":[true,false,null],"c":{"d":"e\u0000\n\"\\"}}"#,
                r#"[1e5,-0,0.1,1E-7,"😀"]"#,
                "\"\"",
            ]);
            v.push(golden("demo-site-receipts/demo-site-boundary.json"));
            v
        },
        dict: &[
            b"{", b"}", b"[", b"]", b"\"", b":", b",", b"null", b"true", b"false", b"\\u0000",
            b"\\ud800", b"\\udc00", b"\\\"", b"1e999", b"-0", b"0.0", b"\\n", b"  ",
        ],
        cost: 1,
    },
    Target {
        name: "ndjson",
        about: "NDJSON indexes and ledgers",
        run: ndjson,
        seeds: || {
            vec![
                golden("learning-op-001/ledger.ndjson"),
                golden("learning-op-001/evidence.ndjson"),
            ]
        },
        dict: &[
            b"\n",
            b"{",
            b"}",
            b"\"event\":",
            b"\"prev_hash\":",
            b"\"event_hash\":",
            b"\"id\":",
            b"\r\n",
        ],
        cost: 2,
    },
    Target {
        name: "ledger_chain",
        about: "hash chain: linked events verify; a tampered event is named",
        run: ledger_chain,
        seeds: || vec![golden("learning-op-001/ledger.ndjson")],
        dict: &[
            b"\n",
            b"{\"a\":1}",
            b"\"prev_hash\":null",
            b"\"event_hash\":\"x\"",
        ],
        cost: 4,
    },
    Target {
        name: "envfile",
        about: "env-file parser and printf %q quoting",
        run: envfile,
        seeds: || {
            vec![
                golden("learning-op-001/session.env"),
                golden("learning-op-001/scope.snapshot.env"),
                b"A='x y'\nB=$'tab\\there'\nC=plain\n".to_vec(),
            ]
        },
        dict: &[
            b"=",
            b"'",
            b"$'",
            b"\\'",
            b"\\\\",
            b"\\n",
            b"\\x1b",
            b"\\u00e9",
            b"\\0",
            b"\n",
            b"#",
            b"\"",
            b"KEY=",
            b"STATUS=closed",
            b"\\",
            b"$",
            b"`",
        ],
        cost: 1,
    },
    Target {
        name: "metadata_scan",
        about: "forbidden-content scanner on free text",
        run: metadata_scan,
        seeds: || {
            s(&[
                "SSH exposed on 22",
                "password=hunter2",
                "-----BEGIN RSA PRIVATE KEY-----",
                "AKIAABCDEFGHIJKLMNOP",
                "Bearer abc.def.ghi",
            ])
        },
        dict: &[
            b"password",
            b"=",
            b":",
            b"token",
            b"secret",
            b"BEGIN",
            b"PRIVATE KEY",
            b"AKIA",
            b"ghp_",
            b"Bearer ",
            b"\n",
        ],
        cost: 1,
    },
    Target {
        name: "timestamp",
        about: "RFC 3339 timestamps: strict and canonical",
        run: timestamp,
        seeds: || {
            s(&[
                "2026-10-02T07:40:00Z",
                "1970-01-01T00:00:00Z",
                "9999-12-31T23:59:59Z",
                "2024-02-29T12:00:00Z",
            ])
        },
        dict: &[b"-", b"T", b":", b"Z", b"+", b"0", b"9", b" "],
        cost: 1,
    },
    Target {
        name: "expiry",
        about: "approval and accepted-risk expiries: forms, overflow, year 9999",
        run: expiry,
        seeds: || {
            s(&[
                "90d",
                "12h",
                "2027-01-15",
                "2027-01-15T10:00:00Z",
                "9223372036854775807d",
            ])
        },
        dict: &[
            b"d",
            b"h",
            b"0",
            b"9",
            b"-",
            b"+",
            b"T",
            b"Z",
            b"99999999999",
        ],
        cost: 1,
    },
    Target {
        name: "slug",
        about: "slugify: names that become paths under the lab root",
        run: slug,
        seeds: || s(&["Full Op", "..", ".", "../../etc", "a/b", "ÉCOLE", "-x-"]),
        dict: &[b".", b"/", b"\\", b"-", b"..", b"\0", b"\xc4\xb0"],
        cost: 1,
    },
    Target {
        name: "packet_text",
        about: "Markdown packet anchor readers",
        run: packet_text,
        seeds: || {
            vec![
                golden("learning-op-001/closeout/learning-op-001-closeout.md"),
                golden("learning-op-001/archive/learning-op-001-archive.md"),
            ]
        },
        dict: &[
            b"- Operation ledger: ",
            b"`",
            b" sha256=",
            b" events=",
            b" rel=",
            b"\n",
            b"- Latest report: ",
        ],
        cost: 1,
    },
    Target {
        name: "receipt",
        about: "receipt validation",
        run: receipt,
        seeds: || {
            vec![
                golden("demo-site-receipts/demo-site-boundary.json"),
                golden("demo-site-receipts/demo-site-packet.json"),
                golden("demo-site-receipts/demo-site-replay.json"),
            ]
        },
        dict: &[
            b"\"receipt_hash\"",
            b"\"event_hash\"",
            b"\"prev_hash\"",
            b"\"schema_version\"",
            b"{",
            b"}",
            b"\"",
        ],
        cost: 1,
    },
    Target {
        name: "op_files",
        about: "every reader and verifier over a lab root with one file corrupted",
        run: op_files,
        seeds: || (0..64u8).map(|i| vec![i, b'{', b'}', b'\n']).collect(),
        dict: &[
            b"\n",
            b"{",
            b"}",
            b"\"",
            b"`",
            b"- Operation ledger: ",
            b" sha256=",
            b"STATUS=",
            b"=",
            b"'",
        ],
        cost: 20,
    },
];

/// Look a target up by name.
pub fn find(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|t| t.name == name)
}

/// Remove the scratch directories `op_files` used.
pub fn cleanup() {
    let _ = std::fs::remove_dir_all(scratch_base());
}
