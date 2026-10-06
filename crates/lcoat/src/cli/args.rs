//! One argument parser for every verb.
//!
//! Each verb declares a [`Spec`]: its usage line, the flags it accepts and
//! how many positional arguments it takes. [`parse`] then applies the same
//! rules everywhere, so no verb can silently drop an argument:
//!
//! - flags may come before, between or after positionals, as `--flag value`
//!   or `--flag=value`;
//! - an unknown flag is an error that names it, and so is a positional
//!   beyond what the verb takes, or a single-value flag given twice;
//! - `--` ends the flags: everything after it is positional, so free text
//!   that starts with `--` can still be recorded;
//! - a lone `-` is positional (stdin for the verbs that read one).
//!
//! Review 2026-10-05: `op start t1 node --profile foo` ran with the default
//! profile and recorded `--profile foo` as notes, and read-only verbs
//! ignored flags they did not know (`op status --json` printed text, exit 0).

use super::{CliError, fail};

/// How a flag takes its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// No value (`--force`).
    Switch,
    /// One value, at most once (`--profile p`).
    Value,
    /// One value, any number of times (`--evidence id --evidence id`).
    Many,
}

/// What a verb accepts.
#[derive(Clone, Copy, Debug)]
pub struct Spec {
    /// The usage line, without the leading `lcoat `.
    pub usage: &'static str,
    /// Accepted flags (with their leading `--`); `"--op|--operation"`
    /// declares an alias, reported and looked up under the first name.
    pub flags: &'static [(&'static str, Kind)],
    /// Required positionals.
    pub min: usize,
    /// Most positionals accepted; `None` takes any number (notes, files).
    pub max: Option<usize>,
}

impl Spec {
    /// A spec with no flags and exactly `min..=max` positionals.
    pub const fn new(usage: &'static str, min: usize, max: Option<usize>) -> Self {
        Self {
            usage,
            flags: &[],
            min,
            max,
        }
    }

    /// The same spec accepting `flags`.
    pub const fn flags(mut self, flags: &'static [(&'static str, Kind)]) -> Self {
        self.flags = flags;
        self
    }

    fn usage_error(&self, what: String) -> CliError {
        fail(format!("{what}\nusage: lcoat {}", self.usage))
    }
}

/// Parsed arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Args {
    /// Positionals, in order.
    pub pos: Vec<String>,
    flags: Vec<(&'static str, String)>,
}

impl Args {
    /// Positional `i`, or `""` when absent.
    pub fn pos(&self, i: usize) -> &str {
        self.pos.get(i).map(String::as_str).unwrap_or("")
    }

    /// Positionals from `i` on.
    pub fn rest(&self, i: usize) -> &[String] {
        self.pos.get(i..).unwrap_or(&[])
    }

    /// Whether a switch was given.
    pub fn has(&self, flag: &str) -> bool {
        self.flags.iter().any(|(k, _)| *k == flag)
    }

    /// A single-value flag's value.
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| *k == flag)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of a repeated flag, in order.
    pub fn values(&self, flag: &str) -> Vec<&str> {
        self.flags
            .iter()
            .filter(|(k, _)| *k == flag)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Parse `args` against `spec`.
pub fn parse(spec: &Spec, args: &[String]) -> Result<Args, CliError> {
    let mut out = Args::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            out.pos.extend(args[i + 1..].iter().cloned());
            break;
        }
        if !a.starts_with('-') || a == "-" {
            out.pos.push(a.to_owned());
            i += 1;
            continue;
        }
        let (name, joined) = match a.split_once('=') {
            Some((k, v)) if a.starts_with("--") => (k, Some(v)),
            _ => (a, None),
        };
        let Some(&(names, kind)) = spec
            .flags
            .iter()
            .find(|(f, _)| f.split('|').any(|n| n == name))
        else {
            return Err(spec.usage_error(format!("unknown option: {name}")));
        };
        // An alias is stored under the flag's first name.
        let flag = names.split('|').next().unwrap_or(names);
        let value = match (kind, joined) {
            (Kind::Switch, Some(_)) => {
                return Err(spec.usage_error(format!("{flag} takes no value")));
            }
            (Kind::Switch, None) => String::new(),
            (_, Some(v)) => v.to_owned(),
            (_, None) => {
                i += 1;
                match args.get(i) {
                    Some(v) => v.clone(),
                    None => return Err(spec.usage_error(format!("{flag} requires a value"))),
                }
            }
        };
        if kind != Kind::Many && out.has(flag) {
            return Err(spec.usage_error(format!("{flag} given more than once")));
        }
        out.flags.push((flag, value));
        i += 1;
    }
    if out.pos.len() < spec.min {
        return Err(spec.usage_error("missing argument".to_owned()));
    }
    if let Some(max) = spec.max
        && out.pos.len() > max
    {
        return Err(spec.usage_error(format!("unexpected argument: {}", out.pos[max])));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    const START: Spec = Spec::new(
        "op start [--profile profile] <name> <target> [notes...]",
        2,
        None,
    )
    .flags(&[("--profile", Kind::Value)]);

    fn err(spec: &Spec, a: &[&str]) -> String {
        match parse(spec, &v(a)) {
            Err(CliError::Core(e)) => e.to_string(),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn flags_are_honoured_wherever_they_appear() {
        for a in [
            &["--profile", "p", "n", "t", "notes"][..],
            &["n", "t", "--profile", "p", "notes"],
            &["n", "t", "notes", "--profile=p"],
        ] {
            let p = parse(&START, &v(a)).unwrap();
            assert_eq!(p.value("--profile"), Some("p"), "{a:?}");
            assert_eq!(p.pos, ["n", "t", "notes"], "{a:?}");
        }
        let p = parse(&START, &v(&["n", "t", "--", "--profile", "x", "-"])).unwrap();
        assert_eq!(p.value("--profile"), None);
        assert_eq!(p.rest(2), ["--profile", "x", "-"]);
    }

    #[test]
    fn anything_unexpected_is_an_error_that_names_it() {
        assert!(err(&START, &["n", "t", "--profle", "p"]).starts_with("unknown option: --profle"));
        assert!(err(&START, &["n"]).contains("usage: lcoat op start"));
        assert!(err(&START, &["n", "t", "--profile"]).contains("requires a value"));
        assert!(
            err(&START, &["n", "t", "--profile", "a", "--profile", "b"]).contains("more than once")
        );
        assert!(err(&START, &["n", "t", "-x"]).starts_with("unknown option: -x"));
        let status = Spec::new("op status [name]", 0, Some(1));
        assert!(err(&status, &["--json"]).starts_with("unknown option: --json"));
        assert!(err(&status, &["a", "b"]).starts_with("unexpected argument: b"));
        let close =
            Spec::new("op close [name] [--force]", 0, Some(1)).flags(&[("--force", Kind::Switch)]);
        assert!(parse(&close, &v(&["--force", "x"])).unwrap().has("--force"));
        assert!(err(&close, &["--force=yes"]).contains("takes no value"));
    }

    #[test]
    fn repeated_flags_collect_every_value() {
        let s = Spec::new("finding resolve <id> [--evidence id]...", 1, Some(1))
            .flags(&[("--evidence", Kind::Many)]);
        let p = parse(&s, &v(&["f1", "--evidence", "a", "--evidence=b"])).unwrap();
        assert_eq!(p.values("--evidence"), ["a", "b"]);
        let q = Spec::new("finding review-queue [--op operation]", 0, Some(0))
            .flags(&[("--op|--operation", Kind::Value)]);
        assert_eq!(
            parse(&q, &v(&["--operation=x"])).unwrap().value("--op"),
            Some("x")
        );
        assert!(err(&q, &["--op", "a", "--operation", "b"]).contains("--op given more than once"));
    }
}
