//! `hash` and `scan`: the phase 0 utilities.

use std::path::Path;

use lcoat_core::metadata::{MetadataOnly, forbidden_paths};
use lcoat_format::hash::Sha256Hex;
use lcoat_format::json::Value;

use super::{CliError, CmdResult, Ctx, USAGE, fail};

/// `hash <file>...`: SHA-256 of each file, `sha256sum` style.
pub fn hash(ctx: &mut Ctx<'_>, paths: &[String]) -> CmdResult {
    if paths.is_empty() {
        return Err(fail(format!(
            "hash requires at least one file\n{}",
            USAGE.trim_end()
        )));
    }
    let mut failed = false;
    for p in paths {
        match Sha256Hex::of_file(Path::new(p)) {
            Ok(h) => ctx.line(&format!("{h}  {p}")),
            Err(e) => {
                let _ = writeln!(ctx.err, "error: {p}: {e}");
                failed = true;
            }
        }
    }
    if failed {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}

/// `scan <file.json>...` or `scan --text <string>`.
pub fn scan(ctx: &mut Ctx<'_>, args: &[String]) -> CmdResult {
    if let Some((flag, rest)) = args.split_first()
        && flag == "--text"
    {
        let text = rest.join(" ");
        return match MetadataOnly::scan(&text) {
            Ok(_) => {
                ctx.line("ok: metadata-only");
                Ok(())
            }
            Err(e) => Err(fail(e.to_string())),
        };
    }
    if args.is_empty() {
        return Err(fail(format!(
            "scan requires a file or --text\n{}",
            USAGE.trim_end()
        )));
    }
    let mut dirty = false;
    for p in args {
        let text = std::fs::read_to_string(p).map_err(|e| fail(format!("{p}: {e}")))?;
        let doc = Value::parse(&text).map_err(|e| fail(format!("{p}: {e}")))?;
        let paths = forbidden_paths(&doc);
        if paths.is_empty() {
            ctx.line(&format!("ok: {p}: metadata-only"));
        } else {
            dirty = true;
            ctx.line(&format!("forbidden: {p}: {}", paths.join(",")));
        }
    }
    if dirty {
        Err(CliError::Exit(1))
    } else {
        Ok(())
    }
}
