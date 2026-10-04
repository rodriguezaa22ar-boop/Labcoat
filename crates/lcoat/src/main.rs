//! `lcoat` command-line entry point.
//!
//! The grammar is `lcoat <domain> <verb>`, as in the shell and Go builds.
//! Everything lives in [`cli`]; this file only wires the process streams and
//! the exit code.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod cli;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut err = stderr.lock();
    let code = cli::run(&args, &mut out, &mut err);
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
