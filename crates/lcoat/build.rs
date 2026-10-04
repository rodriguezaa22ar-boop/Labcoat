//! Records which commit a binary was built from, so `lcoat version` can
//! tell two builds of the same version apart (field run 1: a binary from
//! before `finding review-packet` and one after both said `0.2.0-dev`).
//! Standard library only. Order: `LCOAT_BUILD_COMMIT`, then CI's
//! `GITHUB_SHA`, then `git rev-parse` in the source tree, else `unknown`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=LCOAT_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let from_env = std::env::var("LCOAT_BUILD_COMMIT")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .filter(|s| !s.is_empty());
    let commit = from_env
        .or_else(git_head)
        .unwrap_or_else(|| "unknown".to_owned());
    let short: String = commit
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(12)
        .collect();
    let short = if short.len() >= 7 {
        short
    } else {
        "unknown".to_owned()
    };
    let dirty = if git_dirty() { "-dirty" } else { "" };
    println!("cargo:rustc-env=LCOAT_BUILD_COMMIT={short}{dirty}");
    // Rebuild when HEAD moves (best effort; absent outside a checkout).
    for p in ["../../.git/HEAD", "../../.git/index"] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}

fn git_head() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn git_dirty() -> bool {
    if std::env::var("GITHUB_SHA").is_ok() || std::env::var("LCOAT_BUILD_COMMIT").is_ok() {
        return false;
    }
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}
