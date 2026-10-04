# Lab Coat

Lab Coat (binary: `lcoat`) is a scope-enforcing, metadata-only control plane for authorized security assessment. It wraps the tools you already use (nmap first) in a scope check, records every run in an append-only ledger, hashes tool output into evidence, and produces packets and receipts that anyone can re-verify. It never stores raw output, secrets or credentials in a packet, and it refuses to run anything above Tier 3.

This is the Rust production build. It follows two earlier implementations that it stays compatible with:

- **Atlas** (shell + Nix): the original design and the oracle every build is checked against.
- **Lab Coat Lite** (Go, [`GO-project`](https://github.com/rodriguezaa22ar-boop/GO-project)): a two-week prototype that proved the formats survive a rewrite and was field-validated on a live Fedora server.

Lab Coat reads every operation the shell and Go builds ever wrote, writes files their verifiers still accept, and adds what they could not enforce: a hash-chained ledger, evidence hashes anchored in the packets, and compile-time guarantees that only scanned metadata reaches disk and nothing runs outside scope.

## Status

**Phase 2 of 4 done: the whole v1 lifecycle, written in format 1.1.** `lcoat` starts, runs, closes and packages an operation end to end: `target add`, `op start|resume|close|report|handoff|closeout|audit-packet|archive-packet`, `evidence add|diff`, `finding add|resolve|accept|reopen|note|review-queue|review-packet|review-verify`, `approval grant|list|revoke`, `adapter run nmap|script`, `scope check`, plus every read-only command from phase 1. Everything it writes is still verified by the shell build and by Lite (`conformance/cross_check.sh`: one frozen-clock scenario through all three builds, every verifier on every root, 27 runs). On top of the v1 files it writes what they could not enforce: a hash-chained ledger (`ledger chain-verify`), an evidence manifest anchored in the packets, finding status changes, recorded Tier 3 approvals with mandatory expiry, and scan vantage. `conformance/tamper_rust.sh` runs six tamper cases the shell's verifiers cannot see (edited or deleted artifacts, forged manifests, rewritten or spliced ledger events, a truncated tail), with the shell and Lite run on the same roots to show which build catches what. Zero dependencies; 135 tests, including crash injection at every step of every multi-file write, a compile-fail suite for the rules that are types, and 14 fuzz targets (one per parser that reads untrusted bytes, nmap XML first) that run in every `cargo test` and, coverage-guided, in a nightly cargo-fuzz job.

Phase 3 (accepted-risk review packet done; `evidence bundle`, `doctor`, `--json` field parity next) and phase 4 (receipt signatures, release packets, 0.2.0) follow; the field re-run on the Fedora lab server happens with the operator at the keyboard.

Two behaviours differ from Lite on purpose, both from the field test: an unset `LCOAT_ROOT` is an error rather than a silent fallback to the current directory, and no read-only command creates a directory.

The plan, with an exit check per phase, is in [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md) (including the six places where Lite's output had drifted from the shell's, which this build settles in the shell's favour); what the trust chain does and does not prove is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

| Crate | Purpose | Dependencies |
| --- | --- | --- |
| `lcoat-format` | strict JSON, canonical (`jq -cS`) form, SHA-256, NDJSON, env files, IDs | none |
| `lcoat-core` | scope, ledger, evidence, findings, packets, verifiers, receipts; owns `MetadataOnly` | `lcoat-format` |
| `lcoat-adapters` | nmap, script; the only crate that spawns a process | `lcoat-core` |
| `lcoat` | the CLI | all of the above |
| `lcoat-fuzz` | fuzz targets and a std-only fuzzing engine (never shipped) | all of the above |

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Tamper cases: does this build give the oracle's verdicts?
ATLAS_REPO=/path/to/atlas-trust-infrastructure conformance/tamper.sh check target/debug/lcoat LCOAT_ROOT

# Read-only commands, byte for byte against the shell build and Lite:
ATLAS_REPO=/path/to/atlas-trust-infrastructure GO_PROJECT=/path/to/GO-project conformance/readonly_diff.sh

# Format 1.1 tamper cases only this build catches (shell/Lite comparison when the repos are set):
ATLAS_REPO=... GO_PROJECT=... conformance/tamper_rust.sh target/debug/lcoat

# Everything above plus the three-way lifecycle scenario:
ATLAS_REPO=/path/to/atlas-trust-infrastructure GO_PROJECT=/path/to/GO-project conformance/cross_check.sh

# Crash-injection tests need the crash points compiled in (never in a release build):
cargo test --workspace --features lcoat/test-support

# Longer fuzz campaigns (std-only engine; failing inputs land in target/fuzz-crashes/):
cargo run -p lcoat-fuzz --profile fuzz -- run all --seconds 600
# Coverage-guided, needs nightly and cargo-fuzz:
cargo run -p lcoat-fuzz -- seeds all fuzz/corpus && cargo +nightly fuzz run nmap_xml fuzz/corpus/nmap_xml
```

Requires Rust 1.89 or later (`rust-toolchain.toml` selects stable). No other tools are needed to build; `nmap` is needed at run time for the nmap adapter.

## What it is not

- Not a scanner, an exploit framework or an autonomous tester.
- Not able to run anything above Tier 3; Tier 4 and 5 are refused outright, Tier 3 needs a recorded approval.
- Not a server, a database or a GUI. Plain files under `$LCOAT_ROOT` are the store.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
