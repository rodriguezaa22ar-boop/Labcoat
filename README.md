# Lab Coat

Lab Coat (binary: `lcoat`) is a scope-enforcing, metadata-only control plane for authorized security assessment. It wraps the tools you already use (nmap first) in a scope check, records every run in an append-only ledger, hashes tool output into evidence, and produces packets and receipts that anyone can re-verify. It never stores raw output, secrets or credentials in a packet, and it refuses to run anything above Tier 3.

This is the Rust production build. It follows two earlier implementations that it stays compatible with:

- **Atlas** (shell + Nix): the original design and the oracle every build is checked against.
- **Lab Coat Lite** (Go, [`GO-project`](https://github.com/rodriguezaa22ar-boop/GO-project)): a two-week prototype that proved the formats survive a rewrite and was field-validated on a live Fedora server.

Lab Coat reads every operation the shell and Go builds ever wrote, writes files their verifiers still accept, and adds what they could not enforce: a hash-chained ledger, evidence hashes anchored in the packets, and compile-time guarantees that only scanned metadata reaches disk and nothing runs outside scope.

## Status

**Phase 1 of 4 done: the read-only side.** `lcoat` reads every v1 file the shell build and Lite write and verifies operations the way the shell build does, byte for byte: `op list|readiness|verify|audit-verify|archive-verify|trust-chain`, `scope status`, `evidence list|verify`, `finding list`, `ledger verify|checkpoint`, `receipt create|verify|replay`. Against the shell build at `23ba2d2` it gives the oracle's verdict on all eight tamper cases (`conformance/tamper.sh`) and identical output on all 18 read-only commands (`conformance/readonly_diff.sh`); 98 tests pin the golden fixtures and the shell's recorded output. Zero dependencies. The write side (`op start`, `evidence add`, `finding add`, packets, adapters) is phase 2; until then `lcoat` names the command and points at Lite.

Two behaviours differ from Lite on purpose, both from the field test: an unset `LCOAT_ROOT` is an error rather than a silent fallback to the current directory, and no read-only command creates a directory.

The plan, with an exit check per phase, is in [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md) (including the six places where Lite's output had drifted from the shell's, which this build settles in the shell's favour); what the trust chain does and does not prove is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

| Crate | Purpose | Dependencies |
| --- | --- | --- |
| `lcoat-format` | strict JSON, canonical (`jq -cS`) form, SHA-256, NDJSON, env files, IDs | none |
| `lcoat-core` | scope, ledger, evidence, findings, packets, verifiers, receipts; owns `MetadataOnly` | `lcoat-format` |
| `lcoat-adapters` | nmap, script; the only crate that spawns a process | `lcoat-core` |
| `lcoat` | the CLI | all of the above |

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Tamper cases: does this build give the oracle's verdicts?
ATLAS_REPO=/path/to/atlas-trust-infrastructure conformance/tamper.sh check target/debug/lcoat LCOAT_ROOT

# Read-only commands, byte for byte against the shell build and Lite:
ATLAS_REPO=/path/to/atlas-trust-infrastructure GO_PROJECT=/path/to/GO-project conformance/readonly_diff.sh

# Everything above plus the phase-2 scenario (NOT YET until phase 2 lands):
ATLAS_REPO=/path/to/atlas-trust-infrastructure GO_PROJECT=/path/to/GO-project conformance/cross_check.sh
```

Requires Rust 1.89 or later (`rust-toolchain.toml` selects stable). No other tools are needed to build; `nmap` is needed at run time for the nmap adapter.

## What it is not

- Not a scanner, an exploit framework or an autonomous tester.
- Not able to run anything above Tier 3; Tier 4 and 5 are refused outright, Tier 3 needs a recorded approval.
- Not a server, a database or a GUI. Plain files under `$LCOAT_ROOT` are the store.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
