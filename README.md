# Lab Coat

Lab Coat (binary: `lcoat`) is a scope-enforcing, metadata-only control plane for authorized security assessment. It wraps the tools you already use (nmap first) in a scope check, records every run in an append-only ledger, hashes tool output into evidence, and produces packets and receipts that anyone can re-verify. It never stores raw output, secrets or credentials in a packet, and it refuses to run anything above Tier 3.

This is the Rust production build. It follows two earlier implementations that it stays compatible with:

- **Atlas** (shell + Nix): the original design and the oracle every build is checked against.
- **Lab Coat Lite** (Go, [`GO-project`](https://github.com/rodriguezaa22ar-boop/GO-project)): a two-week prototype that proved the formats survive a rewrite and was field-validated on a live Fedora server.

Lab Coat reads every operation the shell and Go builds ever wrote, writes files their verifiers still accept, and adds what they could not enforce: a hash-chained ledger, evidence hashes anchored in the packets, and compile-time guarantees that only scanned metadata reaches disk and nothing runs outside scope.

## Status

**Phase 0 of 4, prepared.** The workspace builds with zero dependencies, 40 tests pass, and the format crate reproduces every hash recorded in the golden fixtures: the 18-event ledger of `learning-op-001`, its evidence artifact, and all six hashes of the demo-site receipt chain. The plan, with an exit check per phase, is in [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md); what the trust chain does and does not prove is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). The shell oracle's verdicts for eight tamper cases are recorded in `fixtures/tamper/`, so phase 1 has a target that can fail before any verifier exists.

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

# Three-way conformance against the shell build and Lite:
ATLAS_REPO=/path/to/atlas-trust-infrastructure GO_PROJECT=/path/to/GO-project conformance/cross_check.sh
```

Requires Rust 1.89 or later (`rust-toolchain.toml` selects stable). No other tools are needed to build; `nmap` is needed at run time for the nmap adapter.

## What it is not

- Not a scanner, an exploit framework or an autonomous tester.
- Not able to run anything above Tier 3; Tier 4 and 5 are refused outright, Tier 3 needs a recorded approval.
- Not a server, a database or a GUI. Plain files under `$LCOAT_ROOT` are the store.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
