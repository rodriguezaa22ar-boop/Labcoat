# Lab Coat (Rust) Blueprint

As-of 2026-10-02. The living copy is the Claude doc of the same name; this file tracks it.

## Summary

Lab Coat is the production build of the control plane prototyped as Atlas (shell) and proven as Lab Coat Lite (Go). It is written in Rust so the two rules Lite could only test for, *metadata only* and *in scope*, become things the compiler enforces. The binary keeps the name `lcoat`, picks up at version 0.2.0, and reads every operation the shell and Go builds ever wrote.

The strategy in one line: **upgrade the formats additively, so the shell build stays the oracle.** Every file Lab Coat writes is still accepted by the shell and Go verifiers; the extra fields and manifests it adds are what let its own verifiers catch what theirs cannot. Three implementations verifying each other's output is the exit check for the whole build.

Inputs: the Lite blueprint and go/no-go memo in `GO-project/docs`, the Go conformance fixtures (`learning-op-001`, the demo-site receipt chain, the nmap sample), the shell build pinned at `23ba2d2`, and the two field operations on the Fedora lab server that showed where Lite fell short.

## Quality bar

"Best version it can be" has to mean things a reviewer can check, or it means nothing. Every phase from 2 on is held to this list before it merges; anything not met is written down as a gap in this file, not quietly deferred.

1. **Verdicts are never the writer's word.** Every file Lab Coat writes is verified by all three builds (`cross_check.sh` stage 2: nine writer/verifier pairs, every verifier on every root). A Lab Coat-only format addition must leave the shell and Lite verdicts unchanged and must make at least one Rust-only tamper fixture fail that passed before.
2. **Rules are types, not reminders.** Each invariant in "What Rust buys" has a compile-fail test (`trybuild`-style, std-only) showing the forbidden program does not build. A reviewer should be able to try to write raw output into a packet and watch the compiler refuse.
3. **Nothing on the write path can half-happen silently.** Multi-file mutations have a fixed order whose partial states are detectable by the verifiers (see "Transaction order" below); every file is written private (0600/0700) and atomically (temp file + rename) except the two append-only logs, which are `O_APPEND` under a lock; a lab root is locked for the duration of any mutating command so two `lcoat` processes cannot interleave.
4. **No panics on operator input.** `clippy::unwrap_used` and `expect_used` are errors outside tests; every parser (envfile, NDJSON, JSON, packet anchors, nmap XML) has a fuzz target and a property test; every refusal message is tested by an integration test that provokes it.
5. **Byte-identical where the oracle exists.** Output and files match the shell build byte for byte under the frozen clock; every intentional divergence is listed in "Read-only conformance" with a reason.
6. **Honest about limits.** `--help`, the threat model and every verdict line say what was not evaluated (v1 pillars, authorization, completeness). A status word is never printed for something the build did not check.
7. **Reproducible and signed.** `--locked` builds from a committed `Cargo.lock`, static binaries for linux-musl (x86_64, aarch64) and macOS (aarch64), `SHA256SUMS` and a minisign signature per release, signed tags. Zero runtime dependencies; any crate added later gets a one-line reason in "Dependencies".
8. **Fast enough to be invisible.** Every command on a 10,000-event ledger finishes under 100 ms on a laptop; `evidence verify` streams hashes. Measured once per phase and recorded here, not assumed from the language.

## Goals and non-goals

**Goals**

- Full lifecycle parity with Lite, plus the parts Lite deferred: finding status changes, evidence bundles and manifests, the Tier 3 approval plane, release packets, and a `v1 status` split into *toolchain installed* and *trust artifacts sound*.
- Compile-time enforcement of the two invariants: nothing but scanned metadata reaches a packet or receipt, and nothing runs against a target that is not in the operation's scope.
- A ledger whose entries are chained by hash, so a verifier can point at the exact event that was altered.
- Evidence artifact hashes anchored inside the packets, closing the gap found in the first field test.
- Builds for Linux (amd64, arm64) and macOS, so a scan can run from a second vantage point and the record says which one.
- Lite's field-found bugs fixed by construction: an unset lab root is an error; a missing target cannot shift arguments; adapter timeouts are per adapter.

**Non-goals**

- Rewriting wiremap, vector or intelctl, or any scanner.
- Anything above Tier 3. Tier 4 and 5 stay refused outright.
- A GUI, a server, or a database. Plain files under the lab root remain the store.
- Renaming the `atlas.*` schema IDs. Reserved for a 1.0 decision.

## Compatibility strategy: additive formats

Two facts checked in the Go and shell code make upgrades possible without losing the oracle:

- Both verifiers decode NDJSON into generic objects and ignore unknown keys. Extra fields on a ledger line are invisible to them, and the whole-file SHA-256 they anchor still holds.
- The shell's closeout and archive packets already carry an `Evidence manifest:` slot. Lite wrote `none` there (hence two `unverifiable` gaps in `op verify`). A build that fills the slot is verified by the shell's own `archive-verify`.

So Lab Coat writes **format 1.1**: everything Lite wrote, byte for byte, plus additive fields and the manifests the format already had room for.

| Level | Meaning | Checked by |
| --- | --- | --- |
| Read v1 | Lab Coat verifies every shell/Lite operation with identical verdicts | Golden and tamper fixtures from `GO-project` |
| Write v1-compatible | Shell and Lite verifiers accept every packet Lab Coat writes | Three-way cross-check |
| Verify v1.1 | Lab Coat's verifiers use the additive data to catch what v1 cannot | Rust-only tamper fixtures |

A Lite operation continued by Lab Coat gets chain fields from that point on; its verifier reports the chain as `partial`, never as broken. The `atlas.*` schema IDs and the `jq -cS` canonical hashing stay exactly as they are.

## Architecture

```text
 lcoat (bin)            CLI: argument parsing, exit codes, output rendering. No logic.
   |
   +--> lcoat-adapters  nmap, script, later nuclei/zap. Typed argument parsers,
   |      |             subprocess runner. The only crate that executes anything.
   |      v
   +--> lcoat-core      scope, ledger, evidence, findings, packets, verifiers,
          |             receipts, approvals. Owns MetadataOnly and the operation
          |             typestate. Never spawns a process.
          v
        lcoat-format    strict JSON, canonical (jq -cS), SHA-256, NDJSON, envfile
                        (bash %q), second-resolution IDs. Pure functions.
```

- `lcoat-format` is where every byte-compatibility rule lives; the Go fixtures test it hardest.
- `lcoat-core` takes a `LabRoot` (never the current directory) and exposes the lifecycle as types. Public, auditable.
- `lcoat-adapters` is behind the `adapters` Cargo feature (default on). Building without it yields a verify-only binary.
- `lcoat` maps commands to core calls; a command that would break the packet order does not compile.

Read-only commands take `&Operation<_>`; writing commands take `&mut`. The borrow checker is the "read-only stays read-only" test Lite wrote by hand.

## What Rust buys: invariants as types

1. **Metadata only.** Packet and receipt writers accept only `MetadataOnly`, whose only constructor is the forbidden-content scanner.
2. **In scope.** `AdapterRunner::run` takes a `ScopedTarget`, which only `Scope::preflight` can produce.
3. **Lifecycle and packet order.** `Operation<Active>` / `Operation<Closed>` typestate; each packet constructor requires the previous packet by reference.
4. **Tiers and arguments.** `Tier` is an enum; nmap arguments parse into `enum NmapArg`, so unknown flags fail to parse and positionals have no variant.
5. **Append-only ledger.** `Ledger::append` is the only write; the file is `O_APPEND` under an exclusive lock, private to the type.
6. **Lab root.** `LabRoot::from_env()` returns `Err(RootUnset)` instead of a warning.
7. **Read-only commands.** Verifiers take shared references.

Types cannot prove the scanner's patterns are complete or that a hash covered the right bytes; those stay as tests, property tests and fuzzing.

## Format upgrades (all additive)

| Upgrade | On disk | Fixes | v1 verifiers |
| --- | --- | --- | --- |
| Ledger hash chain | `prev_hash`, `event_hash` per event (SHA-256 of canonical event without those fields + previous `event_hash`; first `prev_hash` null) | names the altered event | ignore the fields |
| Evidence manifest | `evidence/manifest.ndjson`; closeout/archive fill the `Evidence manifest:` slot | edited/deleted artifacts caught by `evidence verify` and the trust chain; the manifest itself is hash-anchored in the packets, so it cannot be forged to hide an edit | verify the manifest's hash in the slot; do not re-hash artifacts |
| Finding lifecycle | `finding resolve/accept/reopen` append a record with the same id; `finding.updated` ledger event | status after `add` | latest-record-per-id readers |
| Scan vantage | `vantage=<hostname>` and `vantage_addr` on adapter evidence and `adapter.started` | self-scan vs external scan distinguishable | extra tokens ignored |
| Approval records | `approvals.ndjson`; `approval.granted` event | Tier 3 under a recorded grant | same file the shell uses |
| Receipt signatures | optional `signature` (ed25519 over `receipt_hash`) + key id | receipts tied to an operator key | unknown keys ignored |

Unchanged: env quoting, NDJSON field order, Markdown packet layouts, canonical form, IDs with `_02` suffixes, `atlas.*` schema IDs.

## Phase 2 design, decided before code

Phase 2 writes the files. These decisions are fixed now because changing a format after the field runs is the one thing this project cannot afford.

### Lifecycle as types

```text
Operation::load(root, name) -> Loaded            Loaded::Active(Operation<Active>) | Loaded::Closed(Operation<Closed>)
Operation::start(root, StartParams) -> Operation<Active>
Operation<Active>  : add_evidence, add_finding, update_finding, run_adapter, write_report, write_handoff, close(Readiness) -> Operation<Closed>
Operation<Closed>  : write_closeout, write_audit_packet, write_archive_packet, resume() -> Operation<Active>
both               : everything read-only from phase 1
```

Packet constructors take the previous packet by reference (`write_audit_packet(&closeout)`), so the generation order report → handoff → close → closeout → audit → archive is enforced by the signatures, and the "later allowed events" the verifiers accept after a closeout are exactly the ones these methods can append. Writers take `MetadataOnly` for every free-text field (title, impact, recommendation, notes, detail), so the scanner runs because the call does not compile otherwise, not because a test checks it.

### Transaction order and crash safety

Each mutating command touches files in an order whose partial states a verifier reports as "not recorded" rather than as corruption:

| Command | Order | If interrupted after step n |
| --- | --- | --- |
| `evidence add` | 1 copy artifact into `evidence/<id>/` (temp + rename) · 2 hash and compare · 3 append `evidence.ndjson` · 4 append manifest · 5 append ledger | n<3: orphan directory, no record, next ID gets `_02`; n=3,4: record without ledger event, readiness shows no `artifact.created`, report lists it; verifiers consistent |
| `finding add` | 1 claim `findings/<id>/` · 2 append `findings.ndjson` · 3 append ledger | same shape |
| `op start` | 1 create directories · 2 write `session.env` · 3 write snapshot · 4 append `op.started` · 5 history · 6 set active | n<4: `op list` shows it, ledger empty, `op verify` says missing ledger |
| packets | 1 append `*.generated` event with the path · 2 render · 3 write file (temp + rename) · 4 history | event without file: verifiers say `missing`, exactly what the shell does today |
| `op close` | 1 upsert `STATUS`/`CLOSED_AT` · 2 append readiness and `op.closed` · 3 history · 4 clear active | shell order, kept |

All of these run under one advisory lock on `<op dir>/.lock` (and `state/atlas/.lock` for the active pointer and target registry) held for the whole command. The shell and Lite lock only the ledger line; this is the first build where two operators in one root cannot interleave an evidence copy with a packet render. The lock file is an empty file, ignored by every verifier.

Atomic writes (temp file in the same directory, `fsync`, rename) apply to every whole-file write: env records, packets, reports, receipts. The two NDJSON indexes and the ledger stay append-only.

### What the adapter layer is allowed to do

- Arguments are parsed into enums (`NmapArg`, `ScriptArg`); a flag without a variant is a parse error, so there is no allowlist string to drift. Lite's nmap rules are the starting set: target from the scope snapshot only, no `-iL`, no `--script` outside a fixed safe list, no output-file flags (Lab Coat captures output itself), default timeout 600 s.
- No shell. `std::process::Command` with argv, environment cleared to `PATH` and locale, stdin closed, working directory the run's temp dir.
- Output is captured to `evidence/<id>/` as a file and hashed; nothing from it enters a ledger detail or packet except counts and the hash. The nmap XML parser produces metadata (open ports, service names) for the report and finding suggestions; the parser is fuzzed.
- Vantage is recorded on every run: hostname and the source address `nmap` reports (or the default route address when a tool reports none), as `vantage=` tokens on `adapter.started` and fields on the evidence record. A scan of astra from astra and a scan from the Mac over Tailscale become distinguishable in the trail.
- Tier is a property of the adapter and the arguments, not a flag the operator sets: `nmap -sn` is Tier 1, `-sV` is Tier 2, anything that parses to a NSE category outside `safe`/`default`/`discovery`/`version` does not parse at all.

### Format 1.1 details fixed now

- **Ledger chain:** as frozen in `lcoat-core::chain`. Every event Lab Coat appends carries `prev_hash`/`event_hash`; a ledger that starts under Lite and continues under Lab Coat is `Partial { first_chained }`, reported as such, never upgraded in place.
- **Evidence manifest:** `evidence/manifest.ndjson`, one record per artifact `{id, path, sha256, bytes, recorded_at}`, appended with the index; its own hash goes into the closeout and archive `Evidence manifest:` slot the shell already verifies. Precisely what this buys: an edited or deleted artifact is caught by Lab Coat's (and Lite's) `evidence verify` and by the `Evidence Artifacts` line of `op trust-chain`; an attacker who also rewrites the manifest and index to match is caught by `op verify` and `op archive-verify` in all three builds, because the manifest's hash is anchored in the packets. The shell's own verifiers never re-hash artifacts, so on an edited artifact alone they still say `verified`; `conformance/tamper_rust.sh` demonstrates both halves. (An earlier draft of this paragraph claimed the manifest makes the shell catch the edit; it does not, and the claim was wrong.)
- **Relocatable paths:** packets keep the absolute path the shell expects and add `rel=<root-relative>` tokens on every anchor line. v1 verifiers ignore the token; Lab Coat's verifiers use it only when the absolute path is missing *and* the packet carries the token, so verdicts on v1 packets are unchanged and a Lab Coat root can be moved or restored from backup and still verify.
- **Finding lifecycle:** `finding resolve|accept|reopen|note` append a full record with the same `id` (the readers already take the latest), plus `finding.updated` ledger events with the status transition in `detail`.
- **Approvals:** `approvals.ndjson` keeps the shell's record shape `{ts, op, target, capability, tier, approved_by, reason, status}` and adds `expires_at`; the latest record per capability and target wins, `revoked` ends a grant, `approval grant` requires a reason and an expiry (no open-ended grants), `approval list|revoke` exist, and the preflight honours only an unexpired `approved` record. Phase 4 adds the signature; the record shape is fixed now so phase 4 is additive.
- **`--json` everywhere:** every read-only command accepts `--json` and emits the shell's object where the shell has one (`atlas.operation_trust_chain.v1`, `atlas.receipt_replay.v1`, `atlas.ledger_verify.v1`, `atlas.checkpoint.v1`, …) or a documented `lcoat.*.v1` object where it does not (`lcoat.readiness.v1`, `lcoat.evidence_verify.v1`, `lcoat.ledger_chain.v1`, the three packet verifiers). Scripts and the case study stop parsing tables. Phase 3 checks the shell-object fields one by one against the shell's output.

### Things kept exactly as the shell has them, on purpose

Second-resolution IDs with `_02` suffixes, `printf %q` env quoting, Markdown packet layouts, canonical JSON, `atlas.*` schema IDs and the `SOURCE_TOOL=atlas` marker, exit code 1 for every failure. Each is a compatibility promise to the records already on astra; none is worth breaking for tidiness.

### Exit for phase 2

`cross_check.sh` stage 2 clean (three-way scenario, normalized diff of every file, 27 verifier runs); the Rust-only tamper cases fail only in Rust; the compile-fail suite passes; `evidence add` and `op close` survive an injected crash at every step in the table above with the verifiers reporting the documented state; the astra operations written by Lite 0.1.4 load, verify and can be resumed by Lab Coat without conversion.

### Phase 2 result

Everything above except the last clause is done and checked by `conformance/cross_check.sh` (`CONFORMANCE OK`: 119 tests, TAMPER OK, READONLY OK, TAMPER-RUST OK, 27 verifier runs). The astra step waits for the field re-run with the operator; nothing is remote-driven from here.

- **Crash injection** is real, not simulated: `lcoat_core::crash::point` sits after every step in the transaction-order table and, with `--features lcoat/test-support`, `LCOAT_TEST_CRASH_AT=<step>` exits the binary there (code 99). `crates/lcoat/tests/lifecycle_cli.rs` crashes `op start`, `evidence add`, `finding add`, `op close` and `op closeout` and asserts the verifiers' verdicts and the documented recovery command. Release builds compile the hook out; CI greps the static binaries for the marker string.
- **Compile-fail suite** (`crates/lcoat-core/tests/compile_fail.rs`, std-only, no `trybuild`): eight downstream programs the compiler must refuse: writers on `Operation<Closed>`, packets on `Operation<Active>`, `close` on a closed operation, `ScopedTarget` without a preflight, `String` where `MetadataOnly` is required, a `Written` handle constructed by hand, a path where a `Written` is required.
- **Rust-only tamper cases** (`conformance/tamper_rust.sh`, six cases): artifact edited after capture and artifact deleted (caught by `evidence verify` and the trust chain; the shell says `verified` on the same root, Lite's `evidence verify` catches them too); manifest and index forged to match the edit (caught by `op verify` / `op archive-verify` through the packet anchors, in all three builds); a ledger event rewritten or spliced out before any packet exists (caught by `ledger chain-verify` and the trust chain's `Ledger Chain` line; the shell and Lite have no chain and say `ok`); and the documented limit: a truncated tail passes the chain and is caught only by comparing against a recorded `ledger checkpoint` head.
- **Two deliberate divergences from the shell, to record:** (1) `op closeout`, `op audit-packet` and `op archive-packet` require a closed operation (the shell writes a closeout for an active one); since `op close` clears the active pointer as the shell does, the packets are written by name afterwards (`lcoat op closeout <operation>`), and the refusal says exactly that. (2) `finding accept` works, but `finding review-packet` is phase 3, so an archive packet for an operation with accepted risks is `incomplete` until then; the trust chain reports it on the `Accepted Risk Review Packet` line rather than hiding it.
### Fuzzing (after phase 2)

Thirteen targets, each a function in `crates/lcoat-fuzz/src/targets.rs` that feeds bytes to a parser the way the binary does and asserts what makes the parser safe to trust, not only that it does not panic:

| Target | Input | Invariants beyond "no panic, no hang" |
| --- | --- | --- |
| `nmap_xml` | `nmap -oX` from the network | ports are plain decimals in 1..=65535, protocol is one nmap writes, banners carry no control or bidi characters and are at most 128 characters, one bad byte cannot hide the other findings |
| `nmap_args` | operator arguments | the argv passed to nmap re-parses to the same arguments; no file, spoofing or target flag survives; tier stays 1..=2 |
| `script_args` | operator arguments | declared tier stays 1..=3; no empty command |
| `json` | receipts, indexes | canonical, compact and pretty forms re-parse; canonical bytes are a fixed point and newline-free |
| `ndjson`, `ledger_chain` | indexes, ledgers | freshly linked events verify; tampering event *i* is reported at *i* |
| `envfile` | operation, scope, target, profile records | records round-trip; any string quoted as one value reads back as that value and never as a second key |
| `metadata_scan` | free text | scanner verdicts are consistent and stable |
| `timestamp` | expiries, ledger times | accepted strings are canonical (one spelling per instant) |
| `slug` | names that become paths | slugs stay in `[a-z0-9._-]`, idempotent; dot-only and hidden slugs are refused |
| `packet_text`, `receipt` | packets, receipts | anchor readers return substrings without backticks or whitespace |
| `op_files` | a whole closed operation with one file corrupted | every reader and verifier returns a verdict |

What the first campaign found, all fixed with a unit test and a regression input in `crates/lcoat-fuzz/corpus/` that every `cargo test` replays:

- **nmap XML trusted the scanned host.** Protocol and port were taken as written (`tbp`, `v0`, `0`, `65536` became "open ports"), and `-sV` banners went to the operator's terminal unfiltered, so a hostile service could send ANSI escape sequences (clear the screen, print a fake status line) or bidi overrides. Now protocol and port are validated, banners have control and invisible characters replaced with `?` and are capped at 128 characters, and an invalid UTF-8 byte no longer drops every proposed finding.
- **Timestamps accepted signs and impossible dates** (`+026-…`, `07:-0:00`, February 31st, leap second 60), each printing back as a different instant's spelling. Now digits only, real calendar dates, canonical.
- **Dot names became paths** (found while writing the `slug` target): `slugify` keeps dots, as the shell's does, so `target add ..` wrote a hidden `...env` and `op start ..` was refused only because the directory existed. Every writer now refuses an empty, dot-only or hidden slug with a message naming it.

`cargo test` runs 3,000 inputs per target (about 10 s); `LCOAT_FUZZ_ITERS` raises it (40,000 per target ran clean). Long local campaigns: `cargo run -p lcoat-fuzz --profile fuzz -- run all --seconds 600`.

### Field run 1 (2026-10-04, operator's Fedora lab server)

Two operations run by the operator with the CI-built binary: `local-baseline` (closed, one accepted risk) and `fedora-baseline` (active, two open findings). On both, `ledger chain-verify` reports `verified` and `evidence verify` reports `verified` (3 and 4 artifacts, no problems). For `local-baseline`, `op trust-chain --strict` shows closeout, audit and archive packets verified, evidence artifacts verified, ledger chain verified, close readiness `ready`, and **Trust Chain Status `incomplete`**, with the next step "Generate an accepted-risk review packet before final archive review." That is the phase-3 gap below, met in the field. Not yet recorded: loading the Lite 0.1.4 operations on astra.

The `fedora-baseline` findings were explained, not fixed: rsyslog listening on 514 on all addresses, reachable over Tailscale because firewalld puts the tailnet interface in the trusted zone; nginx on 80 and a dashboard on 8080 bound to the Tailscale address. The accepted-risk path found two problems:

- **`finding accept --expires 90d` stored the text `90d`.** The expiry check compares dates as text, so that acceptance would never have expired. Fixed: `finding accept` takes the same forms as `approval grant` (date, timestamp, `Nh`, `Nd`) through one checked parser (`clock::parse_expiry`, which also closed an overflow on huge counts), stores the instant, and refuses anything else or a past date. Fuzz target `expiry` added.
- **An operation with an accepted risk can close but never reach a `current` trust chain.** Close readiness is `ready` and every packet verifies, but the trust chain stays `incomplete` (and `--strict` fails) until an accepted-risk review packet exists, and `finding review-packet` is not built yet. This moves `finding review-packet` to the top of phase 3.

- **Not yet, carried to phase 3:** `evidence bundle`, `finding review-packet`, `lcoat doctor`, field-by-field `--json` parity with the shell's objects, the field re-run on astra.

## Command surface

Every Lite command keeps its name, arguments and output. New: `finding resolve / accept / reopen`, `evidence bundle`, `approval grant / list / revoke`, `ledger chain-verify`, `receipt sign` and `receipt verify --require-signature`, `v1 status` (split `toolchain` / `trust`), `release packet / verify / replay / manifest`, `lcoat doctor`. Not planned: `web`, `flow`, `advisor`.

Two deliberate behaviour changes: an unset lab root is an error; a missing `<target>` is reported before any argument is read.

## Dependencies, toolchain and supply chain

**Default: the library crates use the standard library only, as Lite used Go's.** Lite's zero-dependency supply chain was a strength, and the environment this scaffold was built in has no crates.io access, so anything built on external crates could not have been compiled before hand-over. The formats are small and ours; std has file locking (1.89); SHA-256 and strict JSON are about 200 lines each with exact test vectors. Phase 0 shipped them and they reproduce every golden hash.

Fallback list if a hand-written piece proves costly (adopt with a one-line reason; `cargo deny` keeps the allowlist): `serde`/`serde_json`, `sha2`/`hex`, `regex`, `clap`, `time`, `rustix`, `ed25519-dalek` (phase 4); dev: `proptest`, `assert_cmd`, `trybuild`, `cargo-fuzz`. `#![forbid(unsafe_code)]` everywhere regardless.

- **Toolchain:** stable Rust, MSRV 1.89, edition 2024, `rust-toolchain.toml`. CI: fmt, clippy `-D warnings`, tests with and without adapters, cargo-deny, MSRV build.
- **Builds:** static `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `aarch64-apple-darwin`; `--locked`, stripped, `SHA256SUMS` per release.
- **Nix: dropped for this repo.** An asset for the shell build (exact `bash`/`jq`/coreutils); with zero dependencies and a pinned toolchain Cargo is already reproducible, so Nix would add a contributor requirement without adding assurance. May return in phase 4 for bit-for-bit reproducible release binaries (linker and libc pinning), a build-server concern.

## Conformance

1. **Pinned oracles:** shell `23ba2d2`; Lite `v0.1.4` (`f4039fb`). Fixtures copied read-only into `fixtures/golden/`. **The shell build is the oracle; Lite is the second opinion.** Where the two disagree on presentation (they never disagreed on a verdict), Lab Coat follows the shell: see "Read-only conformance" below.
1. **Tamper verdicts recorded first.** `conformance/tamper.sh record` builds a closed operation with the shell build, applies eight cases and writes the shell's verdicts to `fixtures/tamper/*.expect`; `tamper.sh check <bin>` diffs another implementation against them. Done in phase 0; Lite matches on all eight. Notably the shell passes an edited artifact (all verifiers `verified`), which is the gap format 1.1 closes.
2. **Golden hashes first:** ledger file hash (18 events), head event and closeout prefix hashes, artifact hash, all three receipts' `event_hash`/`receipt_hash`. Done in phase 0.
3. **Three-way scenario:** one frozen-clock scenario through shell, Go and Rust; normalized diff; every verifier on every root (9 combinations, 27 runs).
4. **Tamper cases, two tiers:** the shell's eight verdicts must be reproduced (`tamper.sh check`); six format 1.1 cases must fail only in Rust (`tamper_rust.sh`, with the shell and Lite run on the same roots to show the gap). Done in phase 2.
5. **Property tests** over canonical JSON, envfile round trip, scanner.
6. **Fuzzing**, two engines over one set of targets (done; see "Fuzzing" below). `crates/lcoat-fuzz` holds 13 targets, one per parser that reads untrusted bytes, each asserting safety invariants, plus a dependency-free mutational engine that runs them in every `cargo test`. `fuzz/` holds cargo-fuzz (libFuzzer, coverage-guided) harnesses calling the same functions; `.github/workflows/fuzz.yml` runs them on nightly, 45 s per target on every push and 10 min per target every night. Local builds and every other job stay on stable.
7. **Compile-fail tests** for the type-level claims: std-only, each case a tiny downstream crate built with `cargo`, one package name per case (two packages with one name share a fingerprint and a failed case can pass as fresh). Done in phase 2.
8. **Field validation:** re-run the Fedora lab assessment with Lab Coat; Lite verifies the result; the case study gets a third column.

### Read-only conformance (phase 1 result)

`conformance/readonly_diff.sh` builds one closed operation with the shell build under the frozen clock and runs every phase-1 command through the shell, Lite and Lab Coat, diffing the outputs byte for byte. Lab Coat matches the shell on all 18 commands. Lite differs from the shell on six of them, which phase 1 found and the shell settles:

| Command | Lite's simplification | Lab Coat follows the shell |
| --- | --- | --- |
| `op verify` | `Packet:` label, no `ARTIFACT STATUS PATH` header, no `disallowed_later_events=` in a changed-ledger row | `Manifest:`, header row, full detail |
| `op audit-verify` | three-column rows, `Verified Anchors`/`Gaps` footer | `ledger=… events=… later_archive_events=…` and `expected_sha=… actual_sha=… manifest=…` rows; status and problems only |
| `op archive-verify` | labels padded to 20, `changed` without `actual=` | 22-column labels, `expected=… actual=…` |
| `op trust-chain` | no Freshness block, no expired-risk count, no review-packet line, no latest-ledger-event line | the shell's layout minus the Business Flow Evidence block (no flows here) plus the `Evidence Artifacts` re-hash line |
| `receipt replay --json` | eight top-level fields | the shell's full object (`ledger_binding`, `chain_checkpoint`, `chain[]`, `metadata_boundary`, `known_limitations`) |
| `receipt create` | compact canonical JSON | `jq -S .` form (pretty, sorted), which is how every shell-written receipt on disk looks |

Normalized before the diff, by design: the `V1 Readiness` line (the shell evaluates its own toolchain pillars; Lab Coat says it does not), the current-chain wording (`Trust chain is current.` vs `Metadata trust chain is current.`), the Business Flow Evidence block, the Evidence Artifacts line, and the clock-dependent fields of `ledger checkpoint`. Every build replays every build's receipts: receipt hashes cover the canonical form, so the serialization difference is cosmetic.

Trust-chain status itself keeps Lite's rule rather than the shell's: the shell also requires its v1 toolchain pillars to be `ready` before saying `current`; Lab Coat does not ship those pillars and does not pretend to evaluate them. This is the one verdict-level difference from the shell, and it is announced on the `V1 Readiness` line of every trust-chain report.

Operation readiness, ledger verify/checkpoint and receipt verify were already identical in all three.

## Eight-week plan

| Weeks | Phase | Deliverable | Exit check |
| --- | --- | --- | --- |
| 0 | Prepare (done) | Workspace, CI, fixtures, canonical JSON + hashing, `MetadataOnly`, this blueprint | `cargo test` reproduces the golden ledger, artifact and receipt hashes |
| 1–2 | Read and verify v1 (done) | envfile, NDJSON, ledger reader, packet verifiers, `receipt verify/replay/create`, `op trust-chain`, `evidence verify`; **tamper cases first, verifiers second** | `tamper.sh check target/debug/lcoat LCOAT_ROOT` prints TAMPER OK; `readonly_diff.sh` prints READONLY OK (18 commands byte-identical to the shell); golden tests pin the shell's recorded output |
| 3–4 | Write v1-compatible (done) | targets, operations, scope, evidence, findings, report, packets, `adapter run`; typestate; `MetadataOnly` on every writer | three-way cross-check clean in all nine directions; compile-fail suite passes |
| 5–6 | Format 1.1 (chain, manifest, finding lifecycle, vantage, approvals and `chain-verify` landed with phase 2) | `evidence bundle`, `finding review-packet`, `doctor`, `--json` field parity; musl + macOS builds | shell and Lite still verify Rust output; Rust-only tamper cases fail only in Rust; Mac scan records vantage |
| 7–8 | Trust plane and release | approval plane, `v1 status` split, receipt signatures, release packets; field re-run; 0.2.0 | field operation verified by all three builds; `v0.2.0` tagged with SHA256SUMS |

Schedule risk sits in weeks 3–4. If the typestate fights the format, the format wins and the type gets a documented exception.

## Open decisions

- [x] **Repo:** `rodriguezaa22ar-boop/labcoat`, Apache-2.0.
- [x] **Binary name and version.** `lcoat`, 0.2.0 onward. Lite is retired when 0.2.0 ships; `GO-project` stays pinned at v0.1.4 as the oracle, security fixes only.
- [ ] **Public/private split.** Default: one public repo, adapters behind a feature flag.
- [ ] **Edition and MSRV.** Default: 2024 / 1.89, stable only.
- [ ] **Signature scheme.** Default: ed25519, keys in `$LCOAT_ROOT/keys/`. Decide in phase 4.
- [x] **Nix.** Dropped (see Dependencies).
- [ ] **Schema IDs.** Default: keep `atlas.*` through 0.x.
- [ ] **Second vantage.** Default: the Mac build over Tailscale.
- [x] **Ledger event hash definition.** Frozen in `lcoat-core::chain`: `sha256(canonical(event without prev_hash/event_hash) + "\n" + prev_hash_hex_or_empty + "\n")`, first `prev_hash` null. Two test vectors computed independently with `jq -cS` and `sha256sum` pin it.

## Threat model

See `docs/THREAT_MODEL.md`: what a verified operation proves (records unaltered, order, scope checked before every run, metadata only, receipt pins an archive), what it does not (completeness, tool correctness, operator honesty, authorization, firewall behaviour from a self-scan), the adversaries considered, and the known weak points in priority order.

## What is prepared today

Phases 0 and 1 are done: zero dependencies, clippy-clean under `-D warnings`, 98 tests. `lcoat-format` reads and writes every v1 file byte-identically (env records, NDJSON, canonical and `jq -S` JSON, timestamps, IDs). `lcoat-core` loads roots, targets, operations, scope snapshots, ledgers, evidence, findings and validation plans; computes readiness; verifies closeout, audit and archive packets, the trust chain, evidence artifacts and receipts; creates and replays receipts. The `lcoat` binary ships the read-only command surface (`op list|readiness|verify|audit-verify|archive-verify|trust-chain`, `scope status`, `evidence list|verify`, `finding list`, `ledger verify|checkpoint`, `receipt create|verify|replay`, `hash`, `scan`) and refuses the write-side verbs with a pointer to Lite until phase 2. Two behaviours already differ from Lite on purpose: an unset `LCOAT_ROOT` is an error, and no read-only command creates a directory.

Exit checks, all passing against the shell build at `23ba2d2`: `conformance/tamper.sh check` (eight tamper cases, identical verdicts), `conformance/readonly_diff.sh` (18 commands byte-identical after the documented normalizations), and the golden tests under `crates/*/tests/golden.rs`, whose expected outputs in `fixtures/expected/` were recorded from the shell. To pick up phase 2: the writers (`target add`, `op start/resume/close`, `evidence add`, `finding add`, report and packets, `adapter run`) as the `Operation<Active>` typestate, with `GO-project/internal/{operation,evidence,findings,report,packet,adapter}` as the reference and `cross_check.sh` stage 2 as the exit check.
