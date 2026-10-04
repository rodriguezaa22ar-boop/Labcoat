# Threat model

What the Lab Coat trust chain proves, what it does not, and who it protects against. One page; if a claim is not here, Lab Coat does not make it.

## What a verified operation proves

Given an operation whose packets, evidence and receipts all verify:

1. **The records were not altered after capture.** Every evidence file re-hashes to the value recorded when it was added; every packet re-hashes to the value the next packet anchored; the ledger file re-hashes to the value the closeout, audit and archive packets recorded. With format 1.1, each ledger event also re-hashes to its `event_hash`, and each `prev_hash` matches the event before it, so a rewritten or removed event is named, not just detected.
2. **The order of events is the order recorded.** The ledger is append-only and chained; packets embed one another's hashes in a fixed generation order.
3. **Every tool run was checked against the declared scope first.** A `scope.preflight` event precedes every `adapter.started`, and the preflight names the target and capability tier the run was approved for. Runs the guard refused appear as `adapter.refused` with no `adapter.started`.
4. **No raw tool output, secret or credential is in any packet or receipt.** Writers accept only scanned metadata; the scanner's patterns are those of the shell build and are published.
5. **A receipt pins a specific archive.** Its `artifact_ref` carries the archive's hash, and a receipt chain orders receipts the same way the ledger orders events.

## What it does not prove

- **Completeness.** That the findings are all the findings. A clean trust chain with one scan is a clean record of one scan.
- **Tool correctness.** nmap's verdict is nmap's. Lab Coat records what the tool said and that the output was not altered afterwards; it does not vouch for the tool.
- **Operator honesty.** The operator declares the scope, the target and (for the `script` adapter) the tier. The chain proves the declaration was recorded before the run, not that it was true. Approval records (Tier 3) are self-authorized in a single-operator lab.
- **Authorization.** That the operator was allowed to assess the target. Lab Coat records that they said so.
- **Availability of referenced artifacts.** A receipt proves what an archive's hash was; it does not store the archive.
- **Firewall behaviour from a self-scan.** A scan run on the target host bypasses that host's own firewall. Format 1.1 records the vantage so a reader can tell; it does not make a self-scan mean more than it does.
- **Anything about the host's security beyond the ports and configuration captured.** No authenticated testing, no vulnerability assessment above Tier 3.

## Adversaries considered

| Adversary | Can they | Defence |
| --- | --- | --- |
| Someone who later edits the records (including the operator) | change an evidence file, a packet, a ledger event, a receipt | hashes anchored in later packets; chained ledger names the event; `evidence verify` re-hashes artifacts. **Limit:** the chain cannot see its own tail removed; a ledger truncated before any packet anchors it is caught only against a recorded `ledger checkpoint` head (`conformance/tamper_rust.sh`, case 6) |
| A tool with malicious output, or a scanned host that lies | inject content into packets or the operator's terminal | output goes only into a hashed evidence file; packets hold hashes and short scanned labels; nmap ports and protocols are validated and service banners have control, bidi and invisible characters replaced and are length-capped before printing; every parser is fuzzed with invariants (`crates/lcoat-fuzz`, cargo-fuzz in CI) |
| An operator making a mistake | scan an out-of-scope host; run an intrusive scan; leave the lab root unset | target comes from scope, never from arguments; argument allowlists; tier ceiling; unset root is an error |
| An operator acting in bad faith | declare a wrong tier for a `script` run; describe a finding dishonestly | **not defended**: recorded, not enforced; this is a lab tool for authorized self-assessment |
| Someone with write access to the lab root during the run | append or rewrite events concurrently | exclusive lock on the ledger during appends; chain detects rewrites after the fact; **not defended** against root-level tampering while the operation is live |
| Supply chain | compromise a dependency | library crates have no dependencies; the CLI has none; CI runs `cargo deny`; releases ship `SHA256SUMS` |

## Out of scope

Multi-user authorization, key management for more than one operator, remote attestation of the host the tool runs on, and anything that would make Lab Coat a server. If those are needed, Lab Coat's records are inputs to that system, not a substitute for it.

## Known weak points, in priority order

1. The `script` adapter's tier is declared, not derived. Mitigation is documentary (the ledger says `declared`); a stronger mitigation (an allowlist of known read-only commands) is a candidate for 0.3.
2. Approvals in a single-operator lab are self-granted. The record is still useful (it shows intent and timing) but is not a control.
3. The scanner is pattern-based. New credential formats need new patterns; the fixture set should grow with each one found in the field.
4. Truncation of a live ledger is undetectable from the ledger alone (see the first adversary row). Keeping `ledger checkpoint` output outside the lab root, or a receipt chain across checkpoints, is the operator's job until signatures land in phase 4.
