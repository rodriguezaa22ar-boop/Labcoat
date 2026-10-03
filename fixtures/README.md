# Fixtures

`golden/` is copied from Lab Coat Lite (`GO-project/testdata/golden`, v0.1.4)
and is read-only. It is the inherited specification: real state written by
the Atlas shell build at commit `23ba2d2`, with hashes recorded inside it.

| Path | What it is | Used by |
| --- | --- | --- |
| `golden/learning-op-001/` | A complete closed operation (18 ledger events, one artifact, four packets) | ledger/evidence/packet verifiers |
| `golden/demo-site-receipts/` | A three-receipt chain with recorded `event_hash`/`receipt_hash` | canonical JSON, receipt verify/replay |
| `golden/nmap/sample.xml` | nmap XML output | adapter parser |
| `golden/profiles/` | scope profiles (`htb-starting-point`, `default`) | scope preflight |
| `golden/targets/`, `golden/reports/` | target record and report from the same run | envfile, report rendering |

Known values the tests pin:

- `learning-op-001/ledger.ndjson`: 18 events, `sha256=ba36a56433f5a4153a1d430bb4632bfe7bdcc989adbf5438ba1ea667758f0c6f`
- `learning-op-001/evidence/ev_20261002T054004Z/recon-output.txt`: `fa0def3c96e0f68e7fe02036187b47485ab9aabe60919692770bae396c1267ad`
- receipt chain: boundary `80b04f94…` → packet `cb4509fc…` → replay `bb79b7ba…` (event hashes)

`expected/` holds outputs recorded from the shell build (`23ba2d2`) against
`golden/`: `op readiness`, `op verify`, `op audit-verify`, `op archive-verify`,
`op trust-chain` for `learning-op-001`, and `receipt verify --json` / `receipt
replay` for the demo-site receipts. The Rust golden tests compare against them
byte for byte. The packet verifiers can only be exercised where the shell
checkout that wrote the golden packets exists (they record absolute paths);
elsewhere that one test prints a note and skips, and `conformance/tamper.sh`
plus `conformance/readonly_diff.sh` are the gate.

`tamper/*.expect` holds the shell oracle's verdicts for eight tamper cases,
recorded by `conformance/tamper.sh record`. The first line describes the
case; the rest are verdict lines another implementation must reproduce
(`tamper.sh check <bin> <rootvar>`). Lite v0.1.4 matches all eight. Note the
`edit_artifact` case: every shell verifier says `verified`, which is the gap
format 1.1 closes with the evidence manifest.
