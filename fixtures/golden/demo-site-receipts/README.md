# Demo Site Receipt Chain

This directory contains a synthetic three-receipt chain for M138. It binds the
public demo path to `atlas.receipt.v1` verification and
`atlas.receipt_replay.v1` replay output without making the demo operational.

Run from the repository root:

```bash
./tools/atlas/bin/atlas receipt replay \
  examples/receipt/demo-site/demo-site-boundary.json \
  examples/receipt/demo-site/demo-site-packet.json \
  examples/receipt/demo-site/demo-site-replay.json \
  --json
```

Expected chain order:

| Index | Receipt | Linkage |
| --- | --- | --- |
| 1 | `demo-site-boundary.json` | `prev_hash: null` |
| 2 | `demo-site-packet.json` | `prev_hash` equals `demo-site-boundary.json` `event_hash` |
| 3 | `demo-site-replay.json` | `prev_hash` equals `demo-site-packet.json` `event_hash` |

The final checkpoint is:

```text
chain_head_event_hash: bb79b7ba13bfc8b657a532c9a07cd3eb9c27020514c903e9cda4385f6e5012eb
chain_head_receipt_hash: f0ba44315536c8397b4a42bc1a5b18bf3992b13752b83e465bed0850a1ea6c38
```

Boundary:

- synthetic only
- metadata-only
- no execution
- no backend
- no persistence
- no hidden state
- no production deployability claim
- no raw artifacts or raw request/response bodies

The canonicalization contract is documented at
`docs/schemas/receipt-canonicalization.v1.md`.
