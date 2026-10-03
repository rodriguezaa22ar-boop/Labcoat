# Atlas Operation Audit Packet

Generated: 2026-10-02T05:42:14Z
Operation: learning-op-001
Operation ID: learning-op-001
Operation Status: closed
Target: demo-learning-node

No raw artifact contents are included in this audit packet.

## Ledger

- Operation ledger: `/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/ledger.ndjson`
- Events: 17
- Ledger SHA256: 397996a303cc1b863cdafea8dbb0b8dba4ab2e5a5b6d58e54e5740bb45e05aa9
- Closeout verification: verified
- Closeout manifest: /home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/closeout/learning-op-001-closeout.md
- Closeout manifest SHA256: bff38f33333f9eae776c0440c5fce75e8baf7ffb0d9e6fc107ed075010153534
- Closeout verification problems: 0
- Accepted risks: 0
- Accepted-risk review packet: none
- Accepted-risk review packet freshness: missing
- Audit packet freshness: current

## Event Counts

```text
artifact.created                 1
audit.packet.generated           1
closeout.manifest.generated      1
finding.recorded                 2
handoff.generated                1
op.close.readiness               1
op.closed                        1
op.started                       1
report.generated                 2
scope.preflight                  6
```

## Audit Flags

```text
forced close: 2026-10-02T05:42:08Z readiness=attention-required readiness=attention-required evidence=1 open_findings=2 accepted_risks=0 expired_accepted_risks=0 pending_validation=0 report_freshness=current bundle_freshness=missing handoff_freshness=current closeout_freshness=missing review_packet_freshness=missing audit_packet_freshness=missing archive_packet_freshness=missing latest_report=/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/reports/learning-op-001-report.md latest_change=finding.recorded evidence_bundle=none handoff=/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/handoff/learning-op-001-handoff.md closeout=none review_packet=none audit_packet=none archive_packet=none force=1
note: closeout verification: verified manifest=/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/closeout/learning-op-001-closeout.md
```

## Timeline

```text
TS                   EVENT                        STATUS       CAPABILITY       TOOL       DETAIL
2026-10-02T05:39:55Z op.started                   ok           read-only        atlas      profile=htb-starting-point notes=authorized metadata-only learning operation using claude
2026-10-02T05:40:04Z scope.preflight              allowed      read-only        atlas      reason=add evidence artifact target=demo-learning-node
2026-10-02T05:40:04Z artifact.created             ok           read-only        atlas      evidence=ev_20261002T054004Z kind=scan-output sha256=fa0def3c96e0f68e7fe02036187b47485ab9aabe60919692770bae396c1267ad path=evidence/ev_20261002T054004Z/recon-output.txt
2026-10-02T05:40:06Z scope.preflight              allowed      read-only        atlas      reason=record finding target=demo-learning-node
2026-10-02T05:40:07Z finding.recorded             ok           read-only        atlas      finding=finding_20261002T054006Z level=observed severity=low status=open
2026-10-02T05:40:07Z scope.preflight              allowed      read-only        atlas      reason=record finding target=demo-learning-node
2026-10-02T05:40:07Z finding.recorded             ok           read-only        atlas      finding=finding_20261002T054007Z level=observed severity=low status=open
2026-10-02T05:40:12Z scope.preflight              allowed      read-only        atlas      reason=plan validation lane --help target=demo-learning-node
2026-10-02T05:40:18Z scope.preflight              allowed      read-only        atlas      reason=plan validation lane validate target=demo-learning-node
2026-10-02T05:40:24Z report.generated             ok           read-only        atlas      /home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/reports/learning-op-001-report.md.md
2026-10-02T05:41:37Z scope.preflight              allowed      read-only        atlas      reason=plan validation lane validate target=demo-learning-node
2026-10-02T05:41:59Z report.generated             ok           read-only        atlas      /home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/reports/learning-op-001-report.md
2026-10-02T05:42:02Z handoff.generated            ok           read-only        atlas      /home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/handoff/learning-op-001-handoff.md
2026-10-02T05:42:08Z op.close.readiness           attention-required read-only        atlas      readiness=attention-required evidence=1 open_findings=2 accepted_risks=0 expired_accepted_risks=0 pending_validation=0 report_freshness=current bundle_freshness=missing handoff_freshness=current closeout_freshness=missing review_packet_freshness=missing audit_packet_freshness=missing archive_packet_freshness=missing latest_report=/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/reports/learning-op-001-report.md latest_change=finding.recorded evidence_bundle=none handoff=/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/handoff/learning-op-001-handoff.md closeout=none review_packet=none audit_packet=none archive_packet=none force=1
2026-10-02T05:42:08Z op.closed                    ok           read-only        atlas      demo-learning-node readiness=attention-required evidence=1 open_findings=2 accepted_risks=0 expired_accepted_risks=0 pending_validation=0 report_freshness=current bundle_freshness=missing handoff_freshness=current closeout_freshness=missing review_packet_freshness=missing audit_packet_freshness=missing archive_packet_freshness=missing latest_report=/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/reports/learning-op-001-report.md latest_change=finding.recorded evidence_bundle=none handoff=/home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/handoff/learning-op-001-handoff.md closeout=none review_packet=none audit_packet=none archive_packet=none force=1
2026-10-02T05:42:10Z closeout.manifest.generated  ok           read-only        atlas      /home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/closeout/learning-op-001-closeout.md
2026-10-02T05:42:14Z audit.packet.generated       ok           read-only        atlas      /home/claude/rodriguezaa22ar-boop/atlas-trust-infrastructure/sessions/learning-op-001/audit/learning-op-001-audit.md
```
