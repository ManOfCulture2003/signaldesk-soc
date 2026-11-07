# Synthetic case: authentication failures followed by success

**Source:** the deterministic lab fixture in `signaldesk/demo.py`. This is generated telemetry, not an incident from an organization. No login attempts or PowerShell commands are executed by the demo.

## Timeline

On 2026-01-15, the fixture records six authentication failures for `alex` on `LAB-WS01` from documentation address `192.0.2.25`, between 12:00:00 and 12:00:50 UTC. A success follows at 12:01:05. SD-001 highlights the failure cluster; SD-003 correlates the later success.

Other fixture events produce a separate possible spray alert, an encoded-command alert and an audit-clear alert. Their proximity is a reason to investigate, not enough evidence to assert a single causal attack chain. A normal login and an unencoded inventory script provide benign comparison events.

## Analysis

The evidence establishes a failure-then-success pattern for one host/account/source combination. It does not establish who controlled the source, why authentication failed, what password was used, or whether the successful session was authorized. Needed context includes account-owner confirmation, source ownership, original authentication status/logon type, change records and subsequent endpoint telemetry.

## Reproduce and document

1. Load the demo, open SD-003 and verify all seven evidence records.
2. Inspect the import hash and timestamps rather than relying only on the alert title.
3. Set status to investigating and document the evidence and missing context.
4. For this known generated fixture, close as benign_positive with rationale: the rule correctly identified the pattern in an authorized synthetic test. This is not a verdict on an unknown real-world login.
5. Export the case, restart the app and verify that the decision persists.
6. Replay the demo and verify no duplicate alert or loss of rationale.

No containment is performed. In a real authorized environment, escalation and response would follow the organization's incident-response procedure.
