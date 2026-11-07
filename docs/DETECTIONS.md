# Detection engineering

The source of truth is `signaldesk/detections.py`. Ruleset version 1 is included in deterministic alert identities. Rule logic changes that alter identity semantics should increment the version and document migration behavior.

SD-001 and SD-002 use **fixed UTC buckets** (`epoch // 300`), not sliding windows. Four failures just before a boundary and one just after do not trigger SD-001. The boundary regression makes this limitation explicit. Low-and-slow or distributed activity can evade the rules. Host and user comparisons are case-sensitive; normalize upstream if your source guarantees case-insensitivity.

SD-003 correlates only earlier failures within 600 seconds of a success. Exact simultaneous timestamps do not establish ordering and are excluded. Incoming batches may be out of order: detection sorts the complete retained dataset by UTC timestamp and content ID. The operation is bounded by the local 50,000-event cap and runs on demand, not continuously.

SD-004 recognizes common `-enc`, `-EncodedCommand` and `-e` switches. It does not decode or execute content, prove malicious intent, resolve renamed executables, or implement the full PowerShell command parser. Approved scripts and administrators may generate this signal. SD-005 can reflect authorized maintenance.

SD-002 detects a multi-account failure pattern consistent with spraying; logs do not reveal whether the same password was attempted. Shared NAT, proxies, scanners and service misconfiguration can create false positives. See [MITRE T1110.003](https://attack.mitre.org/techniques/T1110/003/).

## Validation strategy

- Golden demo: 16 events, exactly five expected rule IDs.
- Below-threshold, bucket-boundary and wrong-host/user negative cases.
- Success ordering and lookback expiry.
- Out-of-order replay determinism and separation of synthetic/imported evidence.
- Benign PowerShell command negative tests.
- Replay preserves analyst state; added evidence reopens a closed case.

These tests verify defined behavior on fixtures. They do not measure precision or recall against an enterprise environment. No fabricated efficacy percentage is reported.

## Tuning procedure

1. Preserve a labeled sample with benign and suspicious events.
2. Explain the source fields and proposed threshold/window change.
3. Add both expected-match and expected-nonmatch tests before changing logic.
4. Evaluate the rule on held-out data; report false positives and missed cases.
5. Record limitations and operational impact in the change description.
