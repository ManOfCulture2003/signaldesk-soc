"""Deterministic event-time detections, with explicit bounded correlation windows."""
from collections import defaultdict
from datetime import datetime
import re

from .events import canonical, digest

RULES = {
    "SD-001": {"title": "Repeated authentication failures", "severity": "medium", "technique": "T1110.001", "description": "At least 5 failures for the same source IP, host and user in one UTC 5-minute bucket.", "triage": "Check whether the account owner mistyped a password or an approved service has stale credentials. Compare later successes and source ownership."},
    "SD-002": {"title": "Possible password spray", "severity": "high", "technique": "T1110.003", "description": "Failures against at least 5 distinct users from one IP to one host in one UTC 5-minute bucket.", "triage": "Review the targeted accounts, shared proxy/NAT use, approved scanners and successful logons. This pattern alone does not prove a shared password was tried."},
    "SD-003": {"title": "Successful login after repeated failures", "severity": "high", "technique": "T1110", "description": "A success preceded by at least 5 failures for the same host, IP and user within 10 minutes.", "triage": "Verify the user and source, determine if the successful session was expected, and inspect subsequent process activity. Escalate with evidence before any containment."},
    "SD-004": {"title": "Encoded PowerShell command", "severity": "medium", "technique": "T1059.001", "description": "Process command contains powershell/pwsh and an encoded-command switch.", "triage": "Inspect parent process and script provenance in the original endpoint logs. Administrators also use encoding; this is a heuristic, not a maliciousness verdict."},
    "SD-005": {"title": "Security audit log cleared", "severity": "high", "technique": "T1070.001", "description": "An audit_cleared event, including Windows Security event 1102.", "triage": "Check maintenance/change authorization and preceding activity. Preserve available logs. Clearing may be legitimate; do not clear logs to test this rule."},
}
RULESET_VERSION = "1"


def epoch(event):
    return datetime.fromisoformat(event["timestamp"]).timestamp()


def detect(events):
    events = sorted(events, key=lambda e: (e["timestamp"], e["id"]))
    failures = defaultdict(list)
    buckets = defaultdict(list)
    sprays = defaultdict(list)
    alerts = []

    def emit(rule, identity, evidence):
        evidence = sorted(evidence, key=lambda e: (e["timestamp"], e["id"]))
        alerts.append({"id": digest(canonical([RULESET_VERSION, rule, identity])), "rule_id": rule,
                       **RULES[rule], "first_seen": evidence[0]["timestamp"], "last_seen": evidence[-1]["timestamp"],
                       "host": evidence[-1]["host"], "evidence": [e["id"] for e in evidence],
                       "synthetic": all(e["synthetic"] for e in evidence), "ruleset_version": RULESET_VERSION})

    for event in events:
        key = (event["host"], event["src_ip"], event["user"], event["synthetic"])
        when = epoch(event)
        if event["kind"] == "auth_failure" and event["src_ip"] and event["user"]:
            failures[key].append(event)
            bucket = int(when // 300)
            buckets[(key, bucket)].append(event)
            sprays[(event["host"], event["src_ip"], event["synthetic"], bucket)].append(event)
        elif event["kind"] == "auth_success" and event["src_ip"] and event["user"]:
            prior = [f for f in failures[key] if 0 < when - epoch(f) <= 600]
            if len(prior) >= 5:
                emit("SD-003", event["id"], prior + [event])
        elif event["kind"] == "process_start" and re.search(r"\b(?:powershell|pwsh)(?:\.exe)?\b", event["command"], re.I):
            if re.search(r"(?:^|\s)-(?:enc|encodedcommand|e)\s+\S+", event["command"], re.I):
                emit("SD-004", event["id"], [event])
        elif event["kind"] == "audit_cleared":
            emit("SD-005", event["id"], [event])
    for key, group in buckets.items():
        if len(group) >= 5:
            emit("SD-001", key, group)
    for key, group in sprays.items():
        if len({e["user"] for e in group}) >= 5:
            emit("SD-002", key, group)
    return sorted(alerts, key=lambda a: (a["last_seen"], a["id"]), reverse=True)
