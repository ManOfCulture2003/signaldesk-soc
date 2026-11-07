"""Deterministic synthetic telemetry only. No attacks or commands are executed."""
import json
from datetime import datetime, timedelta, timezone


def demo_payload():
    base = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    rows = []

    def add(seconds, kind, user="alex", ip="192.0.2.25", command=""):
        rows.append({"timestamp": (base + timedelta(seconds=seconds)).isoformat(), "host": "LAB-WS01",
                     "source": "synthetic_fixture", "event_id": str(len(rows) + 1), "kind": kind,
                     "user": user, "src_ip": ip, "command": command, "synthetic": True})

    for i in range(6):
        add(i * 10, "auth_failure")
    add(65, "auth_success")
    for i, user in enumerate(("morgan", "lee", "jordan", "pat", "sam")):
        add(80 + i * 10, "auth_failure", user, "198.51.100.10")
    add(150, "process_start", command="powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGwAYQBiACcA")
    add(180, "audit_cleared", ip="")
    add(210, "auth_success", "casey", "192.0.2.40")
    add(220, "process_start", "casey", "", "powershell.exe -File approved_inventory.ps1")
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
