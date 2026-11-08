"""Explicit read-only collection from this PC. Never changes audit policy."""
import json
import os
from pathlib import Path
import subprocess

from .events import MAX_BYTES

SCRIPT = r"""
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
try {
  $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4688,1102; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 200 -ErrorAction Stop)
  @{status='available'; xml=('<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join "`n") + '</Events>')} | ConvertTo-Json -Compress
} catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
    @{status='no_events'} | ConvertTo-Json -Compress
  } elseif ($_.CategoryInfo.Category -eq 'PermissionDenied' -or $_.Exception -is [UnauthorizedAccessException]) {
    @{status='permission_denied'} | ConvertTo-Json -Compress
  } elseif ($_.FullyQualifiedErrorId -like '*Module*' -or $_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
    @{status='collector_unavailable'} | ConvertTo-Json -Compress
  } else {
    @{status='unavailable'} | ConvertTo-Json -Compress
  }
}
"""


def collect(store):
    if os.name != "nt":
        return {"status": "unavailable", "message": "Windows Security collection is only available on Windows. Import supported logs on other systems."}
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    # PowerShell 7's inherited module paths can break Windows PowerShell 5.1.
    # Restrict this child to the built-in Windows modules; do not edit the OS.
    environment = os.environ.copy()
    environment["PSModulePath"] = str(executable.parent / "Modules")
    try:
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", SCRIPT],
            capture_output=True, timeout=20, check=True, env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if len(result.stdout) > MAX_BYTES:
            raise ValueError("Collection exceeds the import size limit")
        # PowerShell's redirected output must use UTF-8 for non-ASCII accounts.
        data = json.loads(result.stdout.decode("utf-8-sig"))
        if data.get("status") == "no_events":
            return {"status": "no_events", "message": "No matching Security events in the last 24 hours. This does not prove the PC is safe or auditing is enabled."}
        if data.get("status") == "permission_denied":
            return {"status": "permission_denied", "message": "Windows denied access to the Security log. Use an authorized log export or ask the device administrator for access. No security settings were changed."}
        if data.get("status") == "collector_unavailable":
            return {"status": "collector_unavailable", "message": "The Windows event-reading module could not load. This is a collector setup problem, not evidence of a permissions failure."}
        if data.get("status") != "available":
            return {"status": "unavailable", "message": "Windows event collection failed for an undetermined reason. No data was imported; this does not establish that access was denied."}
        imported = store.ingest(data["xml"].encode("utf-8"), "windows-xml")
        return {"status": "available", "message": "Read up to 200 recent events from this PC. Run detections to analyze them; this is not continuous monitoring.", "import": imported}
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return {"status": "unavailable", "message": "Collection failed or returned invalid data. No successful collection is claimed. Check Windows log access and try again."}
