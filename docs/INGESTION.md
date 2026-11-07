# Import formats

## Normalized NDJSON

One object per UTF-8 line. Unknown fields are rejected to catch accidental schema mismatches. Preserve vendor-specific data in your original evidence archive; do not invent a mapping.

```json
{"timestamp":"2026-01-15T12:00:00Z","host":"LAB-WS01","source":"lab_auth","event_id":"1001","kind":"auth_failure","user":"alex","src_ip":"192.0.2.25","command":"","synthetic":true}
```

Required strings: `timestamp`, `host`, `source`, `event_id`, `kind`. Timestamp must include a timezone and is normalized to UTC microseconds. `kind` must be `auth_failure`, `auth_success`, `process_start` or `audit_cleared`.

Optional: `user`, `src_ip`, `command` default to empty strings. IP must be valid IPv4/IPv6 or empty. `synthetic` defaults to false and must be a JSON boolean. Label generated telemetry true. Authentication correlation requires both user and source IP. Missing identities remain searchable but do not enter authentication rules. Synthetic and imported records are never correlated together.

Event IDs are a SHA-256 digest of canonical normalized content, including source record ID and synthetic label. Equivalent UTC timestamps deduplicate. Different source IDs or changed content remain distinct. This does not deduplicate the same activity described by different products.

## Windows Security XML

The adapter accepts a single `<Event>` or an `<Events>` wrapper containing native Event XML. It maps:

| ID | Normalized kind | Relevant fields |
| --- | --- | --- |
| 4624 | auth_success | TimeCreated, Computer, TargetUserName, IpAddress |
| 4625 | auth_failure | Same as above |
| 4688 | process_start | TargetUserName or SubjectUserName, CommandLine |
| 1102 | audit_cleared | SubjectUserName in EventData or UserData/LogFileCleared |

The source record ID combines EventID and EventRecordID. Unsupported IDs are rejected, not silently dropped. Windows may omit network addresses and command lines. The adapter does not guess them. XML entity expansion is disabled using defusedxml.

Read-only export from a Windows machine you administer:

```powershell
pwsh -File scripts/export-windows-events.ps1 -OutputPath data/windows-events.xml -MaxEvents 200
.\.venv\Scripts\python.exe -m signaldesk.cli --db data/windows.sqlite ingest data/windows-events.xml --format windows-xml
.\.venv\Scripts\python.exe -m signaldesk.cli --db data/windows.sqlite detect
.\.venv\Scripts\python.exe -m signaldesk.cli --db data/windows.sqlite serve
```

With Windows PowerShell 5.1, replace `pwsh` with `powershell`. Access to Security logs may require an elevated terminal or a suitable existing permission. The exporter does not grant permissions, change audit policy, execute a test attack, or clear any logs. It refuses to overwrite an existing export. If there are no matching events it reports that explicitly.

The process command-line field requires the appropriate Windows auditing configuration; absent command lines cannot trigger SD-004. Consult [Microsoft's 4688 documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688). Configure auditing only in a lab you own; enabling command-line logging can capture sensitive arguments.

## Original evidence

Each import stores the exact bytes, format, import time and SHA-256 in SQLite. Provenance links normalized events to their imports. Case reports contain normalized evidence and these hashes, not the entire source file. Keep the original file/database if you need to reproduce parsing. Hashes detect differences when compared with a trusted copy; they do not make a locally editable database tamper-proof or establish forensic chain of custody.
