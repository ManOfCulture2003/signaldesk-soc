# Verification record

## Local verification, 2026-11-08

- Windows, Python 3.12.14, isolated virtual environment.
- 76 automated tests passed. Coverage includes parsing, invalid input, UTC equivalence, duplicate imports, transaction rollback, provenance, every rule, negative and boundary cases, out-of-order detection, case persistence, stale edits, API controls and CLI replay.
- `python -m pip check`: no broken requirements.
- `node --check signaldesk/static/app.js`: passed.
- Real Chrome browser: loaded the demo dashboard; inspected seven evidence events; closed a synthetic case with rationale; verified updated open/closed counts and retained history. Screenshot in `workspace.jpg` shows the running application, not a design mockup.
- Demo fixture: exactly 16 events and five expected alerts. Replay adds zero events/alerts.

An existing Starlette/httpx deprecation warning appears in the test environment. It is not a failed test, but the test-client dependency migration remains future maintenance work.

## Windows evidence limits

The built-in read-only collector successfully queried Windows and returned no matching events. Its child PowerShell process uses the native module directory so an inherited PowerShell 7 module path cannot prevent Windows PowerShell 5.1 from loading Get-WinEvent. Permission failures and collector failures have separate messages. No security settings or audit policies were changed. Windows XML ingestion is validated against generated native-format fixtures; a successful live-endpoint ingest is **not claimed**.

## CI

The workflow tests Python 3.11 and 3.13 on Ubuntu and Windows. Consult the actual GitHub Actions result for the commit you are reviewing; configuration alone is not a passing CI result. Test counts and results above describe local validation only.

## What these checks do not establish

They do not establish enterprise throughput, detection precision/recall on production data, forensic admissibility, compatibility with every Windows audit-policy configuration, or freedom from all defects. No production SOC deployment is claimed.
