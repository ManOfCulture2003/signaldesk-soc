# Architecture and API

`events.py` validates and normalizes input. `store.py` manages transactions, evidence, provenance and case history. `detections.py` is a deterministic pure function over normalized events. `api.py` exposes a local HTTP interface; `cli.py` supplies import, detection, export and server commands. The UI renders event values through `textContent`, never raw HTML.

SQLite uses parameterized queries, foreign keys and short-lived connections. Ingest/detection/triage acquire a write transaction. All input rows validate before ingestion begins. A failed write rolls back. Detection rescans retained events, upserts deterministic alerts, and reopens a case if its evidence changes. It does not erase analyst history. Owner is a descriptive field, not an authenticated identity.

## API

OpenAPI schema: `GET /openapi.json`. No externally hosted Swagger assets are required.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /api/health | Version and local mode |
| GET | /api/session | Ephemeral browser mutation token |
| GET | /api/stats | Event, import and alert counts |
| GET | /api/rules | Detection catalog |
| GET | /api/events | Exact filters: host, user, src_ip, kind; limit 1–500, offset ≥0 |
| POST | /api/import?format=ndjson | Raw UTF-8 body; also windows-xml |
| POST | /api/detect | Run rules against retained events |
| GET | /api/alerts | Alert queue |
| GET | /api/alerts/{id} | Evidence and history |
| POST | /api/alerts/{id}/triage | version, status, disposition, owner, note |
| GET | /api/alerts/{id}/export | Download JSON report |

Private API routes require an authenticated local session. `POST /auth/login` takes the terminal access key; `POST /auth/logout` revokes the session. `GET /healthz` exposes only basic readiness. SignalDesk mutation POST requests also require `X-SignalDesk-Token` from the local session endpoint. Browser origins must match the server origin. This protects HTTP access without creating multi-user tenants. OS administrators and same-user processes remain outside this boundary. HTTP 400 indicates invalid import/decision, 403 invalid token/origin, 404 missing case, 409 stale case version, 413 oversized body and 422 invalid API parameter types.

## Storage and operations

Default database: the current OS user’s SignalDeskSOC data directory (see README). Explicit `--db` still selects a different file. Stop the application before copying the database for a simple consistent backup. Restore by selecting the copied database with `--db`. There is no automatic purge, cloud backup, background service or schema migration framework in v0.1. Use separate databases for separate investigations. Local OS account permissions protect the files; the application does not encrypt them.

`POST /api/collect/windows` performs a one-shot read under existing OS permissions. It is authenticated and requires the mutation header. It does not run detection automatically.
