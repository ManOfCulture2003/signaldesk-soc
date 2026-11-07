# Security boundaries

Run only on a trusted workstation using the supplied loopback-bound launcher. Do not expose the server through port forwarding, a tunnel, a public host, or a reverse proxy. There is no multi-user authentication, RBAC or TLS. Any local process with access to the app or SQLite file can read evidence; the owner label does not authenticate an analyst.

## Controls implemented

- Loopback binding by CLI and allowed Host headers.
- Ephemeral mutation token, same-origin checks and no permissive CORS.
- Local static assets, restrictive Content Security Policy and no HTML rendering of event values.
- File/event caps, strict schema validation, defusedxml, parameterized SQL and atomic imports.
- Optimistic case versions, required rationales and retained decision history.
- Synthetic fixtures separated from imported telemetry during correlation.

The case history is useful operational evidence, not a cryptographically signed or tamper-resistant audit trail. Original input hashes do not authenticate a source. The server trusts the local user and operating system. Detection heuristics have false positives and false negatives.

Never put raw host logs, credentials, real case exports, personal identifiers or database files in a public issue or commit. Report a suspected vulnerability to the repository owner without including sensitive evidence; reproduce it with a minimal synthetic fixture.
