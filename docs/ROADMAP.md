# Roadmap

Completed in v0.1: validated file ingestion, Windows XML adapter, deterministic correlation, event explorer, analyst workflow, evidence export, local UI, tests and CI.

Future work should be validated separately before claiming it works:

- Additional source adapters with real sanitized samples and field-mapping tests.
- Sliding-window correlation and detection tuning against labeled held-out datasets.
- Optional local collector with checkpoints, backpressure and documented retention.
- Integration with an established SIEM through tested export formats or APIs.
- Authentication/RBAC/TLS before any shared deployment.
- Indexing and incremental detection, with measured performance under load.
- Signed evidence manifests and externally anchored audit history if stronger integrity is required.

No live agent, enterprise deployment or commercial-SIEM integration is claimed by this release.
