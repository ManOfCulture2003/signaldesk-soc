"""Explicit local commands; importing the package does not start a server."""
import argparse
import json
from pathlib import Path

from .demo import demo_payload
from .store import Store


def main(argv=None):
    parser = argparse.ArgumentParser(description="SignalDesk SOC: local security event investigations")
    parser.add_argument("--db", type=Path, default=Path("data/signaldesk.sqlite"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Import labeled synthetic evidence and run detections")
    ingest = sub.add_parser("ingest", help="Import a local evidence file")
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--format", choices=["ndjson", "windows-xml"], default="ndjson")
    sub.add_parser("detect")
    sub.add_parser("stats")
    export = sub.add_parser("export")
    export.add_argument("alert_id")
    export.add_argument("output", type=Path)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)
    if args.command == "serve":
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(args.db), host="127.0.0.1", port=args.port)
        return
    store = Store(args.db)
    try:
        if args.command == "demo":
            result = {"import": store.ingest(demo_payload()), "detection": store.run_detection()}
        elif args.command == "ingest":
            from .events import MAX_BYTES
            with args.file.open("rb") as handle:
                payload = handle.read(MAX_BYTES + 1)
            result = store.ingest(payload, args.format)
        elif args.command == "detect":
            result = store.run_detection()
        elif args.command == "stats":
            result = store.stats()
        else:
            result = store.case(args.alert_id)
            # Exclusive creation avoids overwriting evidence or existing reports.
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2)
            print(f"Exported case to {args.output}")
            return
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
