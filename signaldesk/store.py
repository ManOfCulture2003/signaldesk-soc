"""Transactional SQLite evidence, alerts and analyst history."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from .detections import detect
from .events import canonical, parse_payload

MAX_STORED_EVENTS = 50000


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class Conflict(ValueError):
    pass


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
                    host TEXT NOT NULL, kind TEXT NOT NULL, user TEXT NOT NULL, src_ip TEXT NOT NULL,
                    synthetic INTEGER NOT NULL, body TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS event_time ON events(timestamp);
                CREATE TABLE IF NOT EXISTS imports (sha256 TEXT PRIMARY KEY, imported_at TEXT NOT NULL,
                    format TEXT NOT NULL, payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS provenance (event_id TEXT REFERENCES events(id),
                    import_sha TEXT REFERENCES imports(sha256), PRIMARY KEY(event_id, import_sha));
                CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, body TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new', disposition TEXT NOT NULL DEFAULT '',
                    owner TEXT NOT NULL DEFAULT '', version INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL REFERENCES alerts(id), at TEXT NOT NULL,
                    action TEXT NOT NULL, body TEXT NOT NULL);
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, payload, format="ndjson"):
        events = parse_payload(payload, format)
        sha = hashlib.sha256(payload).hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO imports VALUES (?,?,?,?)", (sha, now(), format, payload))
            added = 0
            for event in events:
                added += db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?)",
                    (event["id"], event["timestamp"], event["host"], event["kind"], event["user"],
                     event["src_ip"], int(event["synthetic"]), canonical(event))).rowcount
                db.execute("INSERT OR IGNORE INTO provenance VALUES (?,?)", (event["id"], sha))
            if db.execute("SELECT COUNT(*) FROM events").fetchone()[0] > MAX_STORED_EVENTS:
                raise ValueError("Local database limit is 50000 events; use a separate database for another investigation")
            return {"received": len(events), "inserted": added, "duplicates": len(events) - added, "import_sha256": sha}

    def run_detection(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            events = [json.loads(row[0]) for row in db.execute("SELECT body FROM events ORDER BY timestamp,id")]
            found = detect(events)
            created = updated = 0
            for alert in found:
                body = canonical(alert)
                previous = db.execute("SELECT body FROM alerts WHERE id=?", (alert["id"],)).fetchone()
                if previous is None:
                    db.execute("INSERT INTO alerts(id,body) VALUES (?,?)", (alert["id"], body))
                    db.execute("INSERT INTO audit(alert_id,at,action,body) VALUES (?,?,?,?)",
                               (alert["id"], now(), "detected", canonical({"ruleset_version": alert["ruleset_version"]})))
                    created += 1
                elif previous[0] != body:
                    db.execute("UPDATE alerts SET body=?,version=version+1,status='new',disposition='' WHERE id=?", (body, alert["id"]))
                    db.execute("INSERT INTO audit(alert_id,at,action,body) VALUES (?,?,?,?)",
                               (alert["id"], now(), "evidence_updated", canonical({"reason": "New matching evidence; reopened for review"})))
                    updated += 1
            return {"matched": len(found), "created": created, "updated": updated}

    def events(self, *, host="", kind="", user="", src_ip="", limit=100, offset=0):
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("Invalid pagination")
        clauses, values = [], []
        for field, value in (("host", host), ("kind", kind), ("user", user), ("src_ip", src_ip)):
            if value:
                clauses.append(field + "=?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connection() as db:
            total = db.execute("SELECT COUNT(*) FROM events" + where, values).fetchone()[0]
            rows = db.execute("SELECT body FROM events" + where + " ORDER BY timestamp,id LIMIT ? OFFSET ?", values + [limit, offset])
            return {"total": total, "items": [json.loads(row[0]) for row in rows], "offset": offset, "limit": limit}

    @staticmethod
    def alert_row(row):
        return {**json.loads(row["body"]), **{key: row[key] for key in ("status", "disposition", "owner", "version")}}

    def alerts(self):
        with self.connection() as db:
            rows = [self.alert_row(row) for row in db.execute("SELECT * FROM alerts")]
            return sorted(rows, key=lambda a: (a["last_seen"], a["id"]), reverse=True)

    def case(self, alert_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if row is None:
                raise KeyError(alert_id)
            alert = self.alert_row(row)
            evidence = []
            for event_id in alert["evidence"]:
                event = json.loads(db.execute("SELECT body FROM events WHERE id=?", (event_id,)).fetchone()[0])
                event["import_sha256"] = [r[0] for r in db.execute("SELECT import_sha FROM provenance WHERE event_id=? ORDER BY import_sha", (event_id,))]
                evidence.append(event)
            history = [{"id": r["id"], "at": r["at"], "action": r["action"], **json.loads(r["body"])}
                       for r in db.execute("SELECT * FROM audit WHERE alert_id=? ORDER BY id", (alert_id,))]
            return {"schema_version": 1, "alert": alert, "evidence": evidence, "history": history}

    def triage(self, alert_id, *, version, status, disposition="", owner="", note=""):
        if type(version) is not int or version < 1:
            raise ValueError("version must be a positive integer")
        if status not in ("new", "investigating", "closed"):
            raise ValueError("Invalid status")
        if (status == "closed" and disposition not in ("true_positive", "false_positive", "benign_positive")) or (status != "closed" and disposition):
            raise ValueError("Closed cases require a disposition; open cases must not have one")
        if not isinstance(note, str) or not note.strip() or len(note) > 4000:
            raise ValueError("A triage rationale of 1 to 4000 characters is required")
        if not isinstance(owner, str) or len(owner) > 100:
            raise ValueError("Owner must be at most 100 characters")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT version FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if row is None:
                raise KeyError(alert_id)
            if row[0] != version:
                raise Conflict("Case changed; reload before saving")
            db.execute("UPDATE alerts SET status=?,disposition=?,owner=?,version=version+1 WHERE id=?",
                       (status, disposition, owner.strip(), alert_id))
            db.execute("INSERT INTO audit(alert_id,at,action,body) VALUES (?,?,?,?)", (alert_id, now(), "triage",
                       canonical({"status": status, "disposition": disposition, "owner": owner.strip(), "note": note.strip()})))
        return self.case(alert_id)

    def stats(self):
        with self.connection() as db:
            count = db.execute("SELECT COUNT(*),COALESCE(SUM(synthetic),0),MIN(timestamp),MAX(timestamp) FROM events").fetchone()
            statuses = dict(db.execute("SELECT status,COUNT(*) FROM alerts GROUP BY status"))
            return {"events": count[0], "synthetic_events": count[1], "first_event": count[2], "last_event": count[3],
                    "imports": db.execute("SELECT COUNT(*) FROM imports").fetchone()[0], "alerts": statuses}
