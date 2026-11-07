import json

import pytest

from signaldesk.events import normalize
from signaldesk.store import Store


def event(n=1, **changes):
    row = {"timestamp": f"2026-01-15T12:00:{n:02d}Z", "host": "lab", "source": "test",
           "event_id": str(n), "kind": "auth_failure", "user": "alex", "src_ip": "192.0.2.1", "synthetic": True}
    row.update(changes)
    return row


def payload(rows):
    return ("\n".join(json.dumps(r) for r in rows)+"\n").encode()


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "events.sqlite")
