import json
from types import SimpleNamespace
import pytest
from conftest import event, payload
from test_events import xml
from signaldesk.events import parse_payload
from signaldesk import detections, store as storage, windows


@pytest.mark.parametrize('raw', [b'{"host":"one","host":"two"}', b'['*2000+b']'*2000])
def test_ambiguous_or_deep_json_is_rejected(raw):
    with pytest.raises(ValueError):
        parse_payload(raw, 'ndjson')


@pytest.mark.parametrize('raw', [xml().replace(b'<EventRecordID>123</EventRecordID>', b''),
    xml().replace(b'</Events>', b'<Wrong/></Events>'),
    xml().replace(b'</EventData>', b'<Data Name="TargetUserName">other</Data></EventData>')])
def test_incomplete_and_ambiguous_xml_rejected_atomically(store, raw):
    with pytest.raises(ValueError):
        store.ingest(raw, 'windows-xml')
    assert store.stats()['events'] == store.stats()['imports'] == 0


def test_detection_output_budget_rolls_back(store, monkeypatch):
    rows = [event(i, timestamp='2026-01-15T12:00:00Z') for i in range(10)]
    rows += [event(100+i, kind='auth_success', timestamp='2026-01-15T12:00:10Z') for i in range(20)]
    store.ingest(payload(rows))
    monkeypatch.setattr(detections, 'MAX_EVIDENCE_REFERENCES', 30)
    with pytest.raises(ValueError, match='output limit'):
        store.run_detection()
    assert store.alerts() == []
    with store.connection() as db:
        assert db.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == 0


def test_detection_work_budget(store, monkeypatch):
    store.ingest(payload([event(i) for i in range(6)] + [event(99, kind='auth_success', timestamp='2026-01-15T12:01:00Z')]))
    monkeypatch.setattr(detections, 'MAX_CORRELATION_CHECKS', 1)
    with pytest.raises(ValueError, match='work limit'):
        store.run_detection()
    assert store.alerts() == []


def test_duplicate_variations_cannot_grow_archive_without_limit(store, monkeypatch):
    raw = payload([event()])
    monkeypatch.setattr(storage, 'MAX_IMPORT_BYTES', len(raw)+1)
    store.ingest(raw)
    assert store.ingest(raw)['duplicates'] == 1
    with pytest.raises(ValueError, match='archive limit'):
        store.ingest(raw+b'\n')
    assert store.stats()['imports'] == 1


def test_windows_collector_uses_native_xml_and_deduplicates(store, monkeypatch):
    monkeypatch.setattr(windows, 'os', SimpleNamespace(name='nt', environ={'SystemRoot':r'C:\Windows'}))
    calls = []
    def run(command, **kwargs):
        calls.append((command,kwargs))
        return SimpleNamespace(stdout=json.dumps({'status':'available','xml':xml().decode()}).encode())
    monkeypatch.setattr(windows.subprocess, 'run', run)
    assert windows.collect(store)['import']['inserted'] == 1
    assert windows.collect(store)['import']['duplicates'] == 1
    assert store.stats()['synthetic_events'] == 0
    assert calls[0][1]['timeout'] == 20
    assert calls[0][1]['env']['PSModulePath'].replace('\\','/').endswith('WindowsPowerShell/v1.0/Modules')
    assert 'ExecutionPolicy' not in ' '.join(calls[0][0])


@pytest.mark.parametrize('response', [{'status':'no_events'}, {'status':'unavailable'}, {'status':'available','xml':'bad'}])
def test_windows_no_evidence_is_never_reported_safe(store, monkeypatch, response):
    monkeypatch.setattr(windows, 'os', SimpleNamespace(name='nt', environ={'SystemRoot':r'C:\Windows'}))
    monkeypatch.setattr(windows.subprocess, 'run', lambda *a,**kw: SimpleNamespace(stdout=json.dumps(response).encode()))
    result=windows.collect(store)
    assert result['status'] in ('no_events','unavailable')
    assert store.stats()['events'] == 0


@pytest.mark.parametrize('status', ['permission_denied','collector_unavailable','unavailable','no_events'])
def test_windows_failure_reasons_stay_distinct(store, monkeypatch, status):
    monkeypatch.setattr(windows, 'os', SimpleNamespace(name='nt', environ={'SystemRoot':r'C:\Windows'}))
    monkeypatch.setattr(windows.subprocess, 'run', lambda *a,**kw: SimpleNamespace(stdout=json.dumps({'status':status}).encode()))
    assert windows.collect(store)['status'] == status
    assert store.stats()['events'] == 0
