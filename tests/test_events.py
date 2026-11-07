import json
import pytest

from signaldesk.events import MAX_BYTES, normalize, parse_payload
from conftest import event, payload


def test_timezone_normalization_and_identity():
    a = normalize(event(timestamp="2026-01-15T07:00:01-05:00"))
    b = normalize(event(timestamp="2026-01-15T12:00:01Z"))
    assert a == b
    assert a['timestamp'] == '2026-01-15T12:00:01.000000+00:00'


@pytest.mark.parametrize('change', [{"timestamp": "2026-01-15T12:00:01"}, {"src_ip": "not-an-ip"},
    {"kind": "unknown"}, {"host": ""}, {"event_id": 1}, {"synthetic": "true"}, {"secret": "x"},
    {"command": "x"*8193}, {"user": None}])
def test_invalid_schema(change):
    with pytest.raises(ValueError):
        normalize(event(**change))


@pytest.mark.parametrize('raw', [b'', b'{not json}', b'[]', b'\xff', b'{}', b'x'*(MAX_BYTES+1)])
def test_invalid_payload(raw):
    with pytest.raises(ValueError):
        parse_payload(raw,'ndjson')


def xml(code='4625', data='<EventData><Data Name="TargetUserName">alex</Data><Data Name="IpAddress">192.0.2.1</Data></EventData>'):
    return f'''<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{code}</EventID><TimeCreated SystemTime="2026-01-15T12:00:00Z"/><EventRecordID>123</EventRecordID><Computer>LAB</Computer></System>{data}</Event></Events>'''.encode()


@pytest.mark.parametrize('code,kind', [('4625','auth_failure'),('4624','auth_success'),('4688','process_start'),('1102','audit_cleared')])
def test_windows_adapter(code,kind):
    result=parse_payload(xml(code),'windows-xml')[0]
    assert result['kind']==kind
    assert result['event_id']==code+':123'
    assert result['synthetic'] is False


def test_windows_userdata_log_clear():
    result=parse_payload(xml('1102','<UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>'),'windows-xml')[0]
    assert result['user']=='admin'


def test_xml_entities_and_unsupported_events_rejected():
    with pytest.raises(ValueError):
        parse_payload(b'<!DOCTYPE a [<!ENTITY x "boom">]><Events>&x;</Events>','windows-xml')
    with pytest.raises(ValueError):
        parse_payload(xml('9999'),'windows-xml')


def test_duplicate_import_and_atomic_validation(store):
    raw=payload([event(),event(2)])
    assert store.ingest(raw)['inserted']==2
    assert store.ingest(raw)['duplicates']==2
    assert store.stats()['imports']==1
    with pytest.raises(ValueError):
        store.ingest(payload([event(3),event(4,src_ip='bad')]))
    assert store.stats()['events']==2
    assert store.stats()['imports']==1


def test_original_import_bytes_and_provenance(store):
    raw=payload([event()])
    result=store.ingest(raw)
    with store.connection() as db:
        assert db.execute('SELECT payload FROM imports').fetchone()[0]==raw
        assert db.execute('SELECT import_sha FROM provenance').fetchone()[0]==result['import_sha256']
