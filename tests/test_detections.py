import pytest

from signaldesk.demo import demo_payload
from signaldesk.detections import detect
from signaldesk.events import normalize, parse_payload
from conftest import event


def rules(rows):
    return [a['rule_id'] for a in detect([normalize(r) for r in rows])]


def test_demo_has_exactly_five_expected_alerts():
    alerts=detect(parse_payload(demo_payload(),'ndjson'))
    assert sorted(a['rule_id'] for a in alerts)==['SD-001','SD-002','SD-003','SD-004','SD-005']
    assert all(a['evidence'] and a['synthetic'] for a in alerts)


def test_below_threshold_and_bucket_boundary():
    assert rules([event(i) for i in range(1,5)])==[]
    assert rules([event(i) for i in range(1,6)])==['SD-001']
    rows=[event(i,timestamp=f'2026-01-15T12:04:{55+i:02d}Z') for i in range(1,5)]
    rows.append(event(5,timestamp='2026-01-15T12:05:00Z'))
    assert rules(rows)==[] # Fixed buckets intentionally do not cross boundaries.


def test_spray_requires_distinct_users_and_same_host():
    assert 'SD-002' not in rules([event(i) for i in range(1,7)])
    assert 'SD-002' in rules([event(i,user=f'user{i}') for i in range(1,6)])
    assert 'SD-002' not in rules([event(i,user=f'user{i}',host=f'host{i}') for i in range(1,6)])


def test_success_requires_preceding_failures_within_window():
    failures=[event(i) for i in range(1,6)]
    assert 'SD-003' in rules(failures+[event(10,kind='auth_success')])
    assert 'SD-003' not in rules(failures+[event(0,kind='auth_success')])
    assert 'SD-003' not in rules(failures+[event(10,kind='auth_success',timestamp='2026-01-15T12:11:00Z')])
    assert 'SD-003' not in rules(failures+[event(10,kind='auth_success',user='different')])


def test_synthetic_does_not_correlate_with_real():
    rows=[event(i,synthetic=i<4) for i in range(1,6)]
    assert rules(rows)==[]


def test_out_of_order_is_deterministic():
    rows=parse_payload(demo_payload(),'ndjson')
    assert detect(rows)==detect(list(reversed(rows)))


@pytest.mark.parametrize('command,expected', [('powershell.exe -enc ABC',True),('pwsh -EncodedCommand ABC',True),
    ('powershell.exe -File inventory.ps1',False),('echo -enc ABC',False),('pwsh -enc',False)])
def test_encoded_command_heuristic(command,expected):
    assert ('SD-004' in rules([event(kind='process_start',command=command)])) == expected


def test_missing_identity_does_not_correlate():
    assert rules([event(i,user='',src_ip='') for i in range(1,8)])==[]
