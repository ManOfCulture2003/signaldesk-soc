import pytest

from signaldesk.demo import demo_payload
from signaldesk.store import Conflict, Store
from conftest import event, payload


def case(store):
    store.ingest(demo_payload());store.run_detection()
    return next(a for a in store.alerts() if a['rule_id']=='SD-001')


def test_replay_preserves_triage_and_history(store):
    alert=case(store)
    report=store.triage(alert['id'],version=1,status='closed',disposition='benign_positive',owner='analyst',note='Verified approved lab scenario.')
    assert report['alert']['version']==2
    store.ingest(demo_payload())
    assert store.run_detection()=={'created':0,'updated':0,'matched':5}
    reopened=Store(store.path).case(alert['id'])
    assert reopened['alert']['status']=='closed'
    assert len(reopened['history'])==2
    assert all(e['import_sha256'] for e in reopened['evidence'])


def test_optimistic_concurrency(store):
    alert=case(store)
    store.triage(alert['id'],version=1,status='investigating',note='Reviewing evidence')
    with pytest.raises(Conflict):
        store.triage(alert['id'],version=1,status='closed',disposition='false_positive',note='Stale browser view')
    assert len(store.case(alert['id'])['history'])==2


@pytest.mark.parametrize('change', [{'status':'closed'}, {'note':' '}, {'status':'bad'}, {'disposition':'true_positive'}, {'version':True}])
def test_invalid_decision_is_not_saved(store,change):
    alert=case(store)
    args={'version':1,'status':'investigating','note':'Investigating'};args.update(change)
    with pytest.raises(ValueError):
        store.triage(alert['id'],**args)
    assert store.case(alert['id'])['alert']['version']==1


def test_new_evidence_reopens_case(store):
    rows=[event(i) for i in range(1,6)]
    store.ingest(payload(rows));store.run_detection();alert=store.alerts()[0]
    store.triage(alert['id'],version=1,status='closed',disposition='false_positive',note='Initial review')
    store.ingest(payload([event(6)]))
    assert store.run_detection()['updated']==1
    report=store.case(alert['id'])
    assert report['alert']['status']=='new'
    assert len(report['evidence'])==6
    assert report['history'][-1]['action']=='evidence_updated'


def test_parameterized_search(store):
    store.ingest(payload([event(),event(2,user="' OR 1=1 --")]))
    assert store.events(user="' OR 1=1 --")['total']==1
    assert store.events(limit=1,offset=1)['items'][0]['event_id']=='2'
