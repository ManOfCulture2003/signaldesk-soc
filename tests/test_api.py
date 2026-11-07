import pytest
from fastapi.testclient import TestClient

from signaldesk.api import create_app
from signaldesk.demo import demo_payload


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path/'api.sqlite'),base_url='http://localhost') as client:
        yield client


def token(client):
    return {'X-SignalDesk-Token':client.get('/api/session').json()['token']}


def test_full_investigation_round_trip(client):
    headers=token(client)
    assert client.get('/').status_code==200
    assert client.get('/api/health').json()['status']=='ok'
    assert client.post('/api/import',content=demo_payload(),headers=headers).json()['inserted']==16
    assert client.post('/api/detect',headers=headers).json()['created']==5
    alert=client.get('/api/alerts').json()[0]
    response=client.post('/api/alerts/'+alert['id']+'/triage',headers=headers,json={
        'version':1,'status':'investigating','note':'Validate source and review evidence','owner':'analyst'})
    assert response.status_code==200
    report=client.get('/api/alerts/'+alert['id']+'/export')
    assert report.json()['alert']['status']=='investigating'
    assert 'attachment' in report.headers['content-disposition']
    assert report.headers['cache-control']=='no-store'
    assert client.get('/api/events?limit=1&offset=1').json()['total']==16


def test_cross_origin_and_unauthorized_writes_rejected(client):
    assert client.post('/api/detect').status_code==403
    assert client.post('/api/detect',headers={**token(client),'Origin':'https://evil.invalid'}).status_code==403
    assert client.get('/api/stats',headers={'Host':'evil.invalid'}).status_code==400
    assert 'access-control-allow-origin' not in client.get('/api/session',headers={'Origin':'https://evil.invalid'}).headers


def test_api_errors_and_validation(client):
    headers=token(client)
    assert client.post('/api/import',content=b'bad',headers=headers).status_code==400
    assert client.get('/api/events?limit=501').status_code==422
    assert client.get('/api/alerts/missing').status_code==404
    assert client.get('/static/app.js').headers['x-content-type-options']=='nosniff'
    assert "script-src 'self'" in client.get('/').headers['content-security-policy']
