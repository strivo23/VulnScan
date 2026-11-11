import re

def csrf_token(client,path):
    response=client.get(path)
    match=re.search(rb'name="_csrf_token" value="([^"]+)"',response.data)
    assert match
    return match.group(1).decode()

def test_pages_and_authorization(client):
 assert client.get('/health').json=={"status":"ok","name":"VulnScan"}
 for path in ('/','/scans','/findings','/reports','/settings','/scans/new'):assert client.get(path).status_code==200
 token=csrf_token(client,'/scans/new')
 assert client.post('/scans/new',data={'target':'http://127.0.0.1:8081'}).status_code==400
 r=client.post('/scans/new',data={'target':'http://127.0.0.1:8081','_csrf_token':token});assert r.status_code==200 and b'Confirm' in r.data
 assert client.get('/scans/missing').status_code==404

def test_scan_to_report_workflow(client,monkeypatch):
    finding={"finding_id":"wf-finding","rule_id":"HDR-CSP","title":"Missing CSP","category":"HTTP Headers","severity":"MEDIUM","affected_url":"http://127.0.0.1:8081/","description":"Policy absent","evidence":"not present","impact":"Reduced defense in depth","remediation":"Set a policy","detected_at":"2026-01-01T00:00:00+00:00"}
    monkeypatch.setattr("app.run_scan",lambda *a,**k:([finding],1))
    token=csrf_token(client,'/scans/new')
    response=client.post('/scans/new',data={"target":"http://127.0.0.1:8081","authorized":"yes","_csrf_token":token},follow_redirects=True)
    assert response.status_code==200 and b"Missing CSP" in response.data
    scan_id=client.application.view_functions['scan_details'].__globals__['db'].list_scans(client.application.config['DATABASE'])[0]['scan_id']
    assert client.get(f'/reports/{scan_id}/csv').status_code==200
    assert b"Missing CSP" in client.get(f'/reports/{scan_id}/html').data

def test_allowlist_target_can_be_removed(client,app):
    from database import db
    db.add_authorized_target("example.test",app.config['DATABASE'])
    token=csrf_token(client,'/settings')
    response=client.post('/settings',data={"action":"remove","host":"example.test","_csrf_token":token},follow_redirects=True)
    assert response.status_code==200 and "example.test" not in db.authorized_targets(app.config['DATABASE'])

def test_unreachable_scan_is_saved_as_failed(client,app,monkeypatch):
    from database import db
    monkeypatch.setattr("app.run_scan",lambda *a,**k:([],0))
    token=csrf_token(client,'/scans/new')
    response=client.post('/scans/new',data={"target":"http://127.0.0.1:8081","authorized":"yes","_csrf_token":token},follow_redirects=True)
    assert response.status_code==200 and b"No pages could be retrieved" in response.data
    scan=db.list_scans(app.config['DATABASE'])[0]
    assert scan['status']=='FAILED' and scan['error']
