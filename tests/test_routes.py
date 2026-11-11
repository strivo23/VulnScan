def test_pages_and_authorization(client):
 assert client.get('/health').json=={"status":"ok","name":"VulnScan"}
 for path in ('/','/scans','/findings','/reports','/settings','/scans/new'):assert client.get(path).status_code==200
 r=client.post('/scans/new',data={'target':'http://127.0.0.1:8081'});assert r.status_code==200 and b'Confirm' in r.data
 assert client.get('/scans/missing').status_code==404

def test_scan_to_report_workflow(client,monkeypatch):
    finding={"finding_id":"wf-finding","rule_id":"HDR-CSP","title":"Missing CSP","category":"HTTP Headers","severity":"MEDIUM","affected_url":"http://127.0.0.1:8081/","description":"Policy absent","evidence":"not present","impact":"Reduced defense in depth","remediation":"Set a policy","detected_at":"2026-01-01T00:00:00+00:00"}
    monkeypatch.setattr("app.run_scan",lambda *a,**k:([finding],1))
    response=client.post('/scans/new',data={"target":"http://127.0.0.1:8081","authorized":"yes"},follow_redirects=True)
    assert response.status_code==200 and b"Missing CSP" in response.data
    scan_id=client.application.view_functions['scan_details'].__globals__['db'].list_scans(client.application.config['DATABASE'])[0]['scan_id']
    assert client.get(f'/reports/{scan_id}/csv').status_code==200
    assert b"Missing CSP" in client.get(f'/reports/{scan_id}/html').data
