from scanner.header_analyzer import analyze_headers
def test_missing_and_valid_headers():
    fs=analyze_headers({},"https://127.0.0.1/"); assert {f['rule_id'] for f in fs}>={"HDR-CSP","HDR-HSTS","HDR-NOSNIFF","HDR-FRAME","HDR-REFERRER","HDR-PERMISSIONS"}
    assert next(f for f in fs if f['rule_id']=='HDR-CSP')['severity']=="MEDIUM"
    assert not analyze_headers({"content-security-policy":"default-src 'self'","strict-transport-security":"max-age=3600","x-content-type-options":"nosniff","x-frame-options":"DENY","referrer-policy":"no-referrer","permissions-policy":"camera=()"},"https://x/")
def test_server_disclosure():assert any(f['rule_id']=='DISC-SERVER' for f in analyze_headers({'Server':'Werkzeug/3.0'},'http://x/'))
def test_weak_referrer_and_permissions_policies():
    findings=analyze_headers({'Referrer-Policy':'unsafe-url','Permissions-Policy':'camera=*, microphone=()'},'https://x/')
    assert {'HDR-REFERRER','HDR-PERMISSIONS'}<={f['rule_id'] for f in findings}
