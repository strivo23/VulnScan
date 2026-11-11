from scanner.severity import RULES
def test_documented_severity_rules():assert all(k.startswith(('HDR-','COOKIE-','DISC-','HTTP-','DIR-','TLS-')) for k in RULES)

def test_html_scan_accepts_form_string_page_limit(monkeypatch):
    from scanner import detection_engine as engine
    class Response:
        url='http://127.0.0.1:8081/';headers={'Content-Type':'text/html'};text='<a href="/next">next</a>';cookies=[];status_code=200;is_redirect=False
    class Client:
        allowlist=[];delay=0;calls=0
        def __init__(self,*a):pass
        def get(self,url):self.calls+=1;return Response()
        def request(self,*a,**k):return Response()
        def close(self):pass
    client=Client()
    monkeypatch.setattr(engine,'SafeClient',lambda *a:client)
    monkeypatch.setattr(engine,'analyze_headers',lambda *a:[])
    monkeypatch.setattr(engine,'analyze_cookies',lambda *a:[])
    monkeypatch.setattr(engine,'check_resources',lambda *a:[])
    monkeypatch.setattr(engine,'analyze_tls',lambda *a:{'supported':False})
    findings,pages=engine.run_scan('http://127.0.0.1:8081',max_pages='1',confirm=True)
    assert pages==1 and findings
