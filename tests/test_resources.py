from scanner.resource_checker import PATHS
def test_resource_scope_is_limited():assert len(PATHS)==4 and all(x.count('/')<=1 for x in PATHS)

def test_resource_checker_uses_only_bounded_safe_gets():
    from scanner.resource_checker import check_resources
    class Response:
        status_code=200;headers={'Content-Type':'text/plain'};content=b''
    class Client:
        allowlist=[]
        def __init__(self):self.calls=[]
        def get(self,url):self.calls.append(url);return Response()
    client=Client();findings=check_resources(client,'http://127.0.0.1:8080/')
    assert len(client.calls)==4 and all('/' in url for url in client.calls)
    assert all(f['severity']=='INFO' for f in findings)
