import ipaddress
from requests import Request
from scanner.http_scanner import PinnedAdapter

def test_adapter_pins_ip_and_preserves_https_hostname():
    adapter=PinnedAdapter();adapter.pin('https','app.example',443,{ipaddress.ip_address('93.184.216.34')})
    request=Request('GET','https://app.example/path').prepare()
    pool=adapter.get_connection_with_tls_context(request,True)
    assert pool.host=='93.184.216.34'
    assert pool.assert_hostname=='app.example' and pool.conn_kw['server_hostname']=='app.example'
    assert request.headers['Host']=='app.example'
    adapter.close()
