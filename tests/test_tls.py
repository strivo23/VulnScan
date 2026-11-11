from scanner.tls_analyzer import analyze_tls
from unittest.mock import patch
import ssl
def test_http_not_claimed_tls():assert analyze_tls('http://127.0.0.1')['supported'] is False

def test_verified_tls_uses_default_context_and_hostname():
    cert={'notAfter':'Jan 01 00:00:00 2030 GMT','issuer':((('commonName','Test CA'),),)}
    class Conn:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def getpeercert(self):return cert
        def version(self):return 'TLSv1.3'
    class Context:
        def wrap_socket(self,raw,server_hostname):assert server_hostname=='example.test';return Conn()
    with patch('scanner.tls_analyzer.socket.create_connection'),patch('scanner.tls_analyzer.ssl.create_default_context',return_value=Context()) as context:
        result=analyze_tls('https://example.test/')
    context.assert_called_once_with();assert result['valid'] is True and result['issuer']['commonName']=='Test CA'

def test_invalid_tls_is_reported():
    with patch('scanner.tls_analyzer.socket.create_connection',side_effect=ssl.SSLCertVerificationError('untrusted')):
        result=analyze_tls('https://example.test/')
    assert result['valid'] is False and 'untrusted' in result['reason']
