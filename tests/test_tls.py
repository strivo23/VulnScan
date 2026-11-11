from scanner.tls_analyzer import analyze_tls
def test_http_not_claimed_tls():assert analyze_tls('http://127.0.0.1')['supported'] is False
