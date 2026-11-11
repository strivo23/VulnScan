from scanner.severity import RULES
def test_documented_severity_rules():assert all(k.startswith(('HDR-','COOKIE-','DISC-','HTTP-','DIR-','TLS-')) for k in RULES)
