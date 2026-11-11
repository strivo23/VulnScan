from .severity import RULES
def analyze_cookies(response, url):
    findings=[]
    for c in response.cookies:
        # Never include cookie values in any finding.
        attrs=getattr(c,"_rest",{}) or {}; rest={k.lower():v for k,v in attrs.items()}; rules=[]
        if not c.secure: rules.append(("COOKIE-SECURE","MEDIUM" if url.lower().startswith("http:") else "LOW","Secure"))
        if not c.has_nonstandard_attr("HttpOnly"): rules.append(("COOKIE-HTTPONLY","LOW","HttpOnly"))
        same=rest.get("samesite")
        if not same: rules.append(("COOKIE-SAMESITE","LOW","SameSite"))
        for rule,sev,attr in rules:
            findings.append(dict(rule_id=rule+"-"+c.name,title=f"Cookie {attr} attribute missing",category="Cookie Security",severity=sev,description=RULES[rule],evidence=f"Cookie name: {c.name}; {attr} attribute is absent.",impact="Cookie protection is reduced. Cookie values are intentionally excluded.",remediation=f"Set the {attr} attribute on security-sensitive cookies."))
        if c.expires is None and not c.discard:
            findings.append(dict(rule_id="COOKIE-EXPIRY-"+c.name,title="Cookie has no explicit expiry",category="Cookie Security",severity="INFO",description="Persistent cookie lifetime could not be determined from response metadata.",evidence=f"Cookie name: {c.name}; no Expires or Max-Age observed.",impact="Client may treat it as a session cookie.",remediation="Use an intentional bounded lifetime for persistent cookies."))
    return findings
