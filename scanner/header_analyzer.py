from .severity import RULES
POLICIES={
 "Content-Security-Policy":("HDR-CSP","MEDIUM","Set a restrictive Content-Security-Policy. Avoid unsafe-inline/unsafe-eval; begin with report-only if needed."),
 "Strict-Transport-Security":("HDR-HSTS","MEDIUM","On HTTPS, set Strict-Transport-Security with an appropriate max-age; includeSubDomains only when all subdomains support HTTPS."),
 "X-Content-Type-Options":("HDR-NOSNIFF","LOW","Set X-Content-Type-Options: nosniff."),
 "X-Frame-Options":("HDR-FRAME","LOW","Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."),
 "Referrer-Policy":("HDR-REFERRER","LOW","Set Referrer-Policy: strict-origin-when-cross-origin or a stricter policy."),
 "Permissions-Policy":("HDR-PERMISSIONS","INFO","Set a Permissions-Policy that disables browser features the application does not need.")}
def analyze_headers(headers, url):
    out=[]; lower={k.lower():v for k,v in headers.items()}
    for name,(rule,sev,rem) in POLICIES.items():
        value=lower.get(name.lower())
        weak=False
        if name=="Content-Security-Policy" and value: weak="unsafe-eval" in value.lower() or "unsafe-inline" in value.lower() or ("default-src" not in value.lower() and "script-src" not in value.lower())
        if name=="Strict-Transport-Security" and value:
            import re
            match=re.search(r"max-age\s*=\s*(\d+)",value,re.I); weak=not match or int(match.group(1))==0
        if name=="X-Content-Type-Options" and value: weak=value.strip().lower()!="nosniff"
        if name=="X-Frame-Options" and value: weak=value.strip().lower() not in ("deny","sameorigin") and "frame-ancestors" not in lower.get("content-security-policy","").lower()
        if name=="Referrer-Policy" and value:
            safe={"no-referrer","same-origin","strict-origin","strict-origin-when-cross-origin"}
            recognized=[part.strip().lower() for part in value.split(",") if part.strip().lower() in safe|{"origin","origin-when-cross-origin","no-referrer-when-downgrade","unsafe-url"}]
            weak=not recognized or recognized[-1] not in safe
        if name=="Permissions-Policy" and value:
            weak=any(part.split("=",1)[-1].strip() in ("*","(*)") for part in value.split(",") if "=" in part)
        if not value or weak:
            severity=sev if not weak else ("LOW" if rule=="HDR-CSP" else sev)
            if rule=="HDR-HSTS" and not url.lower().startswith("https:"): severity="INFO"
            out.append(dict(rule_id=rule,title=("Missing " if not value else "Weak ")+name,category="HTTP Headers",severity=severity,description=RULES[rule],evidence=f"{name}: {value or 'not present'}",impact="Weak or absent browser policy reduces defense in depth; impact depends on application behavior.",remediation=rem))
    server=lower.get("server")
    if server and any(ch.isdigit() for ch in server): out.append(dict(rule_id="DISC-SERVER",title="Server version disclosed",category="Information Disclosure",severity="LOW",description=RULES["DISC-SERVER"],evidence=f"Server: {server[:200]}",impact="Fingerprinting can help attackers prioritize known weaknesses; no exploitability is inferred.",remediation="Remove or generalize version details in server response headers."))
    for h in ("x-powered-by","x-aspnet-version","x-generator"):
        if lower.get(h): out.append(dict(rule_id="DISC-HEADER-"+h.upper(),title=f"Information header disclosed: {h}",category="Information Disclosure",severity="INFO",description="The response exposes implementation metadata.",evidence=f"{h}: {lower[h][:200]}",impact="May simplify technology fingerprinting.",remediation=f"Remove the {h} response header if it is not operationally required."))
    return out
