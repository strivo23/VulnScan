import time, uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup
from .target_validator import validate_target
from .http_scanner import SafeClient
from .header_analyzer import analyze_headers
from .cookie_analyzer import analyze_cookies
from .resource_checker import check_resources
from .tls_analyzer import analyze_tls
from .severity import RULES

def run_scan(target, allowlist=(), timeout=5, max_pages=10, delay=.15, confirm=False):
    target=validate_target(target,allowlist,confirm)
    client=SafeClient(allowlist,timeout,delay); findings=[]; seen=set(); visited=set(); queue=[target]
    def add(f,url):
        key=(f["rule_id"],url)
        if key in seen:return
        seen.add(key); findings.append({"finding_id":str(uuid.uuid4()),"rule_id":f["rule_id"],"title":f["title"],"category":f["category"],"severity":f["severity"],"affected_url":url,"description":f["description"],"evidence":f["evidence"],"impact":f["impact"],"remediation":f["remediation"],"detected_at":datetime.now(timezone.utc).isoformat(timespec="seconds")})
    pages=0; root=urlsplit(target)
    while queue and pages<max(1,min(int(max_pages),50)):
        url=queue.pop(0)
        if url in visited:continue
        visited.add(url)
        try:
            r=client.get(url); pages+=1
        except Exception as e:
            if url==target and root.scheme=="https":
                add(dict(rule_id="TLS-INVALID",title="Verified TLS connection failed",category="TLS",severity="HIGH",description=RULES["TLS-INVALID"],evidence=str(e)[:300],impact="Clients cannot verify a secure connection to this endpoint.",remediation="Install a valid certificate for this hostname and ensure the full chain is served."),url)
            continue
        for f in analyze_headers(r.headers,r.url):add(f,r.url)
        for f in analyze_cookies(r,r.url):add(f,r.url)
        if "text/html" in r.headers.get("Content-Type","").lower():
            text=r.text
            if any(x in text.lower() for x in ("index of /","directory listing for /")):
                add(dict(rule_id="DIR-LIST",title="Directory listing appears enabled",category="Information Disclosure",severity="MEDIUM",description=RULES["DIR-LIST"],evidence="Response HTML contains a common directory-index heading.",impact="Directory contents may be discoverable.",remediation="Disable automatic directory indexes and serve an explicit index page."),r.url)
            if pages<max_pages:
                for a in BeautifulSoup(text,"html.parser").find_all("a",href=True):
                    nxt=urljoin(r.url,a["href"]); p=urlsplit(nxt)
                    if p.scheme in ("http","https") and p.hostname==root.hostname and p.port==root.port and p.path not in ("",):
                        nxt=p._replace(query="",fragment="").geturl()
                        if nxt not in visited and nxt not in queue:queue.append(nxt)
        time.sleep(client.delay)
    try:
        for f in check_resources(client,target):add(f,target)
    except Exception:pass
    try:
        validate_target(target,allowlist,confirm=True)
        tls=analyze_tls(target,timeout)
        if tls.get("valid") is False:
            add(dict(rule_id="TLS-INVALID",title="TLS certificate validation failed",category="TLS",severity="HIGH",description=RULES["TLS-INVALID"],evidence=tls.get("reason","TLS verification failed"),impact="Clients cannot establish authenticated transport.",remediation="Use a valid trusted certificate matching the target hostname."),target)
        elif tls.get("valid") is True:
            issuer=", ".join(f"{k}={v}" for k,v in (tls.get("issuer") or {}).items()) or "unavailable"
            add(dict(rule_id="TLS-CERT-INFO",title="Verified TLS certificate details",category="TLS",severity="INFO",description="A TLS handshake completed with normal certificate chain and hostname verification enabled.",evidence=f"Protocol: {tls.get('version') or 'unknown'}; expires: {tls.get('expires') or 'unknown'}; issuer: {issuer}",impact="This is an informational certificate observation, not a cipher-suite audit.",remediation="Monitor certificate renewal and keep the certificate chain current."),target)
    except Exception:pass
    if root.scheme=="http":
        try:
            response=client.request("HEAD",target,max_redirects=0,stream=False)
            loc=response.headers.get("Location","")
            if not (response.is_redirect and loc.lower().startswith("https://")):
                add(dict(rule_id="HTTP-HTTPS",title="HTTP endpoint does not redirect to HTTPS",category="Transport Security",severity="MEDIUM",description="The tested HTTP endpoint did not return a direct redirect to HTTPS.",evidence=f"HTTP {response.status_code}; Location: {loc or 'not present'}",impact="Traffic sent over HTTP can be observed or modified in transit.",remediation="Redirect HTTP to HTTPS and serve the application with a valid TLS certificate."),target)
        except Exception:pass
    return findings,pages
