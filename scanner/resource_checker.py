import time, re
from urllib.parse import urlsplit, urlunsplit
from .target_validator import validate_target
PATHS=("robots.txt","sitemap.xml",".well-known/security.txt","crossdomain.xml")
def check_resources(client,base):
    found=[]
    origin=urlsplit(base)
    for path in PATHS:
        url=urlunsplit((origin.scheme,origin.netloc,"/"+path,"",""))
        try:
            validate_target(url,client.allowlist,confirm=True); r=client.get(url)
            if r.status_code==200:
                typ=r.headers.get("Content-Type","")[:100]
                if path=="crossdomain.xml" and re.search(rb"<allow-access-from\b[^>]*\bdomain\s*=\s*['\"]\*['\"]",r.content,re.I):
                    found.append(dict(rule_id="RESOURCE-CROSSDOMAIN",title="Overly broad cross-domain policy",category="Exposed Resources",severity="MEDIUM",description="Cross-domain policy grants broad access.",evidence="crossdomain.xml permits wildcard domains.",impact="Untrusted origins may access data in legacy clients.",remediation="Restrict allowed domains or remove the file."))
                elif path in ("robots.txt","sitemap.xml",".well-known/security.txt"):
                    found.append(dict(rule_id="RESOURCE-"+path.replace("/","-").upper(),title=f"Public resource available: /{path}",category="Exposed Resources",severity="INFO",description="A conventional public resource is available; this is not automatically a vulnerability.",evidence=f"HTTP 200; Content-Type: {typ}",impact="Resource may reveal intended public paths or contact information.",remediation="Review contents for accidentally published sensitive paths or details."))
        except Exception: continue
        finally:
            if path!=PATHS[-1]:time.sleep(getattr(client,"delay",0))
    return found
