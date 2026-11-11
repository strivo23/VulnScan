import requests
from urllib.parse import urlsplit
from config import USER_AGENT, DEFAULT_TIMEOUT, MAX_BODY_BYTES
from .target_validator import validate_target, validate_redirect, TargetError

class SafeClient:
    def __init__(self, allowlist=(), timeout=DEFAULT_TIMEOUT, delay=0.15):
        self.allowlist=allowlist; self.timeout=max(1,min(float(timeout),20)); self.delay=max(0,min(float(delay),2))
        self.session=requests.Session(); self.session.trust_env=False
        self.session.headers.update({"User-Agent":USER_AGENT,"Accept":"text/html,application/xhtml+xml,*/*;q=0.2"})
    def request(self, method, url, confirm=True, max_redirects=5, stream=True):
        current=validate_target(url,self.allowlist,confirm)
        for _ in range(max_redirects+1):
            # Fresh resolution immediately before each network request protects redirect and DNS scope checks.
            current=validate_target(current,self.allowlist,confirm=True)
            resp=self.session.request(method,current,timeout=self.timeout,allow_redirects=False,stream=stream,verify=True)
            if resp.is_redirect or resp.is_permanent_redirect:
                loc=resp.headers.get("Location")
                if _ == max_redirects: return resp
                resp.close()
                if not loc: return resp
                current=validate_redirect(current,loc,self.allowlist); continue
            if stream:
                chunks=[]; size=0
                for chunk in resp.iter_content(8192):
                    size+=len(chunk); chunks.append(chunk[:max(0,MAX_BODY_BYTES-size)])
                    if size>=MAX_BODY_BYTES: break
                resp._content=b"".join(chunks); resp._content_consumed=True
            return resp
        raise TargetError("Redirect limit exceeded.")
    def get(self,url,**kwargs): return self.request("GET",url,**kwargs)
    def head(self,url,**kwargs): return self.request("HEAD",url,stream=False,**kwargs)
