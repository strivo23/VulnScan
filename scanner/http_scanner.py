import requests
import math
from urllib.parse import urlsplit
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool
from requests.adapters import HTTPAdapter
from config import USER_AGENT, DEFAULT_TIMEOUT, MAX_BODY_BYTES
from .target_validator import validate_target, validate_target_details, validate_redirect, TargetError

class PinnedAdapter(HTTPAdapter):
    """Connect to the exact already-validated address while retaining Host/SNI verification."""
    def __init__(self):
        super().__init__(max_retries=0); self.pin_data=None; self.pool=None
    def pin(self, scheme, host, port, addresses):
        if self.pool:self.pool.close()
        ip=sorted(addresses,key=lambda item:(item.version,item.packed))[0]
        self.pin_data=(scheme,host.lower(),port,ip)
        kwargs={"host":str(ip),"port":port}
        if scheme=="https":self.pool=HTTPSConnectionPool(**kwargs,assert_hostname=host,server_hostname=host)
        else:self.pool=HTTPConnectionPool(**kwargs)
    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        p=urlsplit(request.url)
        if not self.pin_data or self.pin_data[:3]!=(p.scheme,p.hostname.lower(),p.port or (443 if p.scheme=="https" else 80)):
            raise TargetError("No validated address is pinned for this request.")
        host_header=p.hostname
        default=443 if p.scheme=="https" else 80
        if p.port and p.port!=default:host_header+=f":{p.port}"
        request.headers["Host"]=host_header
        return self.pool
    def close(self):
        if self.pool:self.pool.close()
        super().close()

def _bounded_number(value, default, minimum, maximum):
    try:number=float(value)
    except (TypeError,ValueError):number=default
    if not math.isfinite(number):number=default
    return max(minimum,min(number,maximum))

class SafeClient:
    def __init__(self, allowlist=(), timeout=DEFAULT_TIMEOUT, delay=0.15):
        self.allowlist=allowlist; self.timeout=_bounded_number(timeout,DEFAULT_TIMEOUT,1,20); self.delay=_bounded_number(delay,0.15,0,2)
        self.session=requests.Session(); self.session.trust_env=False
        self.session.headers.update({"User-Agent":USER_AGENT,"Accept":"text/html,application/xhtml+xml,*/*;q=0.2"})
        self.adapter=PinnedAdapter(); self.session.mount("http://",self.adapter); self.session.mount("https://",self.adapter)
    def request(self, method, url, confirm=True, max_redirects=5, stream=True):
        current,addresses=validate_target_details(url,self.allowlist,confirm)
        for _ in range(max_redirects+1):
            p=urlsplit(current); self.adapter.pin(p.scheme,p.hostname,p.port or (443 if p.scheme=="https" else 80),addresses)
            resp=self.session.request(method,current,timeout=self.timeout,allow_redirects=False,stream=stream,verify=True)
            if resp.is_redirect or resp.is_permanent_redirect:
                loc=resp.headers.get("Location")
                if _ == max_redirects: return resp
                resp.close()
                if not loc: return resp
                current=validate_redirect(current,loc,self.allowlist)
                current,addresses=validate_target_details(current,self.allowlist,confirm=True); continue
            if stream:
                chunks=[]; size=0
                for chunk in resp.iter_content(8192):
                    size+=len(chunk); chunks.append(chunk[:max(0,MAX_BODY_BYTES-size)])
                    if size>=MAX_BODY_BYTES: break
                resp._content=b"".join(chunks); resp._content_consumed=True
                if size>=MAX_BODY_BYTES:resp.close()
            return resp
        raise TargetError("Redirect limit exceeded.")
    def get(self,url,**kwargs): return self.request("GET",url,**kwargs)
    def head(self,url,**kwargs): return self.request("HEAD",url,stream=False,**kwargs)
    def close(self):self.session.close()
