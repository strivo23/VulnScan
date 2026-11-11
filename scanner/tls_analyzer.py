import socket, ssl
from urllib.parse import urlsplit
from datetime import datetime, timezone
def analyze_tls(url, timeout=5, addresses=None):
    p=urlsplit(url)
    if p.scheme!="https": return {"supported":False,"valid":None,"reason":"Target URL uses HTTP; TLS was not attempted."}
    host=p.hostname; port=p.port or 443; ctx=ssl.create_default_context()
    try:
        connect_host=str(sorted(addresses,key=lambda item:(item.version,item.packed))[0]) if addresses else host
        with socket.create_connection((connect_host,port),timeout=timeout) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as conn:
                cert=conn.getpeercert(); expires=datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                return {"supported":True,"valid":True,"expires":expires.isoformat(),"issuer":dict(x[0] for x in cert.get("issuer",[])),"version":conn.version()}
    except (OSError,ssl.SSLError,ValueError) as e: return {"supported":True,"valid":False,"reason":str(e)[:300]}
