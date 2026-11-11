import ipaddress, socket
from urllib.parse import urlsplit, urlunsplit

class TargetError(ValueError): pass

def normalize_url(url):
    if not isinstance(url,str) or len(url)>2048: raise TargetError("Enter a valid URL (maximum 2048 characters).")
    p=urlsplit(url.strip())
    if p.scheme.lower() not in ("http","https") or not p.hostname: raise TargetError("Only absolute HTTP or HTTPS URLs are supported.")
    if p.username or p.password: raise TargetError("Credentials in target URLs are not allowed.")
    if p.port and not 1<=p.port<=65535: raise TargetError("Invalid port.")
    host=p.hostname.rstrip(".").lower()
    if not host or any(c.isspace() for c in host): raise TargetError("Invalid hostname.")
    path=p.path or "/"
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))

def resolve_ips(host):
    try: return {ipaddress.ip_address(host)}
    except ValueError: pass
    try:
        rows=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
        return {ipaddress.ip_address(r[4][0].split("%",1)[0]) for r in rows}
    except socket.gaierror as e: raise TargetError(f"Hostname could not be resolved: {e}")

def is_private_or_loopback(host):
    ips=resolve_ips(host)
    if not ips: raise TargetError("Hostname has no address records.")
    return all(ip.is_private or ip.is_loopback or ip.is_link_local for ip in ips)

def validate_target(url, allowlist=(), confirm=False):
    return validate_target_details(url,allowlist,confirm)[0]

def validate_target_details(url, allowlist=(), confirm=False):
    if not confirm: raise TargetError("Confirm that you are authorized to assess this target.")
    norm=normalize_url(url); host=urlsplit(norm).hostname
    allowed={str(x).lower().rstrip(".") for x in allowlist}
    ips=resolve_ips(host)
    if not ips: raise TargetError("Hostname has no address records.")
    if host=="localhost" and any(not ip.is_loopback for ip in ips): raise TargetError("localhost resolved outside the loopback range.")
    if host not in ("localhost",) and host not in allowed:
        if not all(ip.is_private or ip.is_loopback or ip.is_link_local for ip in ips): raise TargetError("Public targets must be explicitly added to the authorization allowlist.")
    # Reject mixed public/private DNS answers even for an allowlisted name; they make split-view DNS bypasses harder.
    if host in allowed and any(ip.is_private or ip.is_loopback or ip.is_link_local for ip in ips) and any(ip.is_global for ip in ips):
        raise TargetError("Hostname resolves to a mixed public/private address set.")
    # The caller receives this exact validated DNS set and pins the HTTP connection to one address.
    if any(ip.is_unspecified or ip.is_multicast or ip.is_reserved for ip in ips): raise TargetError("Target resolves to a prohibited IP address.")
    return norm,ips

def validate_redirect(source_url, location, allowlist=()):
    from urllib.parse import urljoin
    dest=validate_target(urljoin(source_url,location),allowlist,confirm=True)
    source_host=urlsplit(source_url).hostname.lower().rstrip("."); dest_host=urlsplit(dest).hostname.lower().rstrip(".")
    explicit={str(x).lower().rstrip(".") for x in allowlist}
    if dest_host!=source_host and dest_host not in explicit:
        if not (is_private_or_loopback(source_host) and is_private_or_loopback(dest_host)):
            raise TargetError("Redirect leaves the authorized target scope.")
    return dest
