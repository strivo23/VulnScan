SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
RULES = {
 "HDR-CSP": "Missing CSP is MEDIUM because it removes a defense-in-depth barrier against injection; observed policy weaknesses are LOW.",
 "HDR-HSTS": "Missing HSTS is MEDIUM on HTTPS because downgrade risk can expose sessions; it is informational on plain HTTP.",
 "HDR-NOSNIFF": "Missing nosniff is LOW due to browser content-type ambiguity.",
 "HDR-FRAME": "Missing clickjacking protection is LOW; explicit DENY/SAMEORIGIN or frame-ancestors is considered protected.",
 "HDR-REFERRER": "Missing Referrer-Policy is LOW due to possible URL disclosure to third parties.",
 "HDR-PERMISSIONS": "Missing Permissions-Policy is INFO since browser features remain governed by browser defaults.",
 "COOKIE-SECURE": "A cookie sent over HTTP without Secure is MEDIUM; Secure absence on HTTPS-only observation is LOW.",
 "COOKIE-HTTPONLY": "Missing HttpOnly is LOW for session exposure to script; cookie purpose is not inferred.",
 "COOKIE-SAMESITE": "Missing SameSite is LOW because cross-site request protections are reduced.",
 "COOKIE-SAMESITE-SECURE": "SameSite=None without Secure permits cross-site cookie delivery without enforcing HTTPS.",
 "DISC-SERVER": "Explicit server product/version disclosure is LOW absent evidence of an exploitable version.",
 "HTTP-HTTPS": "HTTP endpoint without observed HTTPS redirect is MEDIUM due to transport exposure.",
 "DIR-LIST": "Observable directory listing is MEDIUM because file names and contents may be exposed.",
 "TLS-INVALID": "A failed verified TLS handshake is HIGH because clients cannot establish authenticated transport.",
}
