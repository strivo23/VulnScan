# VulnScan

VulnScan is a lightweight, defensive web application configuration assessment tool built with Python and Flask. It performs a small set of safe HTTP checks against localhost, private lab environments, and domains that an operator has explicitly placed on the authorization allowlist. It records observations in SQLite and produces CSV and HTML reports.

## Problem and objectives

Web application teams often need a repeatable way to spot basic browser security policy gaps, cookie flags, transport configuration problems, and accidental information disclosure. VulnScan provides a local dashboard for those checks, keeps evidence tied to a scan, and suggests practical remediation. It is designed for authorized assessment and education; it is not a penetration testing suite.

## Features

- Flask dashboard, scan history, finding detail, reports, and scope settings.
- Scope validation for HTTP(S) URLs, localhost and private addresses, with explicit hostname allowlisting for public domains.
- DNS resolution checks and manually validated redirects; proxy environment variables are disabled.
- Safe GET/HEAD requests, configurable timeout, request delay, and page cap, with a clear VulnScan User-Agent.
- Security header analysis for CSP, HSTS, nosniff, frame options, Referrer-Policy, and Permissions-Policy.
- Verified TLS handshake with certificate hostname/chain validation, expiration and issuer reporting. No cipher-suite audit is claimed.
- Cookie Secure, HttpOnly, SameSite, and expiry checks. Cookie values are not copied into findings or reports.
- A small set of conventional public resource checks and evidence-based server disclosure/directory listing checks.
- SQLite persistence with foreign keys and duplicate rule/URL suppression per scan.
- CSV and standalone HTML reports.
- Vulnerable and secure local Flask fixtures, plus an evaluation runner that computes metrics from real scans.

## Technology and architecture

Python 3.10+, Flask, Requests, BeautifulSoup, SQLite, HTML/CSS/JavaScript, Chart.js (loaded from jsDelivr for the dashboard chart), and pytest. `scanner/` contains scope validation, a bounded HTTP client, and independent analyzers. `database/` owns the SQLite schema and parameterized persistence. `routes` documents route groupings; the small application registers its routes in `app.py` to share one configured database. `reports/` creates exports, `evaluation/` computes metrics, and `lab/` contains loopback-only fixtures.

## Checks and severity

| Area | Rules |
|---|---|
| HTTP headers | Missing or clearly weak CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| TLS | Verified handshake, certificate hostname/chain validation, expiry and issuer where available |
| Cookies | Secure, HttpOnly, SameSite, expiry/Max-Age observation, by cookie name only |
| Exposure | `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/crossdomain.xml` |
| Other configuration | HTTP to HTTPS redirect, versioned Server and selected metadata headers, common directory-index indicator |

Severity is assigned per rule in `scanner/severity.py`. Missing CSP is MEDIUM, for example, while a missing Permissions-Policy is INFO. Findings include a unique ID, rule ID, severity, category, affected URL, detection time, evidence, impact, and remediation. Informational resources such as robots.txt are not called vulnerabilities by default.

## Database

SQLite tables are created automatically at startup: `scans`, `findings`, and `authorized_targets`. Foreign keys link findings to scans. A unique constraint prevents repeat findings with the same rule and URL in one scan. The database file is stored under `data/` and is ignored by Git. No passwords, auth tokens, or cookie values are saved.

## Installation and Windows execution

From PowerShell in the project folder:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Initialize the database:

```powershell
python -c "from database.db import init_db; init_db(); print('Database initialized')"
```

Run the dashboard (it binds to loopback only):

```powershell
python app.py
```

Then open `http://127.0.0.1:5000`. For a local comparison, open two more PowerShell windows in the project folder and run:

```powershell
python -m lab.vulnerable_app
```

```powershell
python -m lab.secure_app
```

The fixtures listen only on `127.0.0.1` at ports 8081 and 8082. Scan `http://127.0.0.1:8081` and `http://127.0.0.1:8082` from the dashboard. The second fixture demonstrates secure response policy and cookie attributes over an HTTP-only local test transport; it intentionally does not claim to demonstrate TLS or an HTTP-to-HTTPS redirect.

Run tests:

```powershell
pytest -q
```

Evaluate known fixture conditions using real local HTTP scans. The evaluation runner starts and stops both fixture servers on loopback automatically:

```powershell
python -m evaluation.run_labs
```

To save those actual scanner runs in SQLite so the dashboard counters and charts show the local results, run:

```powershell
python -m evaluation.run_labs --persist
```

The saved rows appear in Scan History and Reports with the ephemeral loopback ports used during that run. They are actual observations from the vulnerable and secure fixtures, not seeded or hard-coded findings.

## Authorized scanning policy

Only use VulnScan on systems you own or have explicit permission to assess. Loopback and private IP literals are allowed for local labs. Add public hostnames and custom private lab hostnames in **Settings → Authorization allowlist** before scanning them. Public IP literals must also be allowlisted. The New Scan form independently requires an authorization confirmation and a CSRF token. The tool rejects link-local and special-purpose addresses, validates the resolved address set, rejects mixed public/private DNS answers for allowlisted names, pins each HTTP connection to a validated address, preserves the HTTP Host header and TLS hostname verification, validates and pins every redirect destination, disables inherited HTTP proxy settings, follows redirects manually, limits redirect depth and response body size, and confines crawling to the starting host. Do not enter credentials in target URLs. No authentication/session handling is implemented.

The checks use only safe GET and HEAD requests. They do not attempt exploitation, SQL injection payloads, brute force, credential attacks, directory enumeration, or denial-of-service behavior. Request limits and delays are configurable. Scan only in an approved window and environment.

## Reports and filters

Reports are available per Scan ID from Reports and Scan Details pages. CSV contains one row per finding. HTML reports include target, start/end time, duration, severity counts, evidence, impact, remediation, and scope limitations. The Reports and Findings views support Scan ID, severity, category, and date range filters. CSV formula-like values are escaped before export.

## Evaluation methodology

`data/evaluation_cases.json` labels specific expected rules for the vulnerable and secure fixtures. `evaluation.run_labs` starts both apps on loopback, runs the scanner, maps each labelled test condition to observed rule IDs, then calculates TP, FP, TN, FN, precision, recall, F1, detection rate, and false positive rate with zero-division handling. The command prints actual metrics and does not claim a predetermined score. These metrics cover only these implemented test cases; they do not prove detection of all real-world vulnerabilities.

## Limitations

- No authenticated scan, JavaScript rendering, API schema discovery, form crawling, or stateful workflows.
- Only the listed safe configuration and disclosure checks are implemented; this is not complete vulnerability coverage.
- TLS assessment verifies a normal Python SSL connection and certificate. It does not audit cipher suites, protocol downgrade behavior, or the full TLS configuration matrix.
- Header and cookie checks cannot infer every application's intended policy or cookie role; severity is conservative.
- Exposed resource checks inspect a few conventional paths and only recognize a narrow crossdomain wildcard pattern.
- HTTP behavior is observed from one local scanner vantage point; CDN, proxy, and deployment topology may differ.
- Public targets must be authorized explicitly. Network egress and DNS must be available for public domains; the scanner does not bypass local network policy.
- Dashboard Chart.js is served by a public CDN; core scan functionality and reports do not depend on the chart loading.

## Future enhancements

Add an asynchronous job queue for larger scans, optional JSON output, richer date filtering, configurable per-rule policy profiles, certificate expiry notifications, and additional strictly non-invasive checks with independent tests and transparent scope.
