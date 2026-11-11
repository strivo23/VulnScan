import csv, io, html
from collections import Counter
from datetime import datetime
from database.db import get_scan, get_findings

def csv_report(scan_id,path=None,**filters):
    rows=get_findings(scan_id,path,filters.get("severity"),filters.get("category"),filters.get("date_from"),filters.get("date_to")); out=io.StringIO(); fields=["finding_id","rule_id","title","category","severity","affected_url","description","evidence","impact","remediation","detected_at"]
    writer=csv.DictWriter(out,fieldnames=fields); writer.writeheader()
    for r in rows:writer.writerow({k:r[k] for k in fields})
    return out.getvalue()

def html_report(scan_id,path=None,**filters):
    s=get_scan(scan_id,path)
    if not s:raise ValueError("Unknown scan")
    rows=get_findings(scan_id,path,filters.get("severity"),filters.get("category"),filters.get("date_from"),filters.get("date_to")); counts=Counter(r["severity"] for r in rows)
    esc=lambda x:html.escape(str(x or ""))
    detail="".join(f"<article><h2>{esc(r['title'])} <small>{esc(r['severity'])}</small></h2><p><b>Category:</b> {esc(r['category'])} · <b>Rule:</b> {esc(r['rule_id'])}</p><p><b>Affected URL:</b> {esc(r['affected_url'])}</p><p>{esc(r['description'])}</p><p><b>Evidence:</b> {esc(r['evidence'])}</p><p><b>Impact:</b> {esc(r['impact'])}</p><p><b>Remediation:</b> {esc(r['remediation'])}</p></article>" for r in rows)
    sev="".join(f"<li>{k}: {counts.get(k,0)}</li>" for k in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"))
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>VulnScan Assessment Report</title><style>body{{font:15px Arial;max-width:980px;margin:40px auto;color:#162032}}header{{background:#101a2d;color:white;padding:28px}}article{{border:1px solid #ccd4e0;border-radius:8px;padding:18px;margin:16px 0}}small{{color:#9b2c2c}}</style></head><body><header><h1>VulnScan Security Assessment</h1><p>Scan {esc(s['scan_id'])} · {esc(s['target_url'])}</p><p>{esc(s['started_at'])} — {esc(s['completed_at']) or 'in progress'} · {s['pages_checked']} pages checked</p></header><h2>Executive summary</h2><p>Assessment recorded {len(rows)} finding(s). Results reflect only the configured safe checks and observed responses.</p><ul>{sev}</ul><h2>Detailed findings</h2>{detail}<h2>Scope and limitations</h2><p>Authorized target only. Safe GET/HEAD checks; no exploitation, authentication testing, broad port scanning, or complete TLS cipher audit. Results are not proof of absence of vulnerabilities.</p></body></html>"""
