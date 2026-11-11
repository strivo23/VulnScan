import argparse, json, threading, uuid
from datetime import datetime, timezone
from pathlib import Path
from werkzeug.serving import make_server
from lab.vulnerable_app import app as vulnerable
from lab.secure_app import app as secure
from scanner.detection_engine import run_scan
from evaluation.metrics import calculate_metrics
from config import DB_PATH
from database.db import get_scan, init_db, save_scan

def run_app(flask_app,port=0):
    server=make_server("127.0.0.1",port,flask_app,threaded=True); thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return server

def persist_scan(target_url,started_at,findings,pages_checked,path=None):
    scan={"scan_id":str(uuid.uuid4()),"target_url":target_url,"started_at":started_at,
          "completed_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),
          "status":"COMPLETED" if pages_checked or findings else "FAILED",
          "pages_checked":pages_checked,"error":None if pages_checked or findings else "No pages could be retrieved from this fixture."}
    save_scan(scan,findings,path)
    return get_scan(scan["scan_id"],path)

def main():
    parser=argparse.ArgumentParser(description="Evaluate VulnScan against the loopback-only labeled applications.")
    parser.add_argument("--persist",action="store_true",help="Save real fixture scans to the dashboard SQLite database.")
    args=parser.parse_args()
    servers=[]
    try:
        servers.append(run_app(vulnerable))
        servers.append(run_app(secure))
        vuln_url=f"http://127.0.0.1:{servers[0].server_port}"
        secure_url=f"http://127.0.0.1:{servers[1].server_port}"
        vuln_started=datetime.now(timezone.utc).isoformat(timespec="seconds")
        vuln_findings,vuln_pages=run_scan(vuln_url,confirm=True)
        secure_started=datetime.now(timezone.utc).isoformat(timespec="seconds")
        secure_findings,secure_pages=run_scan(secure_url,confirm=True)
        observed={"vuln":vuln_findings,"secure":secure_findings}
    finally:
        for server in servers:server.shutdown()
    cases=json.loads((Path(__file__).parents[1]/"data/evaluation_cases.json").read_text(encoding="utf-8")); outcomes=[]
    for case in cases:
        label="secure" if case["case_id"].startswith("secure-") else "vuln"
        actual=case["rule_id"] in {f["rule_id"] for f in observed[label]}
        expected=case["expected_finding"]
        outcomes.append({**case,"actual_finding":actual,"outcome":"TP" if expected and actual else "FN" if expected else "FP" if actual else "TN"})
    saved=[]
    if args.persist:
        init_db(DB_PATH)
        saved=[persist_scan(vuln_url,vuln_started,vuln_findings,vuln_pages,DB_PATH),
               persist_scan(secure_url,secure_started,secure_findings,secure_pages,DB_PATH)]
    print(json.dumps({"cases":outcomes,"metrics":calculate_metrics(outcomes),"saved_scans":[{"scan_id":s["scan_id"],"target_url":s["target_url"],"status":s["status"],"pages_checked":s["pages_checked"],"total_findings":s["total_findings"]} for s in saved],"note":"Metrics apply only to the labelled local fixture cases; saved results are real observations from these local runs."},indent=2))

if __name__=="__main__":main()
