import json, threading
from pathlib import Path
from werkzeug.serving import make_server
from lab.vulnerable_app import app as vulnerable
from lab.secure_app import app as secure
from scanner.detection_engine import run_scan
from evaluation.metrics import calculate_metrics

def run_app(flask_app,port):
    server=make_server("127.0.0.1",port,flask_app,threaded=True); thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return server

def main():
    servers=[run_app(vulnerable,8081),run_app(secure,8082)]
    try:
        observed={"vuln":run_scan("http://127.0.0.1:8081",confirm=True)[0],"secure":run_scan("http://127.0.0.1:8082",confirm=True)[0]}
    finally:
        for server in servers:server.shutdown()
    cases=json.loads((Path(__file__).parents[1]/"data/evaluation_cases.json").read_text(encoding="utf-8")); outcomes=[]
    for case in cases:
        label="secure" if case["case_id"].startswith("secure-") else "vuln"
        actual=case["rule_id"] in {f["rule_id"] for f in observed[label]}
        expected=case["expected_finding"]
        outcomes.append({**case,"actual_finding":actual,"outcome":"TP" if expected and actual else "FN" if expected else "FP" if actual else "TN"})
    print(json.dumps({"cases":outcomes,"metrics":calculate_metrics(outcomes),"note":"Metrics apply only to the labelled local fixture cases."},indent=2))

if __name__=="__main__":main()
