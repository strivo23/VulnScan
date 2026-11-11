import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from config import DB_PATH

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def connect(path=None):
    db = sqlite3.connect(str(path or DB_PATH), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def init_db(path=None):
    target = Path(path or DB_PATH); target.parent.mkdir(parents=True, exist_ok=True)
    with connect(target) as db:
        db.executescript((Path(__file__).with_name("schema.sql")).read_text(encoding="utf-8"))

def add_authorized_target(target, path=None):
    with connect(path) as db:
        db.execute("INSERT INTO authorized_targets(target,authorization_confirmed,created_at,active) VALUES(?,?,?,1) ON CONFLICT(target) DO UPDATE SET authorization_confirmed=1,active=1", (target,1,now()))

def authorized_targets(path=None):
    with connect(path) as db: return [r["target"] for r in db.execute("SELECT target FROM authorized_targets WHERE active=1 AND authorization_confirmed=1")]

def save_scan(scan, findings, path=None):
    with connect(path) as db:
        db.execute("INSERT INTO scans(scan_id,target_url,started_at,completed_at,status,pages_checked,total_findings,error) VALUES(?,?,?,?,?,?,?,?)", (scan["scan_id"],scan["target_url"],scan["started_at"],scan.get("completed_at"),scan["status"],scan.get("pages_checked",0),0,scan.get("error")))
        for f in findings:
            db.execute("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (f["finding_id"],scan["scan_id"],f["rule_id"],f["title"],f["category"],f["severity"],f["affected_url"],f["description"],f["evidence"],f["impact"],f["remediation"],f["detected_at"]))
        db.execute("UPDATE scans SET total_findings=(SELECT COUNT(*) FROM findings WHERE scan_id=?) WHERE scan_id=?",(scan["scan_id"],scan["scan_id"]))

def get_scan(scan_id,path=None):
    with connect(path) as db: return db.execute("SELECT * FROM scans WHERE scan_id=?",(scan_id,)).fetchone()

def list_scans(path=None):
    with connect(path) as db: return db.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()

def get_findings(scan_id=None,path=None,severity=None,category=None,date_from=None,date_to=None):
    sql="SELECT f.*,s.target_url FROM findings f JOIN scans s USING(scan_id) WHERE 1=1"; args=[]
    if scan_id: sql+=" AND f.scan_id=?"; args.append(scan_id)
    if severity: sql+=" AND f.severity=?"; args.append(severity)
    if category: sql+=" AND f.category=?"; args.append(category)
    if date_from: sql+=" AND substr(f.detected_at,1,10)>=?"; args.append(date_from)
    if date_to: sql+=" AND substr(f.detected_at,1,10)<=?"; args.append(date_to)
    sql+=" ORDER BY f.detected_at DESC"
    with connect(path) as db: return db.execute(sql,args).fetchall()

def get_finding(fid,path=None):
    with connect(path) as db: return db.execute("SELECT f.*,s.target_url FROM findings f JOIN scans s USING(scan_id) WHERE finding_id=?",(fid,)).fetchone()
