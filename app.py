import hmac, secrets, uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, abort, session
from config import SECRET_KEY, DB_PATH
from database import db
from scanner.detection_engine import run_scan
from scanner.target_validator import validate_target, TargetError
from reports.report_generator import csv_report, html_report

def save_failed_scan(scan, findings, error, database_path):
    scan.update(completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),status="FAILED",error=str(error)[:500])
    scan.setdefault("pages_checked",0)
    try:db.save_scan(scan,findings,database_path)
    except Exception:pass

def create_app(test_config=None):
    app=Flask(__name__); app.config.update(SECRET_KEY=SECRET_KEY, DATABASE=str(DB_PATH))
    if test_config:app.config.update(test_config)
    db.init_db(app.config["DATABASE"])
    @app.before_request
    def protect_state_changes():
        if request.method=="POST":
            expected=session.get("_csrf_token","")
            supplied=request.form.get("_csrf_token","")
            if not expected or not supplied or not hmac.compare_digest(expected,supplied):abort(400)
    @app.context_processor
    def inject_csrf_token():
        if "_csrf_token" not in session:session["_csrf_token"]=secrets.token_urlsafe(32)
        return {"csrf_token":session["_csrf_token"]}
    def allowed():return db.authorized_targets(app.config["DATABASE"])
    @app.get("/")
    def dashboard():
        scans=db.list_scans(app.config["DATABASE"]); findings=db.get_findings(path=app.config["DATABASE"])
        stats={s:sum(1 for f in findings if f["severity"]==s) for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
        categories={}
        dates={}
        for f in findings:
            categories[f["category"]]=categories.get(f["category"],0)+1
            day=f["detected_at"][:10]; dates[day]=dates.get(day,0)+1
        timeline=sorted(dates.items())[-14:]
        return render_template("dashboard.html",scans=scans[:8],stats=stats,total_scans=len(scans),total_findings=len(findings),categories=categories,timeline=timeline)
    @app.route("/scans/new",methods=["GET","POST"])
    def new_scan():
        if request.method=="POST":
            scan=None; findings=[]
            target=request.form.get("target",""); confirm=request.form.get("authorized")=="yes"
            try:
                target=validate_target(target,allowed(),confirm)
                scan_id=str(uuid.uuid4()); start=datetime.now(timezone.utc).isoformat(timespec="seconds")
                scan={"scan_id":scan_id,"target_url":target,"started_at":start,"status":"RUNNING"}
                findings,pages=run_scan(target,allowed(),timeout=request.form.get("timeout",5),max_pages=request.form.get("max_pages",10),delay=request.form.get("delay",.15),confirm=True)
                failed=pages==0 and not findings
                scan.update(completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),status="FAILED" if failed else "COMPLETED",pages_checked=pages,error="No pages could be retrieved from this target." if failed else None)
                db.save_scan(scan,findings,app.config["DATABASE"])
                if failed:flash(scan["error"],"error")
                else:flash(f"Scan complete: {pages} page(s), {len(findings)} finding(s).","success")
                return redirect(url_for("scan_details",scan_id=scan_id))
            except (TargetError,ValueError) as e:
                if scan:save_failed_scan(scan,findings,e,app.config["DATABASE"])
                flash(str(e),"error")
            except Exception as e:
                if scan:save_failed_scan(scan,findings,e,app.config["DATABASE"])
                flash(f"Scan failed safely: {str(e)[:240]}","error")
        return render_template("new_scan.html",targets=allowed(),form_data=request.form)
    @app.get("/scans")
    def scan_history():return render_template("scan_history.html",scans=db.list_scans(app.config["DATABASE"]))
    @app.get("/scans/<scan_id>")
    def scan_details(scan_id):
        scan=db.get_scan(scan_id,app.config["DATABASE"])
        if not scan:abort(404)
        findings=db.get_findings(scan_id,app.config["DATABASE"]); counts={s:sum(1 for f in findings if f["severity"]==s) for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
        return render_template("scan_details.html",scan=scan,findings=findings,counts=counts)
    @app.get("/findings")
    def findings_page():
        severity=request.args.get("severity") or None; category=request.args.get("category") or None
        date_from=request.args.get("date_from") or None; date_to=request.args.get("date_to") or None; scan_id=request.args.get("scan_id") or None
        all_findings=db.get_findings(path=app.config["DATABASE"])
        categories=sorted({f["category"] for f in all_findings})
        return render_template("findings.html",findings=db.get_findings(scan_id,app.config["DATABASE"],severity,category,date_from,date_to),severity=severity,category=category,date_from=date_from,date_to=date_to,scan_id=scan_id,scans=db.list_scans(app.config["DATABASE"]),categories=categories)
    @app.get("/findings/<finding_id>")
    def finding_details(finding_id):
        finding=db.get_finding(finding_id,app.config["DATABASE"])
        if not finding:abort(404)
        return render_template("finding_details.html",finding=finding)
    @app.get("/reports")
    def reports_page():
        scans=db.list_scans(app.config["DATABASE"]); selected=request.args.get("scan_id")
        if selected:scans=[s for s in scans if s["scan_id"]==selected]
        findings=db.get_findings(path=app.config["DATABASE"])
        categories=sorted({f["category"] for f in findings})
        return render_template("reports.html",scans=scans,all_scans=db.list_scans(app.config["DATABASE"]),categories=categories)
    @app.get("/reports/<scan_id>/<kind>")
    def download_report(scan_id,kind):
        if not db.get_scan(scan_id,app.config["DATABASE"]):abort(404)
        filters={"severity":request.args.get("severity"),"category":request.args.get("category"),"date_from":request.args.get("date_from"),"date_to":request.args.get("date_to")}
        if kind=="csv":return Response(csv_report(scan_id,app.config["DATABASE"],**filters),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=vulnscan-{scan_id}.csv"})
        if kind=="html":return Response(html_report(scan_id,app.config["DATABASE"],**filters),mimetype="text/html",headers={"Content-Disposition":f"attachment; filename=vulnscan-{scan_id}.html"})
        abort(404)
    @app.route("/settings",methods=["GET","POST"])
    def settings():
        if request.method=="POST":
            try:
                if request.form.get("action")=="remove":
                    host=request.form.get("host","").strip().lower().rstrip(".")
                    removed=db.remove_authorized_target(host,app.config["DATABASE"])
                    flash("Authorization removed." if removed else "Target was not on the active allowlist.","success" if removed else "error")
                    return redirect(url_for("settings"))
                host=request.form.get("host","").strip().lower().rstrip(".")
                if "://" in host:host=urlsplit(host).hostname or ""
                if not host or "/" in host or "@" in host:raise ValueError("Enter a hostname only.")
                validate_target("https://"+host, [host], True)
                db.add_authorized_target(host,app.config["DATABASE"]); flash("Authorization allowlist updated.","success")
            except Exception as e:
                flash(str(e),"error")
                return render_template("settings.html",targets=allowed(),form_host=request.form.get("host",""))
            return redirect(url_for("settings"))
        return render_template("settings.html",targets=allowed(),form_host="")
    @app.get("/health")
    def health():return jsonify(status="ok",name="VulnScan")
    return app

app=create_app()
if __name__=="__main__":app.run(host="127.0.0.1",port=5000,debug=False)
