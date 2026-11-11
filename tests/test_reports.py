from database.db import init_db,save_scan
from reports.report_generator import csv_report,html_report
def test_report_formats(tmp_path):
 p=tmp_path/'r.sqlite';init_db(p);s={'scan_id':'r1','target_url':'http://localhost/','started_at':'now','completed_at':'done','status':'COMPLETED','pages_checked':1};f={'finding_id':'f','scan_id':'r1','rule_id':'R','title':'Safe <title>','category':'Headers','severity':'LOW','affected_url':'http://localhost/','description':'d','evidence':'e','impact':'i','remediation':'r','detected_at':'now'};save_scan(s,[f],p)
 assert 'finding_id' in csv_report('r1',p);assert '&lt;title&gt;' in html_report('r1',p)
