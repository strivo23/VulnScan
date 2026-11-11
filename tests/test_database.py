from database.db import init_db,save_scan,get_scan,get_findings
from datetime import datetime,timezone
def test_storage_and_dedupe(tmp_path):
 p=tmp_path/'db.sqlite';init_db(p);scan={'scan_id':'s1','target_url':'http://127.0.0.1/','started_at':datetime.now(timezone.utc).isoformat(),'completed_at':None,'status':'COMPLETED','pages_checked':1}
 f={'finding_id':'f1','scan_id':'s1','rule_id':'R','title':'Title','category':'Test','severity':'LOW','affected_url':'http://127.0.0.1/','description':'D','evidence':'E','impact':'I','remediation':'R','detected_at':datetime.now(timezone.utc).isoformat()}
 save_scan(scan,[f,f],p);assert get_scan('s1',p)['total_findings']==1;assert len(get_findings('s1',p))==1
