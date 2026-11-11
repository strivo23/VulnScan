from evaluation.metrics import calculate_metrics
def test_metrics_and_zero_division():
 m=calculate_metrics([{'expected_finding':1,'actual_finding':1},{'expected_finding':1,'actual_finding':0},{'expected_finding':0,'actual_finding':1},{'expected_finding':0,'actual_finding':0}]);assert (m['true_positives'],m['false_positives'],m['true_negatives'],m['false_negatives'])==(1,1,1,1);assert m['f1']==.5
 assert calculate_metrics([])['precision']==0

def test_persisted_evaluation_scan_has_real_counts(tmp_path):
    from database.db import init_db
    from evaluation.run_labs import persist_scan
    path=tmp_path/'evaluation.sqlite';init_db(path)
    finding={'finding_id':'actual-finding','rule_id':'HDR-CSP','title':'Missing CSP','category':'HTTP Headers','severity':'MEDIUM','affected_url':'http://127.0.0.1:40000/','description':'missing','evidence':'not present','impact':'impact','remediation':'remediate','detected_at':'2026-11-11T00:00:00+00:00'}
    scan=persist_scan('http://127.0.0.1:40000/','2026-11-11T00:00:00+00:00',[finding],1,path)
    assert scan['status']=='COMPLETED' and scan['total_findings']==1
