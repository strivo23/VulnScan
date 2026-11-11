from evaluation.metrics import calculate_metrics
def test_metrics_and_zero_division():
 m=calculate_metrics([{'expected_finding':1,'actual_finding':1},{'expected_finding':1,'actual_finding':0},{'expected_finding':0,'actual_finding':1},{'expected_finding':0,'actual_finding':0}]);assert (m['true_positives'],m['false_positives'],m['true_negatives'],m['false_negatives'])==(1,1,1,1);assert m['f1']==.5
 assert calculate_metrics([])['precision']==0
