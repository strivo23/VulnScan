def calculate_metrics(cases):
    tp=fp=tn=fn=0
    for c in cases:
        expected=bool(c.get("expected_finding")); actual=bool(c.get("actual_finding"))
        if expected and actual:tp+=1
        elif expected:fn+=1
        elif actual:fp+=1
        else:tn+=1
    div=lambda a,b:a/b if b else 0.0
    precision=div(tp,tp+fp); recall=div(tp,tp+fn); f1=div(2*precision*recall,precision+recall)
    return {"true_positives":tp,"false_positives":fp,"true_negatives":tn,"false_negatives":fn,"precision":precision,"recall":recall,"f1":f1,"detection_rate":recall,"false_positive_rate":div(fp,fp+tn)}

def evaluate_labelled(cases, findings):
    rules={f["rule_id"] for f in findings}; evaluated=[]
    for c in cases:
        found=c["rule_id"] in rules
        evaluated.append({**c,"expected_finding":c["expected_finding"],"actual_finding":found,"outcome":"TP" if c["expected_finding"] and found else "FN" if c["expected_finding"] else "FP" if found else "TN"})
    return evaluated,calculate_metrics(evaluated)
