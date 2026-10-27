import ml, metrics
def test_classifier_and_anomaly():
    r = ml.classify("FIRE SAFETY CERTIFICATE\nInstitution Name: X\nValid Until: 2027-01-01"); assert r["type"] == "fire_safety" and r["confidence"] > 0.8
    assert not ml.anomaly([0, 0, 0, 0, 0.3, 6])[0] and ml.anomaly([898, 1, 1, 1, 0.3, 6])[0]
def test_batch_metrics_are_perfect_on_injected_faults():
    o = metrics.run(write=False); assert o["extraction_accuracy"] > 0.99 and o["micro_precision"] > 0.95 and o["micro_recall"] > 0.95
