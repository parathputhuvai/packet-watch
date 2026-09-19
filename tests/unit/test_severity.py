from packet_watch.models import DetectionResult, Severity
from packet_watch.severity import SeverityScorer


def test_severity_is_deterministic_and_rule_based():
    result = DetectionResult("Port Scanning", "PW-PORT-001", "10.0.0.1", "10.0.0.2", "TCP", {}, {"distinct_destination_ports": 100}, {"distinct_destination_ports": 20, "high_ports": 50, "critical_ports": 100}, {"technique_id":"T1046","technique_name":"Network Service Scanning","tactic":"Discovery"})
    out = SeverityScorer().assign(result)
    assert out.severity == Severity.CRITICAL
    assert out.score == 90
