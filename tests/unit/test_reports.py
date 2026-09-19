from datetime import datetime, timezone

from packet_watch.models import Alert, Severity
from packet_watch.reporting import write_csv, write_pdf


def make_alert():
    return Alert("ABC123", datetime.now(timezone.utc), "10.0.0.5", "10.0.0.1", 4444, 22, "TCP", "Brute-Force Attempts", Severity.HIGH, "PW-BRUTE-001", {"reason":"test"}, {"connection_attempts":25}, {"connection_attempts":10}, {"technique_id":"T1110","technique_name":"Brute Force","tactic":"Credential Access"})


def test_csv_and_pdf_export(tmp_path):
    alerts = [make_alert()]
    csv_path = write_csv(tmp_path / "test.csv", alerts)
    pdf_path = write_pdf(tmp_path / "test.pdf", alerts, alerts[0].timestamp, alerts[0].timestamp)
    assert csv_path.exists() and csv_path.stat().st_size > 0
    assert pdf_path.exists() and pdf_path.stat().st_size > 0
