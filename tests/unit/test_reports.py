from datetime import datetime, timezone

from packet_watch.models import Alert, Severity
from packet_watch.correlation import AlertTimeline
from packet_watch.reporting import write_csv, write_pdf


def make_alert():
    return Alert("ABC123", datetime.now(timezone.utc), "10.0.0.5", "10.0.0.1", 4444, 22, "TCP", "Brute-Force Attempts", Severity.HIGH, "PW-BRUTE-001", {"reason":"test"}, {"connection_attempts":25}, {"connection_attempts":10}, {"technique_id":"T1110","technique_name":"Brute Force","tactic":"Credential Access"})


def test_csv_and_pdf_export(tmp_path):
    alerts = [make_alert()]
    csv_path = write_csv(tmp_path / "test.csv", alerts)
    pdf_path = write_pdf(tmp_path / "test.pdf", alerts, alerts[0].timestamp, alerts[0].timestamp)
    assert csv_path.exists() and csv_path.stat().st_size > 0
    assert pdf_path.exists() and pdf_path.stat().st_size > 0


def test_reports_include_timeline_correlation(tmp_path):
    first = make_alert()
    first.timestamp = datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
    second = Alert("DEF456", datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc), "10.0.0.5", "10.0.0.1", 4444, 23, "TCP", "Port Scan", Severity.MEDIUM, "PW-PORT-001", {}, {}, {}, {})
    timeline = AlertTimeline()
    timeline.add(first)
    timeline.add(second)

    csv_path = write_csv(tmp_path / "timeline.csv", [first, second], timeline.events())
    rows = csv_path.read_text(encoding="utf-8").splitlines()
    assert "correlation_source_ip" in rows[0]
    assert "10.0.0.5" in rows[1] and ",2,2" in rows[1]
    assert "10.0.0.5" in rows[2] and ",1,2" in rows[2]

    pdf_path = write_pdf(tmp_path / "timeline.pdf", [first, second], first.timestamp, first.timestamp, timeline.events())
    assert pdf_path.exists() and pdf_path.stat().st_size > 0


def test_timeline_orders_events_by_source_and_keeps_groups_separate():
    earlier = make_alert()
    earlier.timestamp = datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    later = make_alert()
    later.alert_id = "DEF456"
    later.timestamp = datetime(2026, 1, 1, 0, 0, 3, tzinfo=timezone.utc)
    other = make_alert()
    other.alert_id = "GHI789"
    other.source_ip = "10.0.0.6"
    other.timestamp = datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
    timeline = AlertTimeline()
    timeline.add(later)
    timeline.add(other)
    timeline.add(earlier)

    assert [event.alert_id for event in timeline.events()] == [earlier.alert_id, other.alert_id, later.alert_id]
    assert [event.alert_id for event in timeline.events() if event.source_ip == "10.0.0.5"] == [earlier.alert_id, later.alert_id]
