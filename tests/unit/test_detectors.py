from datetime import datetime, timezone

from packet_watch.detectors import build_detectors
from packet_watch.models import ParsedPacket
from packet_watch.config import load_settings
from packet_watch.state import RollingStateTracker


def settings(): return load_settings("config/config.json")

def test_port_scan_triggers_on_threshold():
    s = settings(); tracker = RollingStateTracker(60); detector = build_detectors(s)[0]
    now = datetime.now(timezone.utc)
    for port in range(1, s.thresholds["port_scan"]["distinct_destination_ports"] + 1):
        tracker.observe(ParsedPacket(now, "10.0.0.9", "10.0.0.1", 40000, port, "TCP", "S"))
    result = detector.detect(ParsedPacket(now, "10.0.0.9", "10.0.0.1", 40000, 9999, "TCP", "S"), tracker.snapshot("10.0.0.9"))
    assert result is not None
    assert result.rule_id == "PW-PORT-001"


def test_ping_sweep_is_distinct_from_icmp_flood():
    s = settings(); tracker = RollingStateTracker(60); ping = build_detectors(s)[7]; flood = build_detectors(s)[6]
    now = datetime.now(timezone.utc)
    for i in range(10):
        tracker.observe(ParsedPacket(now, "10.0.0.9", f"10.0.0.{20+i}", None, None, "ICMP", "", None, None, None, None, None, None, 8, 0))
    snap = tracker.snapshot("10.0.0.9")
    assert ping.detect(ParsedPacket(now, "10.0.0.9", "10.0.0.20", None, None, "ICMP", "", None, None, None, None, None, None, 8, 0), snap) is not None
    assert flood.detect(ParsedPacket(now, "10.0.0.9", "10.0.0.20", None, None, "ICMP", "", None, None, None, None, None, None, 8, 0), snap) is None
