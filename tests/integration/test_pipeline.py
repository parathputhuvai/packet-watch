from datetime import datetime, timezone

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import PortScanDetector
from packet_watch.models import ParsedPacket
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


def test_pipeline_generates_alert_and_whitelist_can_suppress():
    settings = load_settings("config/config.json")
    state = RollingStateTracker(60)
    engine = DetectionEngine([PortScanDetector(settings.thresholds["port_scan"])], state, SeverityScorer(), WhitelistFilter(),)
    now = datetime.now(timezone.utc)
    alerts = []
    for port in range(1, 21):
        alerts.extend(engine.process(ParsedPacket(now, "10.0.0.8", "10.0.0.1", 50000, port, "TCP", "S")))
    assert alerts
    suppressed_engine = DetectionEngine([PortScanDetector(settings.thresholds["port_scan"])], RollingStateTracker(60), SeverityScorer(), WhitelistFilter({"10.0.0.8"}),)
    alerts2=[]
    for port in range(1,21): alerts2.extend(suppressed_engine.process(ParsedPacket(now, "10.0.0.8", "10.0.0.1", 50000, port, "TCP", "S")))
    assert not alerts2
    assert suppressed_engine.suppressed_alerts and suppressed_engine.suppressed_alerts[-1].whitelisted
