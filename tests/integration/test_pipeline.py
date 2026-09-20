from datetime import datetime, timezone

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import PortScanDetector
from packet_watch.models import Alert, ParsedPacket, Severity
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter
from packet_watch.cli.app import PacketWatchApp


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


def test_app_adds_new_suppressed_alert_to_timeline():
    settings = load_settings("config/config.json")
    app = PacketWatchApp(settings)
    now = datetime.now(timezone.utc)
    packet = ParsedPacket(now, "10.0.0.8", "10.0.0.1", 50000, 22, "TCP", "S")
    alert = Alert("SUP123", now, "10.0.0.8", "10.0.0.1", 50000, 22, "TCP", "Port Scan", Severity.HIGH, "PW-PORT-001", {}, {}, {}, {}, whitelisted=True, suppressed_reason="source IP")
    app.parser.parse = lambda raw_packet: packet

    def process(_packet):
        if not app.engine.suppressed_alerts:
            app.engine.suppressed_alerts.append(alert)
        return []

    app.engine.process = process
    app.process_packet(object())
    app.process_packet(object())

    assert app.alerts == []
    assert app.engine.suppressed_alerts == [alert]
    assert [event.alert_id for event in app.timeline.events()] == [alert.alert_id]
