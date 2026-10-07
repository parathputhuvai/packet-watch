from datetime import datetime, timedelta, timezone

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors.dns_tunneling import DNSTunnelingDetector
from packet_watch.models import ParsedPacket
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


def dns_packet(timestamp, query, protocol="UDP"):
    return ParsedPacket(
        timestamp=timestamp,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
        src_port=53000,
        dst_port=53,
        protocol=protocol,
        dns_query=query,
    )


def detector_and_tracker():
    settings = load_settings("config/config.json")
    return DNSTunnelingDetector(settings.thresholds["dns_tunneling"]), RollingStateTracker(60)


def detect_queries(queries, protocol="UDP"):
    detector, tracker = detector_and_tracker()
    now = datetime.now(timezone.utc)
    result = None
    for index, query in enumerate(queries):
        packet = dns_packet(now + timedelta(seconds=index), query, protocol)
        state = tracker.observe(packet)
        result = detector.detect(packet, state)
    return result


def test_normal_browsing_volume_does_not_trigger_dns_tunneling():
    result = detect_queries(["aaaaaaaaaaaaaaaaa.example"] * 30)

    assert result is None


def test_suspicious_dns_triggers_after_minimum_query_count():
    query = "aB3dE7gI9kL2nP4qR6tU8wX0yZ5cF7hJ9mN2sV4xK6pQ8rT.example"

    result = detect_queries([query] * 15)

    assert result is not None
    assert result.rule_id == "PW-DNS-001"


def test_high_entropy_without_long_label_does_not_trigger():
    query = "aB3dE7gI9kL2nP4qR6tU8wX0yZ5cF7hJ9mN2sV4xK6pQ8rT.example"

    result = detect_queries([query[:17] + ".example"] * 30)

    assert result is None


def test_long_label_without_high_entropy_does_not_trigger():
    result = detect_queries(["a" * 45 + ".example"] * 30)

    assert result is None


def test_suspicious_characteristics_below_query_count_do_not_trigger():
    query = "aB3dE7gI9kL2nP4qR6tU8wX0yZ5cF7hJ9mN2sV4xK6pQ8rT.example"

    result = detect_queries([query] * 14)

    assert result is None


def test_tcp_dns_traffic_does_not_trigger():
    query = "aB3dE7gI9kL2nP4qR6tU8wX0yZ5cF7hJ9mN2sV4xK6pQ8rT.example"

    assert detect_queries([query] * 30, protocol="TCP") is None


def test_real_detection_engine_preserves_dns_alert_compatibility():
    settings = load_settings("config/config.json")
    engine = DetectionEngine(
        [DNSTunnelingDetector(settings.thresholds["dns_tunneling"])],
        RollingStateTracker(60),
        SeverityScorer(),
        WhitelistFilter(),
    )
    now = datetime.now(timezone.utc)
    normal = [dns_packet(now + timedelta(seconds=i), "aaaaaaaaaaaaaaaaa.example") for i in range(30)]
    suspicious_query = "aB3dE7gI9kL2nP4qR6tU8wX0yZ5cF7hJ9mN2sV4xK6pQ8rT.example"
    suspicious = [dns_packet(now + timedelta(seconds=61 + i), suspicious_query) for i in range(15)]

    normal_alerts = [alert for packet in normal for alert in engine.process(packet)]
    suspicious_alerts = [alert for packet in suspicious for alert in engine.process(packet)]

    assert not any(alert.rule_id == "PW-DNS-001" for alert in normal_alerts)
    assert any(alert.rule_id == "PW-DNS-001" for alert in suspicious_alerts)