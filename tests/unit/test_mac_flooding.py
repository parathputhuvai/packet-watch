from datetime import datetime, timedelta, timezone

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import MACFloodingDetector, build_detectors
from packet_watch.models import ParsedPacket, Severity
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


SOURCE_IP = "192.0.2.10"
DESTINATION_IP = "198.51.100.20"
MAC_THRESHOLD = 50


def settings():
    return load_settings("config/config.json")


def packet(timestamp, mac_index, protocol="OTHER", src_mac=None):
    return ParsedPacket(
        timestamp=timestamp,
        src_ip=SOURCE_IP,
        dst_ip=DESTINATION_IP,
        protocol=protocol,
        src_mac=src_mac or f"02:00:00:{mac_index // 65536:02x}:{(mac_index // 256) % 256:02x}:{mac_index % 256:02x}",
    )


def detector():
    return MACFloodingDetector(settings().thresholds["mac_flooding"])


def engine_with_mac_detector(whitelist_ips=None):
    configured = settings()
    detectors = build_detectors(configured)
    mac_detector = next(
        item for item in detectors if isinstance(item, MACFloodingDetector)
    )
    engine = DetectionEngine(
        [mac_detector],
        RollingStateTracker(configured.rolling_window_seconds),
        SeverityScorer(),
        WhitelistFilter(whitelist_ips or configured.whitelist_ips, configured.whitelist_ports),
    )
    return engine, mac_detector


def test_mac_flood_detector_is_registered_and_below_threshold_does_not_trigger():
    configured = settings()
    registered = build_detectors(configured)
    mac_detector = next(
        item for item in registered if isinstance(item, MACFloodingDetector)
    )
    assert mac_detector.rule_id == "PW-MAC-001"
    assert configured.rolling_window_seconds == 60
    assert configured.thresholds["mac_flooding"]["distinct_source_macs"] == MAC_THRESHOLD

    tracker = RollingStateTracker(configured.rolling_window_seconds)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index in range(MAC_THRESHOLD - 1):
        state = tracker.observe(packet(now, index))

    assert len(state.source_macs) == MAC_THRESHOLD - 1
    assert mac_detector.detect(packet(now, MAC_THRESHOLD - 1), state) is None


def test_mac_flood_detector_triggers_at_threshold():
    mac_detector = detector()
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for index in range(MAC_THRESHOLD):
        state = tracker.observe(packet(now, index))

    result = mac_detector.detect(packet(now, MAC_THRESHOLD), state)

    assert result is not None
    assert result.rule_id == "PW-MAC-001"
    assert result.observed == {"distinct_source_macs": MAC_THRESHOLD}
    assert result.thresholds == settings().thresholds["mac_flooding"]


def test_mac_flood_detector_triggers_above_threshold_and_scores_by_count():
    mac_detector = detector()
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    high_threshold = settings().thresholds["mac_flooding"]["high_macs"]
    for index in range(high_threshold):
        state = tracker.observe(packet(now, index))

    result = mac_detector.detect(packet(now, high_threshold), state)

    assert result is not None
    assert result.observed["distinct_source_macs"] == high_threshold
    assert SeverityScorer().assign(result).severity is Severity.HIGH


def test_repeated_source_macs_do_not_increase_distinct_count():
    mac_detector = detector()
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    repeated_mac = "02:00:00:00:00:01"

    for _ in range(MAC_THRESHOLD * 2):
        state = tracker.observe(packet(now, 1, src_mac=repeated_mac))

    assert len(state.source_macs) == 1
    assert mac_detector.detect(packet(now, 1, src_mac=repeated_mac), state) is None


def test_distinct_macs_from_different_protocols_are_counted():
    mac_detector = detector()
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    protocols = ("OTHER", "TCP", "UDP", "ICMP", "ARP")

    for index in range(MAC_THRESHOLD):
        state = tracker.observe(packet(now, index, protocol=protocols[index % len(protocols)]))

    assert len(state.source_macs) == MAC_THRESHOLD
    result = mac_detector.detect(
        packet(now, MAC_THRESHOLD, protocol="ARP"),
        state,
    )
    assert result is not None
    assert result.rule_id == "PW-MAC-001"


def test_mac_observations_expire_from_the_rolling_window():
    mac_detector = detector()
    tracker = RollingStateTracker(window_seconds=10)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for index in range(MAC_THRESHOLD):
        state = tracker.observe(packet(now, index))
    assert mac_detector.detect(packet(now, MAC_THRESHOLD), state) is not None

    later = now + timedelta(seconds=11)
    state = tracker.observe(packet(later, MAC_THRESHOLD))

    assert len(state.source_macs) == 1
    assert mac_detector.detect(packet(later, MAC_THRESHOLD + 1), state) is None


def test_engine_generates_mac_alert_with_expected_fields_and_deduplicates():
    engine, _ = engine_with_mac_detector()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alerts = []

    for index in range(MAC_THRESHOLD):
        alerts.extend(engine.process(packet(now, index)))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "PW-MAC-001"
    assert alert.attack_type == "MAC Flooding"
    assert alert.severity is Severity.LOW
    assert alert.source_ip == SOURCE_IP
    assert alert.destination_ip == DESTINATION_IP
    assert alert.protocol == "OTHER"
    assert alert.source_port is None
    assert alert.destination_port is None
    assert alert.observed == {"distinct_source_macs": MAC_THRESHOLD}
    assert alert.thresholds == settings().thresholds["mac_flooding"]
    assert alert.evidence["reason"]
    assert len(alert.alert_id) == 12

    duplicate = engine.process(packet(now + timedelta(seconds=1), MAC_THRESHOLD))
    assert duplicate == []


def test_engine_suppresses_whitelisted_mac_flood_alert():
    engine, _ = engine_with_mac_detector({SOURCE_IP})
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for index in range(MAC_THRESHOLD):
        alerts = engine.process(packet(now, index))

    assert alerts == []
    assert len(engine.suppressed_alerts) == 1
    alert = engine.suppressed_alerts[0]
    assert alert.rule_id == "PW-MAC-001"
    assert alert.whitelisted is True
    assert alert.suppressed_reason == "source/destination IP is whitelisted"
