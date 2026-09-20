from datetime import datetime, timedelta, timezone

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import BruteForceDetector
from packet_watch.models import DetectionResult, ParsedPacket
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


def brute_settings():
    return load_settings("config/config.json").thresholds["brute_force"]


def packet(timestamp, source="10.0.0.5", destination="10.0.0.1", port=22, flags="S", protocol="TCP"):
    return ParsedPacket(
        timestamp=timestamp,
        src_ip=source,
        dst_ip=destination,
        src_port=50000,
        dst_port=port,
        protocol=protocol,
        tcp_flags=flags,
    )


def test_same_target_tcp_syns_trigger_brute_force():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = BruteForceDetector(brute_settings())
    for _ in range(brute_settings()["connection_attempts"]):
        tracker.observe(packet(now))

    result = detector.detect(packet(now), tracker.snapshot("10.0.0.5"))

    assert result is not None
    assert result.observed["connection_attempts"] == brute_settings()["connection_attempts"]


def test_different_target_ports_do_not_combine():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = BruteForceDetector(brute_settings())
    for _ in range(5):
        tracker.observe(packet(now, port=22))
        tracker.observe(packet(now, port=3389))

    assert detector.detect(packet(now, port=22), tracker.snapshot("10.0.0.5")) is None
    assert tracker.snapshot("10.0.0.5").tcp_connection_attempts_by_target[("10.0.0.1", 22)] == 5


def test_different_target_ips_do_not_combine():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = BruteForceDetector(brute_settings())
    for _ in range(5):
        tracker.observe(packet(now, destination="10.0.0.1"))
        tracker.observe(packet(now, destination="10.0.0.2"))

    assert detector.detect(packet(now, destination="10.0.0.1"), tracker.snapshot("10.0.0.5")) is None


def test_udp_cannot_trigger_from_tcp_attempt_state():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = BruteForceDetector(brute_settings())
    for _ in range(brute_settings()["connection_attempts"]):
        tracker.observe(packet(now))

    assert detector.detect(packet(now, protocol="UDP", flags=""), tracker.snapshot("10.0.0.5")) is None


def test_only_syn_without_ack_increments_target_attempts():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    flags = ["S", "SA", "A", "R", "FA"]
    for value in flags:
        tracker.observe(packet(now, flags=value))

    state = tracker.snapshot("10.0.0.5")
    assert state.tcp_connection_attempts == 1
    assert state.tcp_connection_attempts_by_target[("10.0.0.1", 22)] == 1


def test_target_attempts_expire_with_rolling_window():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    for _ in range(3):
        tracker.observe(packet(now))
    tracker.observe(packet(now + timedelta(seconds=61)))

    state = tracker.snapshot("10.0.0.5")
    assert state.tcp_connection_attempts_by_target[("10.0.0.1", 22)] == 1


def test_different_sources_remain_isolated():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    for _ in range(5):
        tracker.observe(packet(now, source="10.0.0.5"))
        tracker.observe(packet(now, source="10.0.0.6"))

    assert tracker.snapshot("10.0.0.5").tcp_connection_attempts_by_target[("10.0.0.1", 22)] == 5
    assert tracker.snapshot("10.0.0.6").tcp_connection_attempts_by_target[("10.0.0.1", 22)] == 5


def test_brute_force_deduplication_includes_destination_port():
    engine = DetectionEngine([], RollingStateTracker(60), SeverityScorer(), WhitelistFilter())
    result = DetectionResult("Brute-Force Attempts", "PW-BRUTE-001", "10.0.0.5", "10.0.0.1", "TCP", {}, {}, {}, {})
    first = packet(datetime.now(timezone.utc), port=22)
    second = packet(first.timestamp, port=3389)

    assert engine._dedup_key(result, first) != engine._dedup_key(result, second)


def test_brute_force_whitelist_preserves_suppressed_alert():
    now = datetime.now(timezone.utc)
    engine = DetectionEngine(
        [BruteForceDetector(brute_settings())],
        RollingStateTracker(60),
        SeverityScorer(),
        WhitelistFilter({"10.0.0.5"}),
    )
    for _ in range(brute_settings()["connection_attempts"]):
        alerts = engine.process(packet(now))

    assert not alerts
    assert len(engine.suppressed_alerts) == 1
    assert engine.suppressed_alerts[0].observed["connection_attempts"] == brute_settings()["connection_attempts"]