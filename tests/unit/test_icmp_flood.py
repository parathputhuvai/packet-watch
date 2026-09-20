from datetime import datetime, timedelta, timezone

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import ICMPFloodDetector
from packet_watch.models import ParsedPacket
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


def icmp_settings():
    return load_settings("config/config.json").thresholds["icmp_flood"]


def packet(timestamp, source="10.0.0.5", destination="10.0.0.1", protocol="ICMP", icmp_type=8, icmp_code=0):
    return ParsedPacket(
        timestamp=timestamp,
        src_ip=source,
        dst_ip=destination,
        protocol=protocol,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )


def small_settings():
    return {"icmp_packets": 3, "high_icmp_packets": 6, "critical_icmp_packets": 12}


def test_icmp_flood_triggers_at_configured_threshold():
    config = icmp_settings()
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = ICMPFloodDetector(config)
    for _ in range(config["icmp_packets"]):
        tracker.observe(packet(now))

    result = detector.detect(packet(now), tracker.snapshot("10.0.0.5"))

    assert result is not None
    assert result.observed["icmp_packets"] == config["icmp_packets"]
    assert result.thresholds == config


def test_icmp_below_threshold_does_not_trigger():
    config = icmp_settings()
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = ICMPFloodDetector(config)
    for _ in range(config["icmp_packets"] - 1):
        tracker.observe(packet(now))

    assert detector.detect(packet(now), tracker.snapshot("10.0.0.5")) is None


def test_non_icmp_packets_do_not_increase_icmp_count():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    tracker.observe(packet(now, protocol="TCP"))
    tracker.observe(packet(now, protocol="UDP"))

    assert tracker.snapshot("10.0.0.5").icmp_count == 0


def test_icmp_state_is_isolated_by_source_ip():
    config = small_settings()
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = ICMPFloodDetector(config)
    for _ in range(config["icmp_packets"]):
        tracker.observe(packet(now, source="10.0.0.5"))
    tracker.observe(packet(now, source="10.0.0.6"))

    assert tracker.snapshot("10.0.0.5").icmp_count == config["icmp_packets"]
    assert tracker.snapshot("10.0.0.6").icmp_count == 1
    assert detector.detect(packet(now, source="10.0.0.6"), tracker.snapshot("10.0.0.6")) is None


def test_icmp_observations_expire_from_rolling_window():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(10)
    for _ in range(3):
        tracker.observe(packet(now))
    tracker.observe(packet(now + timedelta(seconds=11)))

    assert tracker.snapshot("10.0.0.5").icmp_count == 1


def test_all_icmp_packet_types_share_the_same_count():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    for icmp_type, icmp_code in ((0, 0), (3, 1), (8, 0), (11, 0)):
        tracker.observe(packet(now, icmp_type=icmp_type, icmp_code=icmp_code))

    assert tracker.snapshot("10.0.0.5").icmp_count == 4


def test_whitelist_suppression_preserves_icmp_alert_evidence():
    config = small_settings()
    now = datetime.now(timezone.utc)
    engine = DetectionEngine(
        [ICMPFloodDetector(config)],
        RollingStateTracker(60),
        SeverityScorer(),
        WhitelistFilter({"10.0.0.5"}),
    )
    for _ in range(config["icmp_packets"]):
        alerts = engine.process(packet(now))

    assert not alerts
    assert len(engine.suppressed_alerts) == 1
    suppressed = engine.suppressed_alerts[0]
    assert suppressed.whitelisted is True
    assert suppressed.observed["icmp_packets"] == config["icmp_packets"]
    assert suppressed.thresholds == config
    assert suppressed.evidence["reason"]


def test_repeated_icmp_flood_alerts_follow_deduplication():
    config = small_settings()
    now = datetime.now(timezone.utc)
    engine = DetectionEngine(
        [ICMPFloodDetector(config)],
        RollingStateTracker(60),
        SeverityScorer(),
        WhitelistFilter(),
    )
    first_alert = []
    for _ in range(config["icmp_packets"]):
        first_alert = engine.process(packet(now))
    second_alert = engine.process(packet(now))

    assert len(first_alert) == 1
    assert second_alert == []
