from datetime import datetime, timedelta, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import SynFloodDetector, build_detectors
from packet_watch.models import Severity
from packet_watch.parser import PacketParser
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


SOURCE_IP = "192.0.2.10"
DESTINATION_IP = "198.51.100.20"
DESTINATION_PORT = 443


def settings():
    return load_settings("config/config.json")


def raw_tcp(timestamp, flags="S", source=SOURCE_IP, destination=DESTINATION_IP):
    packet = (
        IP(src=source, dst=destination)
        / TCP(sport=50000, dport=DESTINATION_PORT, flags=flags)
    )
    packet.time = timestamp.timestamp()
    return packet


def raw_non_tcp(timestamp, kind, source=SOURCE_IP):
    base = IP(src=source, dst=DESTINATION_IP)
    if kind == "UDP":
        packet = base / UDP(sport=50000, dport=DESTINATION_PORT)
    elif kind == "ICMP":
        packet = base / ICMP()
    else:
        packet = base / IP(proto=47)
    packet.time = timestamp.timestamp()
    return packet


def parse(raw_packet):
    parsed = PacketParser().parse(raw_packet)
    assert parsed is not None
    return parsed


def detector():
    return SynFloodDetector(settings().thresholds["syn_flood"])


def observe_tcp(tracker, timestamp, count, flags="S", source=SOURCE_IP):
    state = None
    for _ in range(count):
        state = tracker.observe(parse(raw_tcp(timestamp, flags, source)))
    return state


def test_syn_detector_is_registered_and_below_threshold_does_not_trigger():
    configured = settings()
    registered = build_detectors(configured)
    syn_detector = next(
        item for item in registered if isinstance(item, SynFloodDetector)
    )
    threshold = configured.thresholds["syn_flood"]["syn_packets"]
    assert syn_detector.rule_id == "PW-SYN-001"
    assert configured.rolling_window_seconds == 60

    tracker = RollingStateTracker(configured.rolling_window_seconds)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    state = observe_tcp(tracker, now, threshold - 1)

    assert state.syn_count == threshold - 1
    assert syn_detector.detect(parse(raw_tcp(now)), state) is None


def test_syn_detector_triggers_at_exact_base_threshold():
    configured = settings()
    threshold = configured.thresholds["syn_flood"]["syn_packets"]
    tracker = RollingStateTracker(configured.rolling_window_seconds)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    state = observe_tcp(tracker, now, threshold)

    result = detector().detect(parse(raw_tcp(now, "A")), state)

    assert state.syn_count == threshold
    assert result is not None
    assert result.rule_id == "PW-SYN-001"
    assert result.observed == {
        "syn_packets": threshold,
        "syn_ack_packets": 0,
        "syn_ack_ratio": float(threshold),
    }
    assert result.thresholds == configured.thresholds["syn_flood"]
    assert SeverityScorer().assign(result).severity is Severity.LOW


def test_configured_high_syn_threshold_triggers_with_high_severity():
    configured = settings()
    high_threshold = configured.thresholds["syn_flood"]["high_syn_packets"]
    tracker = RollingStateTracker(configured.rolling_window_seconds)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observe_tcp(tracker, now, high_threshold, "S")
    state = observe_tcp(tracker, now, 100, "SA")

    result = detector().detect(parse(raw_tcp(now)), state)

    assert result is not None
    assert result.observed["syn_packets"] == high_threshold
    assert result.observed["syn_ack_packets"] == 100
    assert result.observed["syn_ack_ratio"] < configured.thresholds["syn_flood"]["syn_ack_ratio"]
    assert SeverityScorer().assign(result).severity is Severity.HIGH


def test_configured_critical_syn_threshold_scores_critical():
    configured = settings()
    critical_threshold = configured.thresholds["syn_flood"]["critical_syn_packets"]
    tracker = RollingStateTracker(configured.rolling_window_seconds)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observe_tcp(tracker, now, critical_threshold, "S")
    state = observe_tcp(tracker, now, 200, "SA")

    result = detector().detect(parse(raw_tcp(now)), state)

    assert result is not None
    assert result.observed["syn_packets"] == critical_threshold
    assert result.observed["syn_ack_ratio"] < configured.thresholds["syn_flood"]["syn_ack_ratio"]
    assert SeverityScorer().assign(result).severity is Severity.CRITICAL


def test_syn_ack_ratio_below_threshold_rejects_base_count_but_equal_ratio_triggers():
    configured = settings()
    base_threshold = configured.thresholds["syn_flood"]["syn_packets"]
    ratio_threshold = configured.thresholds["syn_flood"]["syn_ack_ratio"]
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    below_tracker = RollingStateTracker(60)
    below_state = observe_tcp(below_tracker, now, base_threshold, "S")
    observe_tcp(below_tracker, now, 26, "SA")
    below_state = below_tracker.snapshot(SOURCE_IP)
    assert below_state.syn_count == base_threshold
    assert below_state.syn_ack_count == 26
    assert below_state.syn_count / below_state.syn_ack_count < ratio_threshold
    assert detector().detect(parse(raw_tcp(now, "S")), below_state) is None

    equal_tracker = RollingStateTracker(60)
    equal_state = observe_tcp(equal_tracker, now, base_threshold, "S")
    observe_tcp(equal_tracker, now, 25, "SA")
    equal_state = equal_tracker.snapshot(SOURCE_IP)
    assert equal_state.syn_count / equal_state.syn_ack_count == ratio_threshold
    result = detector().detect(parse(raw_tcp(now, "S")), equal_state)
    assert result is not None
    assert result.observed["syn_ack_ratio"] == ratio_threshold


def test_only_syn_without_ack_counts_as_syn_and_syn_ack_counts_separately():
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for flags in ("S", "SA", "A", "R", "F", "FA"):
        state = tracker.observe(parse(raw_tcp(now, flags)))

    assert state.syn_count == 1
    assert state.syn_ack_count == 1
    assert state.tcp_connection_attempts == 1


def test_syn_flag_combined_with_fin_is_counted_by_current_flag_predicate():
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    state = tracker.observe(parse(raw_tcp(now, "FS")))

    assert state.syn_count == 1
    assert state.tcp_connection_attempts == 1


def test_syn_ack_packets_alone_do_not_trigger_syn_flood():
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    state = observe_tcp(tracker, now, 100, "SA")

    assert state.syn_count == 0
    assert state.syn_ack_count == 100
    assert detector().detect(parse(raw_tcp(now, "SA")), state) is None


def test_non_tcp_packets_do_not_contribute_to_syn_count_or_trigger():
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for kind in ("UDP", "ICMP", "OTHER"):
        state = None
        for _ in range(150):
            state = tracker.observe(parse(raw_non_tcp(now, kind)))
        assert state.syn_count == 0
        assert detector().detect(parse(raw_tcp(now)), state) is None


def test_syn_counts_are_isolated_by_source_ip():
    tracker = RollingStateTracker(60)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    threshold = settings().thresholds["syn_flood"]["syn_packets"]

    for index in range(threshold // 2):
        tracker.observe(parse(raw_tcp(now, source="192.0.2.10")))
        tracker.observe(parse(raw_tcp(now, source="192.0.2.11")))

    first = tracker.snapshot("192.0.2.10")
    second = tracker.snapshot("192.0.2.11")
    assert first.syn_count == threshold // 2
    assert second.syn_count == threshold // 2
    assert detector().detect(
        parse(raw_tcp(now, source="192.0.2.10")), first
    ) is None
    assert detector().detect(
        parse(raw_tcp(now, source="192.0.2.11")), second
    ) is None


def test_syn_count_aggregates_destinations_for_the_same_source():
    configured = settings()
    threshold = configured.thresholds["syn_flood"]["syn_packets"]
    tracker = RollingStateTracker(configured.rolling_window_seconds)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    for index in range(threshold):
        destination = (
            "198.51.100.20" if index < threshold // 2 else "198.51.100.21"
        )
        state = tracker.observe(parse(raw_tcp(now, destination=destination)))

    assert state.syn_count == threshold
    assert detector().detect(parse(raw_tcp(now)), state) is not None


def test_syn_observations_expire_from_rolling_window():
    tracker = RollingStateTracker(window_seconds=10)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    threshold = settings().thresholds["syn_flood"]["syn_packets"]
    old_state = observe_tcp(tracker, now, threshold)
    assert detector().detect(parse(raw_tcp(now)), old_state) is not None

    later = now + timedelta(seconds=11)
    new_state = tracker.observe(parse(raw_tcp(later)))

    assert new_state.syn_count == 1
    assert detector().detect(parse(raw_tcp(later)), new_state) is None


def test_detection_engine_generates_alert_with_expected_fields_and_deduplicates():
    configured = settings()
    engine = DetectionEngine(
        build_detectors(configured),
        RollingStateTracker(configured.rolling_window_seconds),
        SeverityScorer(),
        WhitelistFilter(),
    )
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alerts = []

    for _ in range(configured.thresholds["syn_flood"]["syn_packets"]):
        alerts.extend(engine.process(parse(raw_tcp(now))))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "PW-SYN-001"
    assert alert.attack_type == "SYN Flood"
    assert alert.source_ip == SOURCE_IP
    assert alert.destination_ip == DESTINATION_IP
    assert alert.source_port == 50000
    assert alert.destination_port == DESTINATION_PORT
    assert alert.protocol == "TCP"
    assert alert.severity is Severity.LOW
    assert alert.evidence["reason"]
    assert alert.observed["syn_packets"] == 100
    assert alert.thresholds == configured.thresholds["syn_flood"]
    assert len(alert.alert_id) == 12

    duplicate = engine.process(
        parse(raw_tcp(now + timedelta(seconds=1), "S"))
    )
    assert duplicate == []


def test_detection_engine_suppresses_whitelisted_syn_flood_alert():
    configured = settings()
    engine = DetectionEngine(
        build_detectors(configured),
        RollingStateTracker(configured.rolling_window_seconds),
        SeverityScorer(),
        WhitelistFilter({SOURCE_IP}),
    )
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = []
    for _ in range(configured.thresholds["syn_flood"]["syn_packets"]):
        alerts.extend(engine.process(parse(raw_tcp(now))))

    assert alerts == []
    assert len(engine.suppressed_alerts) == 1
    suppressed = engine.suppressed_alerts[0]
    assert suppressed.rule_id == "PW-SYN-001"
    assert suppressed.whitelisted is True
    assert suppressed.suppressed_reason == "source/destination IP is whitelisted"
