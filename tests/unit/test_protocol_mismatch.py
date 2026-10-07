from datetime import datetime, timedelta, timezone

from scapy.layers.inet import IP, TCP, UDP

from packet_watch.config import load_settings
from packet_watch.correlation import AlertTimeline
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import ProtocolMismatchDetector, build_detectors
from packet_watch.detectors.common import (
    COMMON_TCP_PORTS,
    COMMON_UDP_PORTS,
    protocol_mismatch,
)
from packet_watch.models import ParsedPacket, Severity
from packet_watch.parser import PacketParser
from packet_watch.reporting import write_csv, write_pdf
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


def packet(source, destination, protocol, source_port, destination_port, timestamp=None):
    return ParsedPacket(
        timestamp=timestamp or datetime.now(timezone.utc),
        src_ip=source,
        dst_ip=destination,
        src_port=source_port,
        dst_port=destination_port,
        protocol=protocol,
    )


def parsed_scapy_packet(
    source,
    destination,
    protocol,
    source_port,
    destination_port,
    timestamp=None,
):
    ip = IP(src=source, dst=destination)
    if protocol == "TCP":
        raw = ip / TCP(sport=source_port, dport=destination_port)
    else:
        raw = ip / UDP(sport=source_port, dport=destination_port)
    if timestamp is not None:
        raw.time = timestamp.timestamp()
    parsed = PacketParser().parse(raw)
    assert parsed is not None
    return parsed


def mismatch_engine(detector=None, whitelist=None):
    settings = load_settings("config/config.json")
    if detector is None:
        from packet_watch.detectors.protocol_mismatch import ProtocolMismatchDetector
        detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    return DetectionEngine(
        [detector],
        RollingStateTracker(60),
        SeverityScorer(),
        WhitelistFilter(whitelist or set()),
    )


def test_remote_https_response_to_dynamic_port_is_not_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip='203.0.113.10',
        dst_ip='192.0.2.10',
        src_port=443,
        dst_port=41006,
        protocol='TCP',
    )

    assert protocol_mismatch(packet) is False


def test_dns_response_to_dynamic_port_is_not_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip='192.0.2.1',
        dst_ip='192.0.2.10',
        src_port=53,
        dst_port=52430,
        protocol='UDP',
    )

    assert protocol_mismatch(packet) is False


def test_https_to_standard_port_is_not_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip='192.0.2.10',
        dst_ip='203.0.113.10',
        src_port=41006,
        dst_port=443,
        protocol='TCP',
    )

    assert protocol_mismatch(packet) is False


def test_quic_to_udp_443_is_not_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip='192.0.2.10',
        dst_ip='203.0.113.10',
        src_port=54321,
        dst_port=443,
        protocol='UDP',
    )

    assert protocol_mismatch(packet) is False


def test_non_standard_tcp_service_port_is_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip='192.0.2.10',
        dst_ip='203.0.113.10',
        src_port=54321,
        dst_port=45678,
        protocol='TCP',
    )

    assert protocol_mismatch(packet) is True


def test_non_standard_udp_service_port_is_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip='192.0.2.10',
        dst_ip='203.0.113.10',
        src_port=54321,
        dst_port=45678,
        protocol='UDP',
    )

    assert protocol_mismatch(packet) is True


def test_windows_discovery_signatures_are_not_mismatches():
    assert protocol_mismatch(packet("10.85.142.46", "10.85.142.179", "TCP", 18716, 2869)) is False
    assert protocol_mismatch(packet("10.85.142.46", "10.85.142.179", "TCP", 18717, 5357)) is False
    assert protocol_mismatch(packet("10.85.142.46", "239.255.255.250", "UDP", 53000, 3702)) is False


def test_known_discovery_signature_does_not_create_engine_alert():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)

    alerts = []
    for index in range(5):
        alerts.extend(engine.process(packet("10.85.142.46", "10.85.142.179", "TCP", 18716 + index, 2869, now)))
        alerts.extend(engine.process(packet("10.85.142.46", "10.85.142.179", "TCP", 19000 + index, 5357, now)))
        alerts.extend(engine.process(packet("10.85.142.46", "239.255.255.250", "UDP", 20000 + index, 3702, now)))

    assert alerts == []


def test_repeated_mismatch_with_changing_source_ports_is_deduplicated():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)

    alerts = []
    for index in range(10):
        alerts.extend(engine.process(packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "PW-MISMATCH-001"


def test_different_mismatch_conditions_remain_distinct():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)

    for index in range(5):
        engine.process(packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now))
    alerts = engine.process(packet("192.0.2.10", "198.51.100.10", "UDP", 50000, 45679, now))

    assert len(alerts) == 1
    assert alerts[0].protocol == "UDP"
    assert alerts[0].destination_port == 45679


def test_different_sources_and_destinations_remain_distinct():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)

    for index in range(5):
        engine.process(packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now))
    for index in range(5):
        engine.process(packet("192.0.2.11", "198.51.100.10", "TCP", 41000 + index, 45678, now))
    alerts = []
    for index in range(5):
        alerts.extend(engine.process(packet("192.0.2.10", "198.51.100.11", "TCP", 42000 + index, 45678, now)))

    assert len(engine._last_alert_at) == 3
    assert len(alerts) == 1


def test_service_response_remains_excluded_from_mismatch():
    assert protocol_mismatch(packet("192.0.2.1", "192.0.2.10", "TCP", 5357, 41006)) is False


def test_threshold_and_reporting_compatibility(tmp_path):
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)
    alerts = []
    for index in range(5):
        alerts.extend(engine.process(packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)))

    assert len(alerts) == 1
    timeline = AlertTimeline()
    timeline.add(alerts[0])
    csv_path = write_csv(tmp_path / "mismatch.csv", alerts, timeline.events())
    pdf_path = write_pdf(tmp_path / "mismatch.pdf", alerts, now, now, timeline.events())
    assert csv_path.exists() and pdf_path.exists()


def test_whitelist_suppression_remains_intact():
    engine = mismatch_engine(whitelist={"192.0.2.10"})
    now = datetime.now(timezone.utc)
    alerts = []
    for index in range(5):
        alerts.extend(engine.process(packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)))

    assert alerts == []
    assert len(engine.suppressed_alerts) == 1


def test_detector_is_registered_and_uses_configured_window_and_thresholds():
    settings = load_settings("config/config.json")
    detector = next(
        detector
        for detector in build_detectors(settings)
        if isinstance(detector, ProtocolMismatchDetector)
    )

    assert detector.rule_id == "PW-MISMATCH-001"
    assert detector.cfg == {"min_packets": 5, "ratio": 0.7, "high_ratio": 0.9}
    assert settings.rolling_window_seconds == 60


def test_normal_tcp_and_udp_service_traffic_does_not_mismatch():
    now = datetime.now(timezone.utc)
    tracker = RollingStateTracker(60)
    detector = ProtocolMismatchDetector(
        load_settings("config/config.json").thresholds["protocol_mismatch"]
    )

    for index in range(6):
        tcp = packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 443, now)
        udp = packet("192.0.2.10", "198.51.100.10", "UDP", 41000 + index, 53, now)
        state = tracker.observe(tcp)
        state = tracker.observe(udp)

    assert state.protocol_observations == 12
    assert state.protocol_mismatch_count == 0
    assert detector.detect(udp, state) is None


def test_fewer_than_minimum_mismatch_observations_do_not_trigger():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)

    alerts = []
    for index in range(4):
        alerts.extend(
            engine.process(
                packet(
                    "192.0.2.10",
                    "198.51.100.10",
                    "TCP",
                    40000 + index,
                    45678,
                    now,
                )
            )
        )

    assert alerts == []
    state = engine.state_tracker.snapshot("192.0.2.10")
    assert state.protocol_observations == 4
    assert state.protocol_mismatch_count == 4


def test_exact_minimum_mismatch_observations_trigger_at_threshold():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)
    alerts = []

    for index in range(5):
        alerts.extend(
            engine.process(
                packet(
                    "192.0.2.10",
                    "198.51.100.10",
                    "TCP",
                    40000 + index,
                    45678,
                    now,
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].rule_id == "PW-MISMATCH-001"
    assert alerts[0].observed["observations"] == 5
    assert alerts[0].observed["mismatch_packets"] == 5
    assert alerts[0].observed["mismatch_ratio"] == 1.0


def test_enough_observations_below_ratio_do_not_trigger():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(settings.rolling_window_seconds)
    now = datetime.now(timezone.utc)

    for index in range(6):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
        )
    for index in range(4):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 41000 + index, 443, now)
        )

    assert state.protocol_observations == 10
    assert state.protocol_mismatch_count == 6
    assert state.protocol_mismatch_count / state.protocol_observations == 0.6
    current_mismatch = packet(
        "192.0.2.10", "198.51.100.10", "TCP", 42000, 45678, now
    )
    assert detector.detect(current_mismatch, state) is None


def test_above_ratio_triggers_and_severity_tracks_high_ratio_boundary():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(settings.rolling_window_seconds)
    now = datetime.now(timezone.utc)

    for index in range(8):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
        )
    for index in range(2):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 41000 + index, 443, now)
        )

    current = packet("192.0.2.10", "198.51.100.10", "TCP", 42000, 45678, now)
    result = detector.detect(current, state)

    assert result is not None
    assert result.observed["mismatch_ratio"] == 0.8
    assert SeverityScorer().assign(result).severity is Severity.MEDIUM

    high_tracker = RollingStateTracker(settings.rolling_window_seconds)
    for index in range(9):
        high_state = high_tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 43000 + index, 45678, now)
        )
    high_state = high_tracker.observe(
        packet("192.0.2.10", "198.51.100.10", "TCP", 44000, 443, now)
    )
    high_result = detector.detect(current, high_state)
    assert high_result is not None
    assert high_result.observed["mismatch_ratio"] == 0.9
    assert SeverityScorer().assign(high_result).severity is Severity.HIGH


def test_ratio_equal_to_configured_threshold_triggers():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(settings.rolling_window_seconds)
    now = datetime.now(timezone.utc)

    for index in range(7):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
        )
    for index in range(3):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 41000 + index, 443, now)
        )

    assert state.protocol_mismatch_count / state.protocol_observations == 0.7
    result = detector.detect(
        packet("192.0.2.10", "198.51.100.10", "TCP", 42000, 45678, now),
        state,
    )
    assert result is not None
    assert result.observed["mismatch_ratio"] == 0.7


def test_tcp_and_udp_mismatch_classification_from_scapy_packets():
    now = datetime.now(timezone.utc)
    tcp = parsed_scapy_packet(
        "192.0.2.10", "198.51.100.10", "TCP", 50000, 45678, now
    )
    udp = parsed_scapy_packet(
        "192.0.2.10", "198.51.100.10", "UDP", 50001, 45678, now
    )
    assert tcp.protocol == "TCP"
    assert udp.protocol == "UDP"
    assert protocol_mismatch(tcp) is True
    assert protocol_mismatch(udp) is True


def test_every_configured_common_service_port_is_excluded():
    for port in COMMON_TCP_PORTS:
        assert protocol_mismatch(
            packet("192.0.2.10", "198.51.100.10", "TCP", 50000, port)
        ) is False
    for port in COMMON_UDP_PORTS:
        assert protocol_mismatch(
            packet("192.0.2.10", "198.51.100.10", "UDP", 50000, port)
        ) is False


def test_likely_response_ephemeral_boundary_is_exact():
    assert protocol_mismatch(
        packet("192.0.2.1", "192.0.2.10", "TCP", 443, 1024)
    ) is False
    assert protocol_mismatch(
        packet("192.0.2.1", "192.0.2.10", "TCP", 443, 1023)
    ) is True


def test_likely_response_observations_are_tracked_under_their_source_ip():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(settings.rolling_window_seconds)
    now = datetime.now(timezone.utc)

    for index in range(3):
        state = tracker.observe(
            packet(
                "192.0.2.10",
                "198.51.100.10",
                "TCP",
                40000 + index,
                45678,
                now,
            )
        )
    for index in range(2):
        response_state = tracker.observe(
            packet(
                "198.51.100.10",
                "192.0.2.10",
                "TCP",
                443,
                50000 + index,
                now,
            )
        )

    source_state = tracker.snapshot("192.0.2.10")
    assert source_state.protocol_observations == 3
    assert source_state.protocol_mismatch_count == 3
    assert response_state.protocol_observations == 2
    assert response_state.protocol_mismatch_count == 0
    current_mismatch = packet(
        "192.0.2.10", "198.51.100.10", "TCP", 42000, 45678, now
    )
    assert detector.detect(current_mismatch, source_state) is None


def test_response_filter_uses_common_port_union_without_transport_matching():
    tcp_with_udp_service_source_port = packet(
        "192.0.2.1", "192.0.2.10", "TCP", 53, 45678
    )
    udp_with_tcp_service_source_port = packet(
        "192.0.2.1", "192.0.2.10", "UDP", 443, 45678
    )

    assert protocol_mismatch(tcp_with_udp_service_source_port) is False
    assert protocol_mismatch(udp_with_tcp_service_source_port) is False


def test_windows_discovery_response_direction_signatures_are_excluded():
    assert protocol_mismatch(
        packet("10.0.0.1", "10.0.0.5", "TCP", 2869, 50000)
    ) is False
    assert protocol_mismatch(
        packet("10.0.0.1", "10.0.0.5", "TCP", 5357, 50001)
    ) is False
    assert protocol_mismatch(
        packet("10.0.0.1", "10.0.0.5", "UDP", 3702, 50002)
    ) is False


def test_unknown_protocol_and_packets_without_destination_port_are_not_mismatches():
    unknown = packet("192.0.2.10", "198.51.100.10", "OTHER", 50000, 45678)
    no_destination_port = packet("192.0.2.10", "198.51.100.10", "TCP", 50000, None)
    assert protocol_mismatch(unknown) is False
    assert protocol_mismatch(no_destination_port) is False


def test_current_packet_must_itself_be_a_mismatch():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(settings.rolling_window_seconds)
    now = datetime.now(timezone.utc)

    for index in range(5):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
        )

    current_common = packet(
        "192.0.2.10", "198.51.100.10", "TCP", 45000, 443, now
    )
    assert detector.detect(current_common, state) is None


def test_different_sources_do_not_combine_to_minimum_count():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(settings.rolling_window_seconds)
    now = datetime.now(timezone.utc)

    for index in range(3):
        tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
        )
        tracker.observe(
            packet("192.0.2.11", "198.51.100.10", "TCP", 41000 + index, 45678, now)
        )

    for source in ("192.0.2.10", "192.0.2.11"):
        state = tracker.snapshot(source)
        assert state.protocol_observations == 3
        assert detector.detect(
            packet(source, "198.51.100.10", "TCP", 42000, 45678, now),
            state,
        ) is None


def test_observations_for_multiple_destinations_aggregate_per_source():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(settings.rolling_window_seconds)
    now = datetime.now(timezone.utc)

    for index in range(3):
        state = tracker.observe(
            packet(
                "192.0.2.10",
                "198.51.100.10",
                "TCP",
                40000 + index,
                45678,
                now,
            )
        )
    for index in range(2):
        state = tracker.observe(
            packet(
                "192.0.2.10",
                "198.51.100.11",
                "UDP",
                41000 + index,
                45679,
                now,
            )
        )

    assert state.protocol_observations == 5
    assert state.protocol_mismatch_count == 5
    result = detector.detect(
        packet("192.0.2.10", "198.51.100.11", "UDP", 42000, 45679, now),
        state,
    )
    assert result is not None
    assert result.destination_ip == "198.51.100.11"


def test_protocol_observations_and_mismatches_expire_with_rolling_window():
    settings = load_settings("config/config.json")
    detector = ProtocolMismatchDetector(settings.thresholds["protocol_mismatch"])
    tracker = RollingStateTracker(window_seconds=10)
    now = datetime.now(timezone.utc)

    for index in range(5):
        state = tracker.observe(
            packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
        )
    assert detector.detect(
        packet("192.0.2.10", "198.51.100.10", "TCP", 45000, 45678, now),
        state,
    ) is not None

    later = now + timedelta(seconds=11)
    state = tracker.observe(
        packet("192.0.2.10", "198.51.100.10", "TCP", 46000, 45678, later)
    )
    assert state.protocol_observations == 1
    assert state.protocol_mismatch_count == 1
    assert detector.detect(
        packet("192.0.2.10", "198.51.100.10", "TCP", 46001, 45678, later),
        state,
    ) is None


def test_engine_alert_contains_expected_fields_and_whitelist_behavior():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)
    alerts = []
    for index in range(5):
        alerts.extend(
            engine.process(
                packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
            )
        )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "PW-MISMATCH-001"
    assert alert.source_ip == "192.0.2.10"
    assert alert.destination_ip == "198.51.100.10"
    assert alert.protocol == "TCP"
    assert alert.source_port == 40004
    assert alert.destination_port == 45678
    assert alert.severity is Severity.HIGH
    assert alert.evidence["reason"]
    assert alert.observed == {
        "mismatch_ratio": 1.0,
        "mismatch_packets": 5,
        "observations": 5,
        "destination_port": 45678,
    }
    assert alert.thresholds == load_settings("config/config.json").thresholds["protocol_mismatch"]
    assert len(alert.alert_id) == 12

    suppressed_engine = mismatch_engine(whitelist={"192.0.2.10"})
    for index in range(5):
        suppressed = suppressed_engine.process(
            packet("192.0.2.10", "198.51.100.10", "TCP", 41000 + index, 45678, now)
        )
    assert suppressed == []
    assert len(suppressed_engine.suppressed_alerts) == 1
    assert suppressed_engine.suppressed_alerts[0].whitelisted is True


def test_engine_dedup_separates_destination_ports_but_suppresses_same_condition():
    engine = mismatch_engine()
    now = datetime.now(timezone.utc)
    for index in range(5):
        engine.process(
            packet("192.0.2.10", "198.51.100.10", "TCP", 40000 + index, 45678, now)
        )

    duplicate = engine.process(
        packet("192.0.2.10", "198.51.100.10", "TCP", 45000, 45678, now + timedelta(seconds=1))
    )
    distinct_port = engine.process(
        packet("192.0.2.10", "198.51.100.10", "TCP", 45001, 45679, now + timedelta(seconds=2))
    )

    assert duplicate == []
    assert len(distinct_port) == 1
    assert distinct_port[0].destination_port == 45679
