from datetime import datetime, timedelta, timezone

import pytest
from scapy.layers.l2 import ARP, Ether

from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import ARPSpoofingDetector, build_detectors
from packet_watch.models import ParsedPacket, Severity
from packet_watch.parser import PacketParser
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


def settings():
    return load_settings("config/config.json")


def raw_arp(timestamp, sender_ip, sender_mac, target_ip="192.0.2.1"):
    packet = (
        Ether(src=sender_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc=sender_mac,
            psrc=sender_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst=target_ip,
        )
    )
    packet.time = timestamp.timestamp()
    return packet


def engine_with_arp(whitelist_ips=None):
    configured = settings()
    detectors = build_detectors(configured)
    detector = next(item for item in detectors if isinstance(item, ARPSpoofingDetector))
    engine = DetectionEngine(
        detectors,
        RollingStateTracker(configured.rolling_window_seconds),
        SeverityScorer(),
        WhitelistFilter(whitelist_ips or configured.whitelist_ips, configured.whitelist_ports),
    )
    return engine, detector


def parse(raw_packet):
    parsed = PacketParser().parse(raw_packet)
    assert parsed is not None
    return parsed


def test_arp_detector_is_registered_and_stable_mapping_does_not_alert():
    engine, detector = engine_with_arp()
    assert detector.rule_id == "PW-ARP-001"

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alerts = []
    for offset in range(4):
        alerts.extend(
            engine.process(
                parse(
                    raw_arp(
                        now + timedelta(seconds=offset),
                        "192.0.2.50",
                        "02:00:00:00:00:50",
                    )
                )
            )
        )

    assert alerts == []
    assert engine.state_tracker.snapshot("192.0.2.50").arp_mapping_changes == 0


def test_changed_mapping_is_detected_and_engine_alert_fields_are_populated():
    engine, detector = engine_with_arp()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = parse(raw_arp(now, "192.0.2.50", "02:00:00:00:00:50"))
    changed = parse(
        raw_arp(
            now + timedelta(seconds=1),
            "192.0.2.50",
            "02:00:00:00:00:51",
        )
    )

    assert engine.process(first) == []
    tracker = RollingStateTracker(60)
    tracker.observe(first)
    changed_state = tracker.observe(changed)
    result = detector.detect(changed, changed_state)

    assert result is not None
    assert result.rule_id == "PW-ARP-001"
    assert result.observed == {"mapping_changes": 1, "current_mapping_count": 1}

    alerts = engine.process(changed)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "PW-ARP-001"
    assert alert.attack_type == "ARP Spoofing"
    assert alert.source_ip == "192.0.2.50"
    assert alert.destination_ip == "192.0.2.1"
    assert alert.protocol == "ARP"
    assert alert.timestamp == changed.timestamp
    assert alert.source_port is None
    assert alert.destination_port is None
    assert alert.severity is Severity.HIGH
    assert alert.evidence["reason"]
    assert alert.observed["mapping_changes"] == 1
    assert alert.thresholds == settings().thresholds["arp_spoofing"]
    assert len(alert.alert_id) == 12


def test_whitelisted_arp_change_is_suppressed_but_retained():
    engine, _ = engine_with_arp({"192.0.2.50"})
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    assert engine.process(
        parse(raw_arp(now, "192.0.2.50", "02:00:00:00:00:50"))
    ) == []
    alerts = engine.process(
        parse(
            raw_arp(
                now + timedelta(seconds=1),
                "192.0.2.50",
                "02:00:00:00:00:51",
            )
        )
    )

    assert alerts == []
    assert len(engine.suppressed_alerts) == 1
    suppressed = engine.suppressed_alerts[0]
    assert suppressed.rule_id == "PW-ARP-001"
    assert suppressed.whitelisted is True
    assert suppressed.suppressed_reason == "source/destination IP is whitelisted"


def test_different_sender_ips_do_not_create_mapping_changes():
    engine, _ = engine_with_arp()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = []
    for offset, (sender_ip, sender_mac) in enumerate(
        (
            ("192.0.2.50", "02:00:00:00:00:50"),
            ("192.0.2.51", "02:00:00:00:00:51"),
            ("192.0.2.52", "02:00:00:00:00:52"),
        )
    ):
        alerts.extend(
            engine.process(
                parse(
                    raw_arp(
                        now + timedelta(seconds=offset),
                        sender_ip,
                        sender_mac,
                    )
                )
            )
        )

    assert alerts == []
    assert all(
        engine.state_tracker.snapshot(sender_ip).arp_mapping_changes == 0
        for sender_ip in ("192.0.2.50", "192.0.2.51", "192.0.2.52")
    )


def test_repeated_mapping_changes_are_deduplicated_for_sixty_seconds():
    engine, _ = engine_with_arp()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = []
    for offset, sender_mac in enumerate(
        (
            "02:00:00:00:00:50",
            "02:00:00:00:00:51",
            "02:00:00:00:00:50",
            "02:00:00:00:00:52",
        )
    ):
        alerts.extend(
            engine.process(
                parse(
                    raw_arp(
                        now + timedelta(seconds=offset),
                        "192.0.2.50",
                        sender_mac,
                    )
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].rule_id == "PW-ARP-001"
    assert len(engine._last_alert_at) == 1

    later_change = engine.process(
        parse(
            raw_arp(
                now + timedelta(seconds=62),
                "192.0.2.50",
                "02:00:00:00:00:53",
            )
        )
    )
    assert len(later_change) == 1


def test_missing_arp_sender_fields_do_not_crash_or_alert():
    engine, detector = engine_with_arp()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    raw_incomplete = ARP(op=1, psrc="", hwsrc="", pdst="192.0.2.1")
    raw_incomplete.time = now.timestamp()
    parsed_incomplete = parse(raw_incomplete)
    assert parsed_incomplete.arp_psrc is None
    assert parsed_incomplete.arp_hwsrc is None
    assert engine.process(parsed_incomplete) == []

    incomplete = ParsedPacket(
        timestamp=now,
        protocol="ARP",
        src_ip="192.0.2.50",
        dst_ip="192.0.2.1",
        arp_psrc=None,
        arp_hwsrc=None,
    )

    state = engine.state_tracker.observe(incomplete)
    assert state is not None
    assert detector.detect(incomplete, state) is None
    assert engine.process(incomplete) == []

    no_source = ParsedPacket(timestamp=now, protocol="ARP")
    assert engine.process(no_source) == []


@pytest.mark.parametrize(
    ("sender_ips", "sender_macs"),
    [
        (("not-an-ip", "not-an-ip"), ("02:00:00:00:00:50", "02:00:00:00:00:51")),
        (("192.0.2.50", "192.0.2.50"), ("not-a-mac", "also-not-a-mac")),
    ],
    ids=("invalid-sender-ip", "invalid-sender-mac"),
)
def test_invalid_nonempty_arp_sender_values_do_not_alert(sender_ips, sender_macs):
    engine, detector = engine_with_arp()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = []
    sources = set()
    for offset, (sender_ip, sender_mac) in enumerate(zip(sender_ips, sender_macs)):
        raw_packet = ARP(
            op=2,
            psrc=sender_ip,
            hwsrc=sender_mac,
            pdst="192.0.2.1",
        )
        raw_packet.time = (now + timedelta(seconds=offset)).timestamp()
        packet = parse(raw_packet)
        assert packet.arp_psrc is not None
        assert packet.arp_hwsrc is not None
        sources.add(packet.src_ip)
        state = engine.state_tracker.observe(packet)
        assert state is not None
        assert detector.detect(packet, state) is None
        alerts.extend(engine.process(packet))

    assert alerts == []
    assert all(
        engine.state_tracker.snapshot(source).arp_mapping_changes == 0
        for source in sources
    )


def test_valid_sender_ip_and_mac_are_accepted():
    packet = parse(
        raw_arp(
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            "192.0.2.50",
            "02:00:00:00:00:50",
        )
    )

    assert packet.arp_psrc == "192.0.2.50"
    assert packet.arp_hwsrc == "02:00:00:00:00:50"


def test_mapping_changes_expire_and_a_new_change_is_detected():
    detector = ARPSpoofingDetector(settings().thresholds["arp_spoofing"])
    tracker = RollingStateTracker(window_seconds=10)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    first = parse(raw_arp(now, "192.0.2.50", "02:00:00:00:00:50"))
    changed = parse(
        raw_arp(
            now + timedelta(seconds=1),
            "192.0.2.50",
            "02:00:00:00:00:51",
        )
    )
    tracker.observe(first)
    changed_state = tracker.observe(changed)
    assert detector.detect(changed, changed_state) is not None

    stable_after_expiration = parse(
        raw_arp(
            now + timedelta(seconds=12),
            "192.0.2.50",
            "02:00:00:00:00:51",
        )
    )
    expired_state = tracker.observe(stable_after_expiration)
    assert expired_state.arp_mapping_changes == 0
    assert detector.detect(stable_after_expiration, expired_state) is None

    new_change = parse(
        raw_arp(
            now + timedelta(seconds=13),
            "192.0.2.50",
            "02:00:00:00:00:52",
        )
    )
    new_state = tracker.observe(new_change)
    assert new_state.arp_mapping_changes == 1
    assert detector.detect(new_change, new_state) is not None
