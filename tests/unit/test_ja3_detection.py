from datetime import datetime, timedelta, timezone

from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.layers.tls.handshake import TLSClientHello as TLSClientHelloLayer

from packet_watch.cli.app import PacketWatchApp
from packet_watch.config import load_settings
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import JA3Detector, build_detectors
from packet_watch.models import JA3Result, ParsedPacket, Severity
from packet_watch.parser import PacketParser
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.threat_intel.ja3 import SSLBLClient, calculate_ja3
from packet_watch.threat_intel.pipeline import enrich_tls_packet
from packet_watch.whitelist import WhitelistFilter


KNOWN_JA3_STRING = "771,4865-4866,,,"
KNOWN_JA3_FINGERPRINT = "3d406cfeb27540a8d99cecd58f281004"
SOURCE_IP = "192.0.2.10"
DESTINATION_IP = "198.51.100.20"


def raw_client_hello(timestamp=None):
    packet = (
        IP(src=SOURCE_IP, dst=DESTINATION_IP)
        / TCP(sport=50000, dport=443)
        / TLS(
            msg=[
                TLSClientHello(
                    version=771,
                    ciphers=[0x1301, 0x1302],
                    ext=[],
                )
            ]
        )
    )
    if timestamp is not None:
        packet.time = timestamp.timestamp()
    return packet


def parse(raw_packet):
    parsed = PacketParser().parse(raw_packet)
    assert parsed is not None
    return parsed


def sslbl_with_entries(entries):
    client = SSLBLClient(feed_url="https://unused.invalid/feed.csv", enabled=False)
    client._entries = entries
    return client


def matched_entry():
    return {
        KNOWN_JA3_FINGERPRINT: {
            "first_seen": "2026-01-01",
            "last_seen": "2026-01-02",
            "listing_reason": "test threat entry",
        }
    }


def test_valid_client_hello_is_parsed_and_matches_seeded_threat_data():
    packet = parse(raw_client_hello())
    assert packet.tls_client_hello == {
        "version": 771,
        "ciphers": [4865, 4866],
        "extensions": [],
    }

    tls_info = packet.tls_client_hello
    hello = type(
        "Hello",
        (),
        {
            "version": tls_info["version"],
            "ciphers": tls_info["ciphers"],
            "ext": [],
        },
    )()
    assert calculate_ja3(hello) == (KNOWN_JA3_STRING, KNOWN_JA3_FINGERPRINT)

    client = sslbl_with_entries(matched_entry())
    enrich_tls_packet(packet, client)

    assert packet.tls_client_hello["ja3_fingerprint"] == KNOWN_JA3_FINGERPRINT
    assert packet.tls_client_hello["ja3_match"] is True
    assert packet.tls_client_hello["ja3_status"] == "matched"
    assert packet.tls_client_hello["ja3_listing_reason"] == "test threat entry"


def test_valid_nonmatching_fingerprint_is_not_listed_and_does_not_alert():
    packet = parse(raw_client_hello())
    client = sslbl_with_entries(
        {
            "00000000000000000000000000000000": {
                "first_seen": "2026-01-01",
                "last_seen": "2026-01-02",
                "listing_reason": "different fingerprint",
            }
        }
    )
    enrich_tls_packet(packet, client)

    assert packet.tls_client_hello["ja3_fingerprint"] == KNOWN_JA3_FINGERPRINT
    assert packet.tls_client_hello["ja3_match"] is False
    assert packet.tls_client_hello["ja3_status"] == "not_listed"

    detector = JA3Detector()
    state = RollingStateTracker().observe(packet)
    assert detector.detect(packet, state) is None


def test_packet_without_client_hello_has_no_ja3_metadata_or_alert():
    raw_packet = IP(src=SOURCE_IP, dst=DESTINATION_IP) / TCP(sport=50000, dport=443)
    packet = parse(raw_packet)
    assert packet.tls_client_hello is None

    enrich_tls_packet(packet, sslbl_with_entries(matched_entry()))

    assert packet.tls_client_hello is None
    state = RollingStateTracker().observe(packet)
    assert JA3Detector().detect(packet, state) is None


def test_malformed_client_hello_is_ignored_without_crashing_or_alerting():
    class MalformedHello:
        version = None
        ciphers = []
        ext = []

    class MalformedPacket:
        def __contains__(self, layer):
            return layer is TLSClientHelloLayer

        def __getitem__(self, layer):
            return MalformedHello()

    parser = PacketParser()
    assert parser._extract_tls_client_hello(MalformedPacket()) is None

    packet = ParsedPacket(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        src_ip=SOURCE_IP,
        dst_ip=DESTINATION_IP,
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        tls_client_hello={"version": None, "ciphers": [], "extensions": []},
    )
    enrich_tls_packet(packet, sslbl_with_entries(matched_entry()))

    assert packet.tls_client_hello["ja3_status"] == "error"
    assert "ja3_fingerprint" not in packet.tls_client_hello
    state = RollingStateTracker().observe(packet)
    assert JA3Detector().detect(packet, state) is None


def test_full_app_path_generates_high_severity_ja3_alert_and_deduplicates():
    settings = load_settings("config/config.json")
    app = PacketWatchApp(settings)
    detector = next(
        detector
        for detector in app.engine.detectors
        if isinstance(detector, JA3Detector)
    )
    assert detector.rule_id == "PW-JA3-001"

    class SeededSSLBL:
        def lookup(self, fingerprint):
            if fingerprint == KNOWN_JA3_FINGERPRINT:
                return JA3Result(
                    fingerprint=fingerprint,
                    matched=True,
                    listing_reason="test threat entry",
                    status="matched",
                )
            return JA3Result(fingerprint=fingerprint, status="not_listed")

    app.sslbl = SeededSSLBL()
    app.abuseipdb.check = lambda ip: None
    app._print_alert = lambda alert: None
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    app.process_packet(raw_client_hello(start))

    assert len(app.alerts) == 1
    alert = app.alerts[0]
    assert alert.rule_id == "PW-JA3-001"
    assert alert.attack_type == "Malicious Encrypted Traffic (TLS/JA3)"
    assert alert.severity is Severity.HIGH
    assert alert.source_ip == SOURCE_IP
    assert alert.destination_ip == DESTINATION_IP
    assert alert.source_port == 50000
    assert alert.destination_port == 443
    assert alert.protocol == "TCP"
    assert alert.evidence["ja3"] == KNOWN_JA3_FINGERPRINT
    assert alert.observed["sslbl_match"] is True
    assert alert.ja3 is not None
    assert alert.ja3.matched is True
    assert alert.ja3.fingerprint == KNOWN_JA3_FINGERPRINT

    app.process_packet(raw_client_hello(start + timedelta(seconds=1)))
    assert len(app.alerts) == 1


def test_full_engine_path_whitelist_suppresses_matched_ja3_alert():
    settings = load_settings("config/config.json")
    detectors = build_detectors(settings)
    assert any(isinstance(detector, JA3Detector) for detector in detectors)
    engine = DetectionEngine(
        detectors,
        RollingStateTracker(settings.rolling_window_seconds),
        SeverityScorer(),
        WhitelistFilter({SOURCE_IP}),
    )

    packet = parse(raw_client_hello(datetime(2026, 1, 1, tzinfo=timezone.utc)))
    enrich_tls_packet(packet, sslbl_with_entries(matched_entry()))
    alerts = engine.process(packet)

    assert alerts == []
    assert len(engine.suppressed_alerts) == 1
    suppressed = engine.suppressed_alerts[0]
    assert suppressed.rule_id == "PW-JA3-001"
    assert suppressed.whitelisted is True
    assert suppressed.suppressed_reason == "source/destination IP is whitelisted"
