from datetime import datetime, timezone

from packet_watch.detectors.common import protocol_mismatch
from packet_watch.models import ParsedPacket


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
