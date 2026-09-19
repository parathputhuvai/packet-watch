from datetime import datetime, timezone

from packet_watch.models import ParsedPacket
from packet_watch.detectors.common import protocol_mismatch


def test_remote_https_response_to_private_ephemeral_port_is_not_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="142.251.12.119",
        dst_ip="192.168.100.5",
        src_port=443,
        dst_port=65112,
        protocol="UDP",
    )

    assert protocol_mismatch(packet) is False


def test_outbound_https_to_standard_port_is_not_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.100.5",
        dst_ip="142.251.12.119",
        src_port=65112,
        dst_port=443,
        protocol="TCP",
    )

    assert protocol_mismatch(packet) is False


def test_non_standard_outbound_service_port_is_mismatch():
    packet = ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.100.5",
        dst_ip="142.251.12.119",
        src_port=65112,
        dst_port=45678,
        protocol="TCP",
    )

    assert protocol_mismatch(packet) is True
