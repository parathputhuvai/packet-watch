from datetime import datetime, timedelta, timezone

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from packet_watch.models import ParsedPacket
from packet_watch.parser import PacketParser
from packet_watch.state import RollingStateTracker


def pkt(ts, src="10.0.0.5", dst="10.0.0.1", dport=80):
    return ParsedPacket(timestamp=ts, src_ip=src, dst_ip=dst, src_port=44444, dst_port=dport, protocol="TCP", tcp_flags="S")


def dns_pkt(ts, protocol="UDP", query="query.example"):
    return ParsedPacket(
        timestamp=ts,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
        src_port=53000,
        dst_port=53,
        protocol=protocol,
        dns_query=query,
    )


def test_state_is_per_source_and_rolling():
    base = datetime.now(timezone.utc)
    state = RollingStateTracker(60)
    for i in range(3): state.observe(pkt(base + timedelta(seconds=i)))
    for i in range(2): state.observe(pkt(base + timedelta(seconds=i), src="10.0.0.6", dport=443))
    assert len(state.snapshot("10.0.0.5").observations) == 3
    assert len(state.snapshot("10.0.0.6").observations) == 2


def test_expiration_removes_old_observations():
    base = datetime.now(timezone.utc)
    state = RollingStateTracker(10)
    state.observe(pkt(base))
    state.observe(pkt(base + timedelta(seconds=11)))
    assert len(state.snapshot("10.0.0.5").observations) == 1


def test_service_responses_do_not_feed_port_scan_destination_ports():
    base = datetime.now(timezone.utc)
    state = RollingStateTracker(60)
    for i in range(25):
        state.observe(ParsedPacket(
            timestamp=base + timedelta(seconds=i),
            src_ip='192.168.100.1',
            dst_ip='192.168.100.5',
            src_port=53,
            dst_port=50000 + i,
            protocol='UDP',
        ))
    snap = state.snapshot('192.168.100.1')
    assert snap is not None
    assert len(snap.scan_destination_ports) == 0
    assert len(snap.destination_ports) == 25


def test_udp_dns_query_enters_dns_state():
    state = RollingStateTracker(60)
    now = datetime.now(timezone.utc)

    state.observe(dns_pkt(now, "UDP"))

    assert list(state.snapshot("10.0.0.5").dns_queries) == ["query.example"]


def test_tcp_dns_query_does_not_enter_dns_state():
    state = RollingStateTracker(60)
    now = datetime.now(timezone.utc)

    state.observe(dns_pkt(now, "TCP"))

    assert list(state.snapshot("10.0.0.5").dns_queries) == []


def test_tcp_dns_query_does_not_increase_udp_dns_count():
    state = RollingStateTracker(60)
    now = datetime.now(timezone.utc)

    state.observe(dns_pkt(now, "TCP", "tcp.example"))
    state.observe(dns_pkt(now + timedelta(seconds=1), "UDP", "udp-one.example"))
    state.observe(dns_pkt(now + timedelta(seconds=2), "UDP", "udp-two.example"))

    assert list(state.snapshot("10.0.0.5").dns_queries) == ["udp-one.example", "udp-two.example"]


def test_dns_responses_do_not_enter_dns_state():
    parser = PacketParser()
    response = IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=53000) / DNS(
        id=1,
        qr=1,
        qd=DNSQR(qname="response.example"),
    )
    parsed = parser.parse(response)
    assert parsed is not None
    assert parsed.dns_query is None

    state = RollingStateTracker(60)
    state.observe(parsed)

    assert list(state.snapshot("10.0.0.1").dns_queries) == []
