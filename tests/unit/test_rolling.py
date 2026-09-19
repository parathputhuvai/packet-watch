from datetime import datetime, timedelta, timezone

from packet_watch.models import ParsedPacket
from packet_watch.state import RollingStateTracker


def pkt(ts, src="10.0.0.5", dst="10.0.0.1", dport=80):
    return ParsedPacket(timestamp=ts, src_ip=src, dst_ip=dst, src_port=44444, dst_port=dport, protocol="TCP", tcp_flags="S")


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
