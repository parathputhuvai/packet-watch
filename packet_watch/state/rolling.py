from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from packet_watch.models import ParsedPacket
from packet_watch.detectors.common import protocol_mismatch


@dataclass
class Observation:
    timestamp: datetime
    packet: ParsedPacket


@dataclass
class SourceState:
    observations: deque[Observation] = field(default_factory=deque)
    destination_ports: set[int] = field(default_factory=set)
    destination_ips: set[str] = field(default_factory=set)
    source_macs: set[str] = field(default_factory=set)
    syn_count: int = 0
    syn_ack_count: int = 0
    icmp_count: int = 0
    tcp_connection_attempts: int = 0
    dns_queries: deque[str] = field(default_factory=deque)
    arp_mapping_changes: int = 0
    arp_mappings: dict[str, str] = field(default_factory=dict)
    protocol_mismatch_count: int = 0
    protocol_observations: int = 0
    ja3_fingerprints: set[str] = field(default_factory=set)

    def reset_derived(self) -> None:
        self.destination_ports.clear()
        self.destination_ips.clear()
        self.source_macs.clear()
        self.syn_count = 0
        self.syn_ack_count = 0
        self.icmp_count = 0
        self.tcp_connection_attempts = 0
        self.dns_queries.clear()
        self.arp_mapping_changes = 0
        self.protocol_mismatch_count = 0
        self.protocol_observations = 0
        self.ja3_fingerprints.clear()


class RollingStateTracker:
    """Maintains bounded per-source observations across reporting intervals."""

    def __init__(self, window_seconds: int = 60):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window = timedelta(seconds=window_seconds)
        self.sources: dict[str, SourceState] = defaultdict(SourceState)
        self._arp_global: dict[str, str] = {}

    def observe(self, packet: ParsedPacket) -> SourceState | None:
        self.expire(packet.timestamp)
        source = packet.src_ip or packet.src_mac
        if not source:
            return None
        state = self.sources[source]
        state.observations.append(Observation(packet.timestamp, packet))
        self._refresh_state(source)
        return state

    def expire(self, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        cutoff = now - self.window
        empty: list[str] = []
        for source, state in self.sources.items():
            while state.observations and state.observations[0].timestamp < cutoff:
                state.observations.popleft()
            self._refresh_state(source)
            if not state.observations:
                empty.append(source)
        for source in empty:
            self.sources.pop(source, None)

    def snapshot(self, source: str) -> SourceState | None:
        state = self.sources.get(source)
        if state is None:
            return None
        self._refresh_state(source)
        return state

    def active_sources(self) -> Iterable[str]:
        return tuple(self.sources)

    def _refresh_state(self, source: str) -> None:
        state = self.sources[source]
        state.reset_derived()
        local_arp_changes = 0
        latest_arp: dict[str, str] = {}
        protocol_counter: Counter[str] = Counter()
        for obs in state.observations:
            p = obs.packet
            if p.dst_port is not None:
                state.destination_ports.add(p.dst_port)
            if p.dst_ip:
                state.destination_ips.add(p.dst_ip)
            if p.src_mac:
                state.source_macs.add(p.src_mac)
            if p.protocol == "TCP":
                flags = set(p.tcp_flags)
                if "S" in flags and "A" not in flags:
                    state.syn_count += 1
                    state.tcp_connection_attempts += 1
                elif "S" in flags and "A" in flags:
                    state.syn_ack_count += 1
            if p.protocol == "ICMP":
                state.icmp_count += 1
            if p.dns_query:
                state.dns_queries.append(p.dns_query)
            if p.arp_psrc and p.arp_hwsrc:
                previous = latest_arp.get(p.arp_psrc)
                if previous and previous != p.arp_hwsrc:
                    local_arp_changes += 1
                latest_arp[p.arp_psrc] = p.arp_hwsrc
            if p.protocol != "OTHER":
                protocol_counter[p.protocol] += 1
                if self._is_protocol_mismatch(p):
                    state.protocol_mismatch_count += 1
                    state.protocol_observations += 1
                elif p.dst_port is not None:
                    state.protocol_observations += 1
            if p.tls_client_hello:
                fp = p.tls_client_hello.get("ja3_fingerprint")
                if fp:
                    state.ja3_fingerprints.add(fp)
        state.arp_mappings = latest_arp
        state.arp_mapping_changes = local_arp_changes

    @staticmethod
    def _is_protocol_mismatch(p: ParsedPacket) -> bool:
        return protocol_mismatch(p)
