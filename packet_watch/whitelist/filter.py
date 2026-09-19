from __future__ import annotations

from packet_watch.models import DetectionResult


class WhitelistFilter:
    def __init__(self, ips: set[str] | None = None, ports: set[int] | None = None):
        self.ips = set(ips or ())
        self.ports = set(ports or ())

    def should_suppress(self, result: DetectionResult, destination_port: int | None = None) -> tuple[bool, str | None]:
        if result.source_ip in self.ips or result.destination_ip in self.ips:
            return True, "source/destination IP is whitelisted"
        if destination_port in self.ports:
            return True, "destination port is whitelisted"
        return False, None
