from __future__ import annotations

import math
import re


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def max_label_length(qname: str) -> int:
    return max((len(label) for label in qname.split(".") if label), default=0)


def looks_auth_service(port: int | None) -> bool:
    return port in {21, 22, 23, 25, 110, 143, 445, 3389, 5900, 5985, 5986, 8080, 8443}


def is_private_or_local(ip: str | None) -> bool:
    if not ip:
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback or ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return True


def protocol_mismatch(packet) -> bool:
    if packet.dst_port is None:
        return False
    expected = {
        "TCP": {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3389, 5985, 5986},
        "UDP": {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500},
    }
    return packet.protocol in expected and packet.dst_port not in expected[packet.protocol]
