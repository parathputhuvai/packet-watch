from __future__ import annotations

import math


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def max_label_length(qname: str) -> int:
    return max((len(label) for label in qname.split('.') if label), default=0)


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


# Common service ports used as destination ports for client requests and
# source ports for server responses. This list is a signature set, not a
# complete registry of every service on a network.
COMMON_TCP_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143,
    443, 445, 587, 993, 995, 3389, 5900, 5985,
    5986, 8080, 8443
}

COMMON_UDP_PORTS = {
    53, 67, 68, 69, 123, 137, 138, 161,
    162, 443, 500, 514, 1900, 4500, 5353, 5355
}

COMMON_SERVICE_PORTS = COMMON_TCP_PORTS | COMMON_UDP_PORTS


def is_likely_service_response(packet) -> bool:
    """Return True for a packet shaped like a service response.

    Examples:
        DNS: 53 -> client ephemeral port
        HTTPS: 443 -> client ephemeral port
        Router service: 1900 -> client ephemeral port

    The detector must not assume a single fixed ephemeral-port range because
    real captures can contain dynamically allocated/client-side ports outside
    one particular operating-system default range (for example, VPN/NAT or
    other networking components can change the observed port values).
    """
    return (
        packet.src_port is not None
        and packet.dst_port is not None
        and packet.src_port in COMMON_SERVICE_PORTS
        and packet.dst_port not in COMMON_SERVICE_PORTS
        and packet.dst_port >= 1024
    )


def protocol_mismatch(packet) -> bool:
    """Detect likely non-standard destination-port usage.

    Only request-like traffic is evaluated. A packet whose source port is a
    known service port and whose destination is a client-side dynamic port is
    treated as a likely response rather than a mismatch.
    """
    if packet.dst_port is None:
        return False

    expected = {
        'TCP': COMMON_TCP_PORTS,
        'UDP': COMMON_UDP_PORTS,
    }

    if packet.protocol not in expected:
        return False

    if is_likely_service_response(packet):
        return False

    return packet.dst_port not in expected[packet.protocol]
