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
    """
    Detect protocol/destination-port mismatches for traffic where the
    destination port represents the service being contacted.

    Important:
    A normal response from a remote server commonly looks like:

        remote_server:443 -> local_host:ephemeral_port

    The local ephemeral port is not a service port and must not be
    interpreted as a protocol mismatch.
    """
    if packet.dst_port is None:
        return False

    if packet.protocol not in {"TCP", "UDP"}:
        return False

    # Do not treat normal Internet responses to a local/private host's
    # ephemeral port as a mismatch.
    #
    # Example:
    #   142.251.x.x:443 -> 192.168.100.5:65112
    #
    # The destination port 65112 is the client's temporary port, not
    # an indication that HTTPS is using a non-standard service port.
    if packet.src_ip and packet.dst_ip:
        try:
            import ipaddress

            src = ipaddress.ip_address(packet.src_ip)
            dst = ipaddress.ip_address(packet.dst_ip)

            src_is_private = (
                src.is_private
                or src.is_loopback
                or src.is_link_local
            )
            dst_is_private = (
                dst.is_private
                or dst.is_loopback
                or dst.is_link_local
            )

            if not src_is_private and dst_is_private:
                return False

        except ValueError:
            # If an address cannot be parsed, continue with the
            # normal port-signature check.
            pass

    expected = {
        "TCP": {
            20, 21, 22, 23, 25, 53, 80, 110, 143,
            443, 445, 587, 993, 995, 3389, 5985, 5986
        },
        "UDP": {
            53, 67, 68, 69, 123, 137, 138, 161,
            162, 500, 514, 1900, 4500
        },
    }

    return packet.dst_port not in expected[packet.protocol]
