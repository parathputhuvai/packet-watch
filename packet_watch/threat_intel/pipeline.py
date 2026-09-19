from __future__ import annotations

from packet_watch.threat_intel.ja3 import SSLBLClient, calculate_ja3


def enrich_tls_packet(packet, sslbl: SSLBLClient) -> None:
    """Mutate only the TLS metadata container with locally computed JA3 fields."""
    if not packet.tls_client_hello:
        return
    info = packet.tls_client_hello
    if info.get("ja3_fingerprint"):
        return
    # The parser stores the Scapy-derived primitives. Reconstruct the JA3 string
    # from a lightweight proxy object so downstream detectors remain Scapy-free.
    class HelloProxy:
        version = info.get("version")
        ciphers = info.get("ciphers", [])
        ext = [type("Ext", (), ext)() for ext in info.get("extensions", [])]
    try:
        ja3_string, fingerprint = calculate_ja3(HelloProxy())
        match = sslbl.lookup(fingerprint)
        info.update({"ja3_string": ja3_string, "ja3_fingerprint": fingerprint, "ja3_match": match.matched,
                     "ja3_listing_reason": match.listing_reason, "ja3_status": match.status,
                     "ja3_first_seen": match.first_seen, "ja3_last_seen": match.last_seen})
    except Exception as exc:
        info.update({"ja3_status": "error", "ja3_error": str(exc)})
