from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from packet_watch.models import ParsedPacket


class PacketParser:
    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger("packet_watch.parser")

    def parse(self, packet: Any) -> ParsedPacket | None:
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.l2 import ARP, Ether
            from scapy.layers.dns import DNS, DNSQR
        except ImportError as exc:
            raise RuntimeError("Scapy is required for packet parsing. Install dependencies with 'pip install -r requirements.txt'.") from exc

        try:
            ts = getattr(packet, "time", None)
            timestamp = datetime.fromtimestamp(float(ts), tz=timezone.utc) if ts is not None else datetime.now(timezone.utc)
            result = ParsedPacket(timestamp=timestamp, packet_len=len(packet))
            if Ether in packet:
                result.src_mac = str(packet[Ether].src)
                result.dst_mac = str(packet[Ether].dst)
            if ARP in packet:
                arp = packet[ARP]
                result.protocol = "ARP"
                result.arp_op = int(arp.op) if arp.op is not None else None
                result.arp_psrc = str(arp.psrc) if arp.psrc else None
                result.arp_pdst = str(arp.pdst) if arp.pdst else None
                result.arp_hwsrc = str(arp.hwsrc) if arp.hwsrc else result.src_mac
                result.src_ip = result.arp_psrc
                result.dst_ip = result.arp_pdst
                return result
            if IP in packet:
                ip = packet[IP]
                result.src_ip = str(ip.src)
                result.dst_ip = str(ip.dst)
                if TCP in packet:
                    tcp = packet[TCP]
                    result.protocol = "TCP"
                    result.src_port = int(tcp.sport)
                    result.dst_port = int(tcp.dport)
                    result.tcp_flags = str(tcp.flags)
                elif UDP in packet:
                    udp = packet[UDP]
                    result.protocol = "UDP"
                    result.src_port = int(udp.sport)
                    result.dst_port = int(udp.dport)
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    result.protocol = "ICMP"
                    result.icmp_type = int(icmp.type)
                    result.icmp_code = int(icmp.code)
                else:
                    result.protocol = str(getattr(ip, "proto", "IP"))

                if DNS in packet:
                    dns = packet[DNS]
                    if int(getattr(dns, "qr", 1)) == 0 and getattr(dns, "qd", None) is not None:
                        qd = dns.qd
                        if DNSQR in qd:
                            qname = bytes(qd.qname).decode(errors="ignore").rstrip(".")
                            result.dns_query = qname
                            result.dns_qtype = int(qd.qtype)

                result.tls_client_hello = self._extract_tls_client_hello(packet)
            return result
        except Exception as exc:  # defensive parser boundary
            self.logger.warning("Malformed/unsupported packet ignored: %s", exc)
            return None

    def _extract_tls_client_hello(self, packet: Any) -> dict[str, Any] | None:
        try:
            from scapy.layers.tls.handshake import TLSClientHello
            if TLSClientHello not in packet:
                return None
            hello = packet[TLSClientHello]
            ciphers = self._list_ints(getattr(hello, "ciphers", []))
            ext_values: list[dict[str, Any]] = []
            extensions = getattr(hello, "ext", []) or []
            for ext in extensions:
                item: dict[str, Any] = {"type": int(getattr(ext, "type", -1))}
                if hasattr(ext, "groups"):
                    item["groups"] = self._list_ints(getattr(ext, "groups", []))
                if hasattr(ext, "ecpl"):
                    item["ecpl"] = self._list_ints(getattr(ext, "ecpl", []))
                if hasattr(ext, "versions"):
                    item["versions"] = self._list_ints(getattr(ext, "versions", []))
                ext_values.append(item)
            return {"version": int(hello.version), "ciphers": ciphers, "extensions": ext_values}
        except Exception as exc:
            self.logger.debug("TLS Client Hello extraction unavailable: %s", exc)
            return None

    @staticmethod
    def _list_ints(value: Any) -> list[int]:
        out: list[int] = []
        for item in value or []:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                pass
        return out
