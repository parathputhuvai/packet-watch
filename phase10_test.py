from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR
from packet_watch.config import load_settings
from packet_watch.parser import PacketParser
from packet_watch.detection.engine import DetectionEngine
from packet_watch.detectors import build_detectors
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter

s = load_settings("config/config.json")
parser = PacketParser()
state = RollingStateTracker(s.rolling_window_seconds)

engine = DetectionEngine(
    build_detectors(s),
    state,
    SeverityScorer(),
    WhitelistFilter(s.whitelist_ips, s.whitelist_ports),
)

hits = []

# 1. Port Scan
for i in range(20):
    pkt = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
        sport=40000 + i, dport=10000 + i, flags="S"
    )
    hits.extend(engine.process(parser.parse(pkt)))

# 2. SYN Flood
for i in range(100):
    pkt = IP(src="198.51.100.10", dst="198.51.100.20") / TCP(
        sport=41000 + i, dport=22, flags="S"
    )
    hits.extend(engine.process(parser.parse(pkt)))

# 3. DNS Tunneling
dns_labels = [
    "a8f31c9e72b4d6f10e5a83c7192b4d8f61e0a93c75d1f84e2b6a90c31",
    "f29a7c41e8d305b6c91f72a4e0d83c15b7a62f9e31d8c54a0e76b291",
    "9c4e71a8d2f603b5e91c47a20f8d36c71a5e90b24c68f13d7a4e82",
]

for i in range(20):
    label = dns_labels[i % len(dns_labels)]
    pkt = (
        IP(src="203.0.113.10", dst="203.0.113.20")
        / UDP(sport=53000 + i, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname=label + ".example.com"),
        )
    )
    hits.extend(engine.process(parser.parse(pkt)))

# 4. Brute Force
for i in range(100):
    pkt = IP(src="198.51.100.30", dst="198.51.100.40") / TCP(
        sport=42000 + i, dport=22, flags="S"
    )
    hits.extend(engine.process(parser.parse(pkt)))

# 5. ICMP Flood
for _ in range(100):
    pkt = IP(src="203.0.113.30", dst="203.0.113.40") / ICMP()
    hits.extend(engine.process(parser.parse(pkt)))

print("TOTAL ALERTS:", len(hits))
print()
print("DETECTIONS:")

counts = {}

for alert in hits:
    counts[alert.rule_id] = counts.get(alert.rule_id, 0) + 1

for rule, count in counts.items():
    print(rule, count)
