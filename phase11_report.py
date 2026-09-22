from pathlib import Path
from datetime import datetime, timezone

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR

from packet_watch.config import load_settings
from packet_watch.parser import PacketParser
from packet_watch.detection.engine import DetectionEngine
from packet_watch.detectors import build_detectors
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter
from packet_watch.reporting import write_csv, write_pdf


settings = load_settings("config/config.json")
parser = PacketParser()
state = RollingStateTracker(settings.rolling_window_seconds)

engine = DetectionEngine(
    build_detectors(settings),
    state,
    SeverityScorer(),
    WhitelistFilter(
        settings.whitelist_ips,
        settings.whitelist_ports,
    ),
)

alerts = []


# 1. Port Scan
for i in range(20):
    pkt = (
        IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=40000 + i, dport=10000 + i, flags="S")
    )
    alerts.extend(engine.process(parser.parse(pkt)))


# 2. SYN Flood
for i in range(100):
    pkt = (
        IP(src="198.51.100.10", dst="198.51.100.20")
        / TCP(sport=41000 + i, dport=22, flags="S")
    )
    alerts.extend(engine.process(parser.parse(pkt)))


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

    alerts.extend(engine.process(parser.parse(pkt)))


# 4. Brute Force
for i in range(10):
    pkt = (
        IP(src="198.51.100.30", dst="198.51.100.40")
        / TCP(sport=42000 + i, dport=22, flags="S")
    )
    alerts.extend(engine.process(parser.parse(pkt)))


# 5. ICMP Flood
for _ in range(100):
    pkt = (
        IP(src="203.0.113.30", dst="203.0.113.40")
        / ICMP()
    )
    alerts.extend(engine.process(parser.parse(pkt)))


# Keep only the five Review-2 detector alerts.
review_rules = {
    "PW-PORT-001",
    "PW-SYN-001",
    "PW-DNS-001",
    "PW-BRUTE-001",
    "PW-ICMP-001",
}

review_alerts = [
    alert for alert in alerts
    if alert.rule_id in review_rules
]

timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
output_dir = Path("reports")
output_dir.mkdir(exist_ok=True)

csv_path = output_dir / f"review2_{timestamp}.csv"
pdf_path = output_dir / f"review2_{timestamp}.pdf"
report_started_at = min((alert.timestamp for alert in review_alerts), default=datetime.now(timezone.utc))
report_ended_at = max((alert.timestamp for alert in review_alerts), default=report_started_at)

write_csv(csv_path, review_alerts)
write_pdf(pdf_path, review_alerts, report_started_at, report_ended_at)

print()
print("PHASE 11 REPORT")
print("================")
print("Review-2 alerts:", len(review_alerts))

for alert in review_alerts:
    print(
        alert.rule_id,
        "|",
        alert.attack_type,
        "|",
        alert.severity,
    )

print()
print("CSV:", csv_path.resolve())
print("PDF:", pdf_path.resolve())