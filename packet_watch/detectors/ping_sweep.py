from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for

class PingSweepDetector(Detector):
    rule_id = "PW-PING-001"; attack_type = "Ping Sweep"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        if packet.protocol != "ICMP" or packet.icmp_type not in {8, 0}: return None
        n = len(state.destination_ips)
        if n < self.cfg["distinct_destinations"]: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, "ICMP",
            {"reason": "One source contacted many distinct destination IPs using ICMP."}, {"distinct_destinations": n}, self.cfg, mitre_for("ping_sweep"))
