from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for

class ICMPFloodDetector(Detector):
    rule_id = "PW-ICMP-001"; attack_type = "ICMP Flood"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        if packet.protocol != "ICMP": return None
        n = state.icmp_count
        if n < self.cfg["icmp_packets"]: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, "ICMP",
            {"reason": "ICMP packet count exceeded the configured rolling-window threshold."}, {"icmp_packets": n}, self.cfg, mitre_for("icmp_flood"))
