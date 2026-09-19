from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for

class PortScanDetector(Detector):
    rule_id = "PW-PORT-001"; attack_type = "Port Scanning"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        t = self.cfg
        n = len(state.destination_ports)
        if n < t["distinct_destination_ports"]: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, packet.protocol,
            {"reason": "Multiple distinct destination ports contacted within the rolling window."},
            {"distinct_destination_ports": n}, t, mitre_for("port_scanning"))
