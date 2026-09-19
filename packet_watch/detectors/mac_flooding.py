from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for

class MACFloodingDetector(Detector):
    rule_id = "PW-MAC-001"; attack_type = "MAC Flooding"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        n = len(state.source_macs)
        if n < self.cfg["distinct_source_macs"]: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, packet.protocol,
            {"reason": "A source presented an unusually large number of distinct source MAC observations within the rolling window."},
            {"distinct_source_macs": n}, self.cfg, mitre_for("mac_flooding"),
            confidence_note="On a switched network, endpoint capture may not expose the switch CAM-table state; this is an on-wire indicator only.")
