from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for

class SynFloodDetector(Detector):
    rule_id = "PW-SYN-001"; attack_type = "SYN Flood"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        if packet.protocol != "TCP": return None
        n = state.syn_count
        if n < self.cfg["syn_packets"]: return None
        ratio = n / max(state.syn_ack_count, 1)
        if n < self.cfg["syn_packets"] and ratio < self.cfg["syn_ack_ratio"]: return None
        if ratio < self.cfg["syn_ack_ratio"] and n < self.cfg["high_syn_packets"]: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, "TCP",
            {"reason": "Excessive SYN activity and/or elevated SYN-to-SYN/ACK relationship."},
            {"syn_packets": n, "syn_ack_packets": state.syn_ack_count, "syn_ack_ratio": round(ratio, 2)},
            self.cfg, mitre_for("syn_flood"), confidence_note="Network behavior is consistent with SYN-flood activity; packet evidence does not prove endpoint impact.")
