from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for
from .common import protocol_mismatch

class ProtocolMismatchDetector(Detector):
    rule_id = "PW-MISMATCH-001"; attack_type = "Non-Standard Port / Protocol Mismatch"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        if state.protocol_observations < self.cfg["min_packets"]: return None
        ratio = state.protocol_mismatch_count / max(state.protocol_observations, 1)
        if ratio < self.cfg["ratio"] or not protocol_mismatch(packet): return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, packet.protocol,
            {"reason": "Observed transport protocol and destination port relationship is outside configured common-service signatures."},
            {"mismatch_ratio": round(ratio, 3), "mismatch_packets": state.protocol_mismatch_count, "observations": state.protocol_observations, "destination_port": packet.dst_port},
            self.cfg, mitre_for("protocol_mismatch"), confidence_note="Non-standard port usage can be legitimate; this rule identifies a signature mismatch, not maliciousness by itself.")
