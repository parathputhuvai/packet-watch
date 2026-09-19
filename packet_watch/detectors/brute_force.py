from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for
from .common import looks_auth_service

class BruteForceDetector(Detector):
    rule_id = "PW-BRUTE-001"; attack_type = "Brute-Force Attempts"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        if packet.protocol not in {"TCP", "UDP"} or not looks_auth_service(packet.dst_port): return None
        n = state.tcp_connection_attempts
        if n < self.cfg["connection_attempts"]: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, packet.protocol,
            {"reason": "Repeated connection attempts to an authentication/service port from one source."},
            {"connection_attempts": n, "target_port": packet.dst_port}, self.cfg, mitre_for("brute_force"),
            confidence_note="This is network evidence of repeated service attempts; successful authentication and credentials are not observable here.")
