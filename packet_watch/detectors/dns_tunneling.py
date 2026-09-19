from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for
from .common import shannon_entropy, max_label_length

class DNSTunnelingDetector(Detector):
    rule_id = "PW-DNS-001"; attack_type = "DNS Tunneling"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        if packet.protocol != "UDP" or not packet.dns_query: return None
        queries = list(state.dns_queries)
        n = len(queries)
        if n < self.cfg["queries"]: return None
        entropies = [shannon_entropy(q.replace(".", "")) for q in queries]
        lengths = [max_label_length(q) for q in queries]
        max_entropy = max(entropies, default=0.0); max_len = max(lengths, default=0)
        signal = max_entropy >= self.cfg["entropy"] and max_len >= self.cfg["label_length"]
        volume_signal = n >= self.cfg.get("high_queries", n + 1)
        if not signal and not volume_signal: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, "UDP",
            {"reason": "DNS query volume/label characteristics crossed explicit tunneling heuristics."},
            {"queries": n, "max_entropy": round(max_entropy, 3), "max_label_length": max_len},
            self.cfg, mitre_for("dns_tunneling"), confidence_note="DNS characteristics are consistent with tunneling but can also occur in legitimate high-entropy hostnames.")
