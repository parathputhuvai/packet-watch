from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for

class ARPSpoofingDetector(Detector):
    rule_id = "PW-ARP-001"; attack_type = "ARP Spoofing"
    def __init__(self, cfg): self.cfg = cfg
    def detect(self, packet, state):
        if packet.protocol != "ARP" or packet.arp_psrc is None or packet.arp_hwsrc is None: return None
        if state.arp_mapping_changes < self.cfg["mapping_change_count"]: return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, "ARP",
            {"reason": "An IP address was observed with more than one source MAC within the rolling window."},
            {"mapping_changes": state.arp_mapping_changes, "current_mapping_count": len(state.arp_mappings)},
            self.cfg, mitre_for("arp_spoofing"), confidence_note="Conflicting ARP mappings are an indicator of possible ARP spoofing or legitimate network reconfiguration.")
