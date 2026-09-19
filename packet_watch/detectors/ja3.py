from packet_watch.detection.base import Detector
from packet_watch.models import DetectionResult
from packet_watch.mitre import mitre_for

class JA3Detector(Detector):
    rule_id = "PW-JA3-001"; attack_type = "Malicious Encrypted Traffic (TLS/JA3)"
    def detect(self, packet, state):
        info = packet.tls_client_hello or {}
        fp = info.get("ja3_fingerprint")
        if not fp or not info.get("ja3_match"):
            return None
        return DetectionResult(self.attack_type, self.rule_id, packet.src_ip, packet.dst_ip, packet.protocol,
            {"reason": "Observed TLS Client Hello JA3 fingerprint matched configured SSLBL threat data.", "ja3": fp},
            {"ja3_fingerprint": fp, "sslbl_match": True, "listing_reason": info.get("ja3_listing_reason")},
            {}, mitre_for("ja3_malicious"), confidence_note="JA3 is a supporting indicator. Shared TLS libraries can cause identical fingerprints across unrelated applications.")
