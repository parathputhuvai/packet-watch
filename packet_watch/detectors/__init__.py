from .port_scan import PortScanDetector
from .syn_flood import SynFloodDetector
from .arp_spoofing import ARPSpoofingDetector
from .dns_tunneling import DNSTunnelingDetector
from .brute_force import BruteForceDetector
from .ja3 import JA3Detector
from .icmp_flood import ICMPFloodDetector
from .ping_sweep import PingSweepDetector
from .mac_flooding import MACFloodingDetector
from .protocol_mismatch import ProtocolMismatchDetector


def build_detectors(settings):
    t = settings.thresholds
    return [
        PortScanDetector(t["port_scan"]), SynFloodDetector(t["syn_flood"]),
        ARPSpoofingDetector(t["arp_spoofing"]), DNSTunnelingDetector(t["dns_tunneling"]),
        BruteForceDetector(t["brute_force"]), JA3Detector(),
        ICMPFloodDetector(t["icmp_flood"]), PingSweepDetector(t["ping_sweep"]),
        MACFloodingDetector(t["mac_flooding"]), ProtocolMismatchDetector(t["protocol_mismatch"]),
    ]
