from __future__ import annotations

# Mapping is kept in one reviewable module. These are ATT&CK techniques relevant
# to the observable network behavior; they are not claims that the packet alone
# proves the full ATT&CK procedure occurred.
MITRE_MAPPING: dict[str, dict[str, str]] = {
    "port_scanning": {"technique_id": "T1046", "technique_name": "Network Service Scanning", "tactic": "Discovery"},
    "syn_flood": {"technique_id": "T1498", "technique_name": "Network Denial of Service", "tactic": "Impact"},
    "arp_spoofing": {"technique_id": "T1557.002", "technique_name": "Adversary-in-the-Middle: ARP Cache Poisoning", "tactic": "Credential Access"},
    "dns_tunneling": {"technique_id": "T1071.004", "technique_name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
    "brute_force": {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
    "ja3_malicious": {"technique_id": "T1573", "technique_name": "Encrypted Channel", "tactic": "Command and Control"},
    "icmp_flood": {"technique_id": "T1498", "technique_name": "Network Denial of Service", "tactic": "Impact"},
    "ping_sweep": {"technique_id": "T1018", "technique_name": "Remote System Discovery", "tactic": "Discovery"},
    "mac_flooding": {"technique_id": "T1498", "technique_name": "Network Denial of Service", "tactic": "Impact"},
    "protocol_mismatch": {"technique_id": "T1571", "technique_name": "Non-Standard Port", "tactic": "Command and Control"},
}


def mitre_for(rule_id: str) -> dict[str, str]:
    return dict(MITRE_MAPPING[rule_id])
