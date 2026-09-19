# Packet Watch: Network Intrusion Analyzer

Packet Watch is a Windows command-line, passive network intrusion analyzer written in Python 3.10+. It captures live traffic with Scapy/Npcap and applies explicit, explainable signature/rule logic for exactly ten attack patterns.

## Scope

Packet Watch is intentionally not an ML IDS, anomaly detector, web/GUI dashboard, distributed collector, SIEM, Wireshark replacement, or PCAP-first application. Detection state is maintained continuously in a configurable rolling window; periodic reports do not reset state.

## Ten detections

1. Port Scanning  
2. SYN Flood  
3. ARP Spoofing  
4. DNS Tunneling  
5. Brute-Force Attempts  
6. Malicious Encrypted Traffic using TLS/JA3 Fingerprinting  
7. ICMP Flood  
8. Ping Sweep  
9. MAC Flooding  
10. Non-Standard Port / Protocol Mismatch

## Architecture

`Live Capture -> Packet Parser -> Per-Source Rolling State -> Signature Detection -> Severity -> IP Reputation -> Correlation/Timeline -> Whitelist -> Rich Terminal -> PDF/CSV`

The parser normalizes only fields needed by the detector/reporting layers. Optional threat intelligence is isolated and failure-tolerant.

## Windows requirements

- Windows 10/11
- Python 3.10+
- Npcap installed with packet-capture support
- Administrator/elevated terminal may be required depending on capture/interface permissions

The normal workflow does not require Wireshark.

## Setup

```powershell
py -3.10 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Install Npcap from the official Npcap project and verify that Scapy can enumerate interfaces.

## Configuration

Edit `config/config.json` for thresholds, rolling window, report interval, whitelist IPs/ports, capture interface, and threat-data settings.

Set the AbuseIPDB API key in `.env` as `PACKET_WATCH_ABUSEIPDB_API_KEY=...`. The key is never stored in source code.

SSLBL's JA3 fingerprint blacklist is configured to refresh no more frequently than every 15 minutes by default. The feed is optional: if it is unavailable, Packet Watch still calculates and reports observed JA3 values where available.

## Usage

```powershell
.venv\Scripts\python -m packet_watch interfaces
.venv\Scripts\python -m packet_watch info
.venv\Scripts\python -m packet_watch monitor --interface "YOUR INTERFACE NAME"
```

Press `Ctrl+C` to stop capture and write final PDF/CSV reports under `reports/`.

## Testing

The test suite feeds synthetic parsed packet objects directly to the rolling state and detector layers. This keeps the core logic testable without making PCAP ingestion a product feature.

```powershell
.venv\Scripts\python -m pytest -q
```

## Reports

CSV includes alert metadata, evidence, observed values, thresholds, MITRE metadata, reputation enrichment, JA3 information and whitelist state. PDF is an incident-oriented summary rather than a raw packet dump.

## Limitations

Packet Watch is network-only. It cannot inspect process execution, files, memory or endpoint behavior. On switched networks, the host generally sees only traffic that reaches its interface; wider visibility needs a mirror port, gateway placement or future distributed collection. Encrypted application payloads are not decrypted. JA3 is a supporting indicator because applications can share TLS libraries. Rule thresholds require tuning for individual networks. Continuous operation is required while the attack occurs.

## Future scope (documented, not implemented)

Distributed collection, centralized multi-source analysis, client-server transport, endpoint telemetry, ML detection, statistical baselining and enterprise SIEM/XDR functionality.
