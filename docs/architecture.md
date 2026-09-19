# Packet Watch Architecture

Packet Watch processes each captured packet through a narrow pipeline:

1. **Live capture** — Scapy/Npcap supplies raw packets.
2. **Parser** — `PacketParser` converts supported packets into `ParsedPacket`.
3. **Rolling state** — `RollingStateTracker` maintains per-source observations for a bounded window.
4. **Detection engine** — ten explicit detectors inspect current packet + rolling state.
5. **Severity** — `SeverityScorer` deterministically maps observed threshold exceedance to Low/Medium/High/Critical.
6. **Threat intelligence** — AbuseIPDB enriches generated alerts; SSLBL supports JA3 lookup.
7. **Correlation** — `AlertTimeline` groups alerts by source and chronology.
8. **Whitelist** — configured trusted IPs/ports suppress repeated user-facing alerts while preserving the fact that suppression happened.
9. **Output** — Rich terminal panels show evidence, severity and MITRE information.
10. **Reporting** — PDF/CSV exports summarize session alerts.

Reporting intervals never reset rolling state. State cleanup is timestamp based.
