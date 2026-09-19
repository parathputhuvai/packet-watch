# Viva Explanation: Packet Flow

1. **Capture:** Scapy receives a packet from the selected Windows interface through Npcap.
2. **Parse:** `PacketParser` extracts only fields needed by detection: addresses, ports, protocol, flags, ARP/DNS/ICMP data and TLS Client Hello metadata where available.
3. **Normalize:** The raw Scapy object becomes a `ParsedPacket` dataclass, so detectors do not depend on raw packet syntax.
4. **Update rolling state:** The source-specific state tracker adds the observation and removes data older than the configured rolling window. This state remains alive across report boundaries.
5. **Detect:** Each of the ten explicit detectors evaluates the packet and current source state against configurable thresholds/signatures.
6. **Score:** A deterministic severity function examines the rule and observed threshold exceedance and assigns Low, Medium, High or Critical.
7. **Enrich:** The source IP can be checked against AbuseIPDB. TLS Client Hello metadata can produce a JA3 fingerprint and SSLBL can report whether that fingerprint is listed.
8. **Correlate:** The alert is added to a chronological source-based timeline.
9. **Whitelist:** A configured trusted IP or destination port can suppress the user-facing alert while the suppression is retained for audit reporting.
10. **Present:** Rich renders the alert with source/destination, attack type, rule, evidence, severity and MITRE metadata.
11. **Report:** Periodic/final exports summarize alerts to CSV and incident-oriented PDF. Exporting does not reset the rolling state.

The core security decision therefore remains explainable: packet observation -> rolling feature -> explicit rule -> deterministic severity -> optional enrichment -> alert/report.
