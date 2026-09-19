# Detection Rules

All rules are explicit signatures/thresholds. Numeric values are implementation settings in `config/config.json`, not universal claims about maliciousness.

| Rule | Trigger summary |
|---|---|
| PW-PORT-001 | Distinct destination ports from one source reach the configured threshold. |
| PW-SYN-001 | Rolling SYN count crosses the threshold and the SYN/SYN-ACK relationship supports the signature. |
| PW-ARP-001 | An observed ARP source IP changes MAC mapping within the rolling window. |
| PW-DNS-001 | DNS query count plus explicit entropy/label-length heuristics support tunneling. |
| PW-BRUTE-001 | Repeated connection attempts to configured authentication/service ports cross the threshold. |
| PW-JA3-001 | Observed JA3 fingerprint is present in loaded SSLBL threat data. |
| PW-ICMP-001 | Rolling ICMP count crosses the rate threshold. |
| PW-PING-001 | ICMP source contacts many distinct destination IPs. |
| PW-MAC-001 | Source presents many distinct MAC observations within the rolling window. |
| PW-MISMATCH-001 | Repeated protocol/port combinations fall outside configured common-service signatures. |

Detectors emit evidence and observed/threshold values so a reviewer can trace why an alert was generated.
