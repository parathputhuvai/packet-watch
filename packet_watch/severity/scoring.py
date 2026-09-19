from __future__ import annotations

from packet_watch.models import DetectionResult, Severity, SeverityResult


class SeverityScorer:
    """Deterministic rule-specific severity based on threshold exceedance."""

    def assign(self, result: DetectionResult) -> SeverityResult:
        obs = result.observed
        th = result.thresholds
        rid = result.rule_id
        if rid == "PW-PORT-001":
            value = float(obs.get("distinct_destination_ports", 0))
            score = 10 if value < float(th["distinct_destination_ports"]) * 1.25 else 40 if value < float(th.get("high_ports", 50)) else 70 if value < float(th.get("critical_ports", 100)) else 90
        elif rid in {"PW-SYN-001", "PW-ICMP-001", "PW-MAC-001"}:
            key_map = {
                "PW-SYN-001": ("syn_packets", "syn_packets", "high_syn_packets", "critical_syn_packets"),
                "PW-ICMP-001": ("icmp_packets", "icmp_packets", "high_icmp_packets", "critical_icmp_packets"),
                "PW-MAC-001": ("distinct_source_macs", "distinct_source_macs", "high_macs", "critical_macs"),
            }
            obs_key, base_key, high_key, critical_key = key_map[rid]
            value = float(obs.get(obs_key, 0))
            base = float(th[base_key])
            high = float(th.get(high_key, base * 2))
            critical = float(th.get(critical_key, base * 4))
            score = 20 if value < base * 1.5 else 45 if value < high else 70 if value < critical else 95
        elif rid == "PW-ARP-001":
            score = 70 if int(obs.get("mapping_changes", 0)) > 1 else 60
        elif rid == "PW-DNS-001":
            q = float(obs.get("queries", 0)); entropy = float(obs.get("max_entropy", 0)); label = float(obs.get("max_label_length", 0))
            score = 30
            if q >= float(th["queries"]): score += 20
            if q >= float(th.get("high_queries", th["queries"] * 2)): score += 20
            if entropy >= float(th["entropy"]): score += 10
            if label >= float(th["label_length"]): score += 10
            score = min(score, 90)
        elif rid == "PW-BRUTE-001":
            value = float(obs.get("connection_attempts", 0))
            base = float(th["connection_attempts"]); high = float(th["high_attempts"]); critical = float(th["critical_attempts"])
            score = 25 if value < high else 60 if value < critical else 90 if value >= critical else 40
        elif rid == "PW-JA3-001":
            score = 70
        elif rid == "PW-PING-001":
            value = float(obs.get("distinct_destinations", 0)); base = float(th["distinct_destinations"]); high = float(th["high_destinations"])
            score = 40 if value < high else 70
        elif rid == "PW-MISMATCH-001":
            ratio = float(obs.get("mismatch_ratio", 0)); high = float(th["high_ratio"])
            score = 40 if ratio < high else 70
        else:
            score = 30
        severity = Severity.LOW if score < 40 else Severity.MEDIUM if score < 60 else Severity.HIGH if score < 85 else Severity.CRITICAL
        return SeverityResult(severity=severity, score=score, reason=f"Deterministic score {score}/100 derived from {result.rule_id} observed values and configured thresholds.")
