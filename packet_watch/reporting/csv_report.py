from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from packet_watch.models import Alert, TimelineEvent

FIELDS = ["alert_id", "timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", "attack_type", "severity", "rule_id", "evidence", "observed", "thresholds", "mitre_technique_id", "mitre_technique_name", "mitre_tactic", "confidence_note", "reputation_status", "reputation_score", "ja3_fingerprint", "ja3_matched", "ja3_listing_reason", "whitelisted", "suppressed_reason", "correlation_source_ip", "correlation_sequence", "correlation_group_size"]


def write_csv(path: str | Path, alerts: list[Alert], timeline_events: list[TimelineEvent] | None = None) -> Path:
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    correlation: dict[str, tuple[str, int, int]] = {}
    if timeline_events is not None:
        events_by_source: dict[str, list[TimelineEvent]] = defaultdict(list)
        for event in timeline_events:
            events_by_source[event.source_ip or "unknown"].append(event)
        for source_ip, events in events_by_source.items():
            for sequence, event in enumerate(events, 1):
                correlation[event.alert_id] = (source_ip, sequence, len(events))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for a in alerts:
            source_ip, sequence, group_size = correlation.get(a.alert_id, (None, None, None))
            writer.writerow({
                "alert_id": a.alert_id, "timestamp": a.timestamp.isoformat(), "source_ip": a.source_ip, "destination_ip": a.destination_ip,
                "source_port": a.source_port, "destination_port": a.destination_port, "protocol": a.protocol, "attack_type": a.attack_type,
                "severity": a.severity.value, "rule_id": a.rule_id, "evidence": repr(a.evidence), "observed": repr(a.observed), "thresholds": repr(a.thresholds),
                "mitre_technique_id": a.mitre.get("technique_id"), "mitre_technique_name": a.mitre.get("technique_name"), "mitre_tactic": a.mitre.get("tactic"),
                "confidence_note": a.confidence_note, "reputation_status": a.reputation.status if a.reputation else None,
                "reputation_score": a.reputation.abuse_confidence_score if a.reputation else None,
                "ja3_fingerprint": a.ja3.fingerprint if a.ja3 else None, "ja3_matched": a.ja3.matched if a.ja3 else None,
                "ja3_listing_reason": a.ja3.listing_reason if a.ja3 else None, "whitelisted": a.whitelisted, "suppressed_reason": a.suppressed_reason,
                "correlation_source_ip": source_ip, "correlation_sequence": sequence, "correlation_group_size": group_size,
            })
    return path
