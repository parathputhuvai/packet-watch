from __future__ import annotations

from collections import defaultdict

from packet_watch.models import Alert, TimelineEvent


class AlertTimeline:
    def __init__(self):
        self.events_by_source: dict[str, list[TimelineEvent]] = defaultdict(list)

    def add(self, alert: Alert) -> TimelineEvent:
        event = TimelineEvent(alert.timestamp, alert.source_ip, alert.attack_type, alert.severity, alert.evidence, alert.mitre, alert.alert_id)
        self.events_by_source[alert.source_ip or "unknown"].append(event)
        self.events_by_source[alert.source_ip or "unknown"].sort(key=lambda e: e.timestamp)
        return event

    def events(self):
        output = []
        for events in self.events_by_source.values():
            output.extend(events)
        return sorted(output, key=lambda e: e.timestamp)
