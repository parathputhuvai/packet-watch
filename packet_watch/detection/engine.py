from __future__ import annotations

import logging
import uuid

from packet_watch.models import Alert, DetectionResult
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.whitelist import WhitelistFilter


class DetectionEngine:
    def __init__(self, detectors, state_tracker: RollingStateTracker, severity: SeverityScorer, whitelist: WhitelistFilter, logger: logging.Logger | None = None):
        self.detectors = detectors
        self.state_tracker = state_tracker
        self.severity = severity
        self.whitelist = whitelist
        self.logger = logger or logging.getLogger("packet_watch.detection")
        self.suppressed_alerts: list[Alert] = []

    def process(self, packet):
        state = self.state_tracker.observe(packet)
        if state is None:
            return []
        alerts: list[Alert] = []
        seen_rules: set[str] = set()
        for detector in self.detectors:
            try:
                result = detector.detect(packet, state)
            except Exception as exc:
                self.logger.exception("Detector %s failed: %s", detector.rule_id, exc)
                continue
            if result is None or result.rule_id in seen_rules:
                continue
            seen_rules.add(result.rule_id)
            sev = self.severity.assign(result)
            suppressed, reason = self.whitelist.should_suppress(result, packet.dst_port)
            alert = Alert(
                alert_id=uuid.uuid4().hex[:12].upper(),
                timestamp=packet.timestamp,
                source_ip=result.source_ip,
                destination_ip=result.destination_ip,
                source_port=packet.src_port,
                destination_port=packet.dst_port,
                protocol=result.protocol,
                attack_type=result.attack_type,
                severity=sev.severity,
                rule_id=result.rule_id,
                evidence=result.evidence,
                observed=result.observed,
                thresholds=result.thresholds,
                mitre=result.mitre,
                confidence_note=result.confidence_note,
                whitelisted=suppressed,
                suppressed_reason=reason,
            )
            if suppressed:
                self.suppressed_alerts.append(alert)
                continue
            alerts.append(alert)
        return alerts
