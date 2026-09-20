from __future__ import annotations

import logging
import uuid
from datetime import timedelta

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
        self._last_alert_at: dict[tuple, object] = {}
        self.alert_dedup_seconds = 60

    def _dedup_key(self, result, packet) -> tuple:
        """
        Build a key used to prevent repeated alerts for the same condition.

        Protocol mismatch includes ports because different flows may
        legitimately have different destination ports.

        Other detectors are grouped by rule + IP pair + protocol.
        """
        if result.rule_id == "PW-MISMATCH-001":
            return (
                result.rule_id,
                result.source_ip,
                result.destination_ip,
                result.protocol,
                packet.src_port,
                packet.dst_port,
            )

        if result.rule_id == "PW-BRUTE-001":
            return (
                result.rule_id,
                result.source_ip,
                result.destination_ip,
                result.protocol,
                packet.dst_port,
            )

        return (
            result.rule_id,
            result.source_ip,
            result.destination_ip,
            result.protocol,
        )

    def _is_duplicate_alert(self, result, packet) -> bool:
        """
        Return True when the same detection was already emitted recently.
        """
        key = self._dedup_key(result, packet)
        current_time = packet.timestamp

        previous_time = self._last_alert_at.get(key)

        if previous_time is not None:
            elapsed = (current_time - previous_time).total_seconds()

            if elapsed < self.alert_dedup_seconds:
                return True

        self._last_alert_at[key] = current_time

        # Remove stale deduplication entries occasionally so the dictionary
        # does not grow forever during a long capture.
        cutoff = current_time - timedelta(seconds=self.alert_dedup_seconds)

        stale_keys = [
            stored_key
            for stored_key, timestamp in self._last_alert_at.items()
            if timestamp < cutoff
        ]

        for stored_key in stale_keys:
            self._last_alert_at.pop(stored_key, None)

        return False

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

            if self._is_duplicate_alert(result, packet):
                continue

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
