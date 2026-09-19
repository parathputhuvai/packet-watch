from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(slots=True)
class ParsedPacket:
    timestamp: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "OTHER"
    tcp_flags: str = ""
    src_mac: str | None = None
    dst_mac: str | None = None
    arp_op: int | None = None
    arp_psrc: str | None = None
    arp_pdst: str | None = None
    arp_hwsrc: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    dns_query: str | None = None
    dns_qtype: int | None = None
    tls_client_hello: dict[str, Any] | None = None
    packet_len: int = 0


@dataclass(slots=True)
class DetectionResult:
    attack_type: str
    rule_id: str
    source_ip: str | None
    destination_ip: str | None
    protocol: str
    evidence: dict[str, Any]
    observed: dict[str, Any]
    thresholds: dict[str, Any]
    mitre: dict[str, str]
    severity: Severity = Severity.LOW
    confidence_note: str | None = None


@dataclass(slots=True)
class SeverityResult:
    severity: Severity
    score: int
    reason: str


@dataclass(slots=True)
class ReputationResult:
    ip: str
    status: str = "unknown"
    abuse_confidence_score: int | None = None
    total_reports: int | None = None
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    message: str | None = None


@dataclass(slots=True)
class JA3Result:
    fingerprint: str | None
    matched: bool = False
    listing_reason: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    status: str = "not_available"
    note: str | None = None


@dataclass(slots=True)
class Alert:
    alert_id: str
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    attack_type: str
    severity: Severity
    rule_id: str
    evidence: dict[str, Any]
    observed: dict[str, Any]
    thresholds: dict[str, Any]
    mitre: dict[str, str]
    confidence_note: str | None = None
    reputation: ReputationResult | None = None
    ja3: JA3Result | None = None
    whitelisted: bool = False
    suppressed_reason: str | None = None


@dataclass(slots=True)
class TimelineEvent:
    timestamp: datetime
    source_ip: str | None
    attack_type: str
    severity: Severity
    evidence: dict[str, Any]
    mitre: dict[str, str]
    alert_id: str


@dataclass(slots=True)
class ReportRecord:
    alert: Alert


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
