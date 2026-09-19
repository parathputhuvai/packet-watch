from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field

import requests

from packet_watch.models import ReputationResult


@dataclass
class AbuseIPDBClient:
    api_key: str | None = None
    max_age_days: int = 90
    timeout_seconds: int = 5
    cache_seconds: int = 900
    enabled: bool = True
    logger: logging.Logger | None = None
    _cache: dict[str, tuple[float, ReputationResult]] = field(default_factory=dict, init=False)

    def __post_init__(self):
        self.logger = self.logger or logging.getLogger("packet_watch.abuseipdb")
        self.enabled = self.enabled and bool(self.api_key)

    def check(self, ip: str | None) -> ReputationResult | None:
        if not ip:
            return None
        try:
            obj = ipaddress.ip_address(ip)
            if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved:
                return ReputationResult(ip=ip, status="skipped_local")
        except ValueError:
            return ReputationResult(ip=ip, status="invalid")
        if not self.enabled:
            return ReputationResult(ip=ip, status="unavailable", message="AbuseIPDB API key not configured or enrichment disabled.")
        cached = self._cache.get(ip)
        if cached and time.monotonic() - cached[0] < self.cache_seconds:
            return cached[1]
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": self.api_key, "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": self.max_age_days}, timeout=self.timeout_seconds)
            r.raise_for_status()
            data = r.json().get("data", {})
            result = ReputationResult(ip=ip, status="available", abuse_confidence_score=data.get("abuseConfidenceScore"), total_reports=data.get("totalReports"), country_code=data.get("countryCode"), isp=data.get("isp"), domain=data.get("domain"))
            self._cache[ip] = (time.monotonic(), result)
            return result
        except (requests.RequestException, ValueError) as exc:
            self.logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            result = ReputationResult(ip=ip, status="error", message=str(exc))
            self._cache[ip] = (time.monotonic(), result)
            return result


def from_environment(settings: dict, logger: logging.Logger | None = None) -> AbuseIPDBClient:
    key = os.getenv(settings.get("api_key_env", "PACKET_WATCH_ABUSEIPDB_API_KEY"))
    return AbuseIPDBClient(api_key=key, max_age_days=int(settings.get("max_age_days", 90)), timeout_seconds=int(settings.get("timeout_seconds", 5)), cache_seconds=int(settings.get("cache_seconds", 900)), enabled=bool(settings.get("enabled", True)), logger=logger)
