from __future__ import annotations

import csv
import hashlib
import io
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests

from packet_watch.models import JA3Result


def _ints(values: Any) -> list[int]:
    out = []
    for value in values or []:
        try:
            out.append(int(value))
        except (TypeError, ValueError):
            continue
    return out


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A


def calculate_ja3(hello: Any) -> tuple[str, str]:
    """Calculate JA3 string and MD5 for a Scapy TLSClientHello-like object."""
    version = int(getattr(hello, "version"))
    ciphers = [v for v in _ints(getattr(hello, "ciphers", [])) if not _is_grease(v)]
    ext_ids: list[int] = []
    groups: list[int] = []
    point_formats: list[int] = []
    for ext in getattr(hello, "ext", []) or []:
        try:
            ext_id = int(getattr(ext, "type"))
        except (TypeError, ValueError):
            continue
        if not _is_grease(ext_id):
            ext_ids.append(ext_id)
        groups.extend(v for v in _ints(getattr(ext, "groups", [])) if not _is_grease(v))
        point_formats.extend(_ints(getattr(ext, "ecpl", [])))
    ja3_string = ",".join([
        str(version),
        "-".join(map(str, ciphers)),
        "-".join(map(str, ext_ids)),
        "-".join(map(str, groups)),
        "-".join(map(str, point_formats)),
    ])
    return ja3_string, hashlib.md5(ja3_string.encode("utf-8"), usedforsecurity=False).hexdigest()


@dataclass
class SSLBLClient:
    feed_url: str
    refresh_seconds: int = 900
    timeout_seconds: int = 10
    enabled: bool = True
    logger: logging.Logger | None = None

    def __post_init__(self):
        self.logger = self.logger or logging.getLogger("packet_watch.sslbl")
        self._entries: dict[str, dict[str, str]] = {}
        self._loaded_at = 0.0

    def refresh(self, force: bool = False) -> bool:
        if not self.enabled:
            return False
        if not force and time.monotonic() - self._loaded_at < self.refresh_seconds:
            return True
        try:
            response = requests.get(self.feed_url, timeout=self.timeout_seconds)
            response.raise_for_status()
            entries: dict[str, dict[str, str]] = {}
            for row in csv.reader(io.StringIO(response.text)):
                if not row or row[0].startswith("#") or row[0].strip().lower() == "ja3_md5":
                    continue
                if len(row) >= 4:
                    entries[row[0].strip().lower()] = {"first_seen": row[1], "last_seen": row[2], "listing_reason": row[3]}
            self._entries = entries
            self._loaded_at = time.monotonic()
            self.logger.info("Loaded %d SSLBL JA3 fingerprints", len(entries))
            return True
        except requests.RequestException as exc:
            self._loaded_at = time.monotonic()
            self.logger.warning("SSLBL feed unavailable: %s", exc)
            return False

    def lookup(self, fingerprint: str) -> JA3Result:
        self.refresh()
        entry = self._entries.get(fingerprint.lower())
        if entry:
            return JA3Result(fingerprint=fingerprint, matched=True, status="matched", **entry,
                             note="Matched SSLBL threat-data; treat as a supporting indicator, not definitive proof of compromise.")
        if self._entries:
            return JA3Result(fingerprint=fingerprint, matched=False, status="not_listed")
        return JA3Result(fingerprint=fingerprint, matched=False, status="feed_unavailable", note="SSLBL threat data unavailable; observed JA3 is still available.")
