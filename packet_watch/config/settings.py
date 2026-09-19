from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


@dataclass(slots=True)
class Settings:
    root: Path
    data: dict[str, Any]

    @property
    def rolling_window_seconds(self) -> int:
        return int(self.data["rolling_window_seconds"])

    @property
    def reporting_interval_seconds(self) -> int:
        return int(self.data["reporting_interval_seconds"])

    @property
    def thresholds(self) -> dict[str, Any]:
        return self.data["thresholds"]

    @property
    def whitelist_ips(self) -> set[str]:
        return set(self.data["whitelist"]["ips"])

    @property
    def whitelist_ports(self) -> set[int]:
        return {int(p) for p in self.data["whitelist"]["ports"]}

    @property
    def abuseipdb(self) -> dict[str, Any]:
        return self.data["abuseipdb"]

    @property
    def sslbl(self) -> dict[str, Any]:
        return self.data["sslbl"]


def load_settings(path: str | Path) -> Settings:
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    data = json.loads(config_path.read_text(encoding="utf-8"))
    load_dotenv(config_path.parent.parent / ".env")
    level = os.getenv("PACKET_WATCH_LOG_LEVEL")
    if level:
        data["log_level"] = level
    return Settings(root=config_path.parent.parent, data=data)
