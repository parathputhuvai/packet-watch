from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Sequence


_GUID_PATTERN = re.compile(
    r"\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?",
    re.IGNORECASE,
)


class ActiveInterfaceError(RuntimeError):
    """Raised when an active Windows adapter cannot be mapped to Npcap."""


@dataclass(frozen=True, slots=True)
class ActiveInterfaceInfo:
    friendly_name: str
    status: str
    ipv4_address: str | None
    gateway: str | None
    interface_guid: str
    npcap_interface: str


def _normalise_guid(value: str | None) -> str:
    if not value:
        return ""
    match = _GUID_PATTERN.search(str(value).strip())
    return match.group(1).lower() if match else ""


def map_guid_to_npcap(
    interface_guid: str,
    npcap_interfaces: Sequence[str],
) -> str | None:
    target = _normalise_guid(interface_guid)
    if not target:
        return None
    for interface in npcap_interfaces:
        if _normalise_guid(interface) == target:
            return interface
    return None


def _load_windows_adapters() -> list[dict[str, Any]]:
    script = r"""
$ErrorActionPreference = 'Stop'
$rows = @(
    Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 |
    Sort-Object RouteMetric |
    ForEach-Object {
        $route = $_
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        if ($null -ne $adapter -and $adapter.Status -eq 'Up') {
            $ip = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } |
                Select-Object -First 1
            [pscustomobject]@{
                FriendlyName = [string]$adapter.Name
                Status = [string]$adapter.Status
                InterfaceGuid = [string]$adapter.InterfaceGuid
                IPv4Address = if ($ip) { [string]$ip.IPAddress } else { $null }
                Gateway = [string]$route.NextHop
            }
        }
    }
)
$rows | ConvertTo-Json -Compress
"""
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise ActiveInterfaceError(
            f"Could not run Windows PowerShell for adapter discovery: {exc}"
        ) from exc

    if completed.returncode != 0:
        raise ActiveInterfaceError(
            "Windows network interface discovery failed. Check that networking is enabled."
        )
    try:
        payload = json.loads(completed.stdout) if completed.stdout.strip() else []
    except json.JSONDecodeError as exc:
        raise ActiveInterfaceError(
            "Windows network information could not be parsed."
        ) from exc

    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _list_npcap_interfaces() -> list[str]:
    from .live import LiveCapture

    return LiveCapture.list_interfaces()


def find_active_interface(
    adapter_loader: Callable[[], list[dict[str, Any]]] | None = None,
    npcap_loader: Callable[[], list[str]] | None = None,
) -> ActiveInterfaceInfo:
    adapters = (adapter_loader or _load_windows_adapters)()
    npcap_interfaces = (npcap_loader or _list_npcap_interfaces)()
    if not adapters:
        raise ActiveInterfaceError("No active IPv4 network interface was found.")
    if not npcap_interfaces:
        raise ActiveInterfaceError(
            "Scapy/Npcap returned no capture interfaces. Verify that Npcap is installed."
        )

    for adapter in adapters:
        npcap_interface = map_guid_to_npcap(
            str(adapter.get("InterfaceGuid") or ""),
            npcap_interfaces,
        )
        if npcap_interface is None:
            continue
        return ActiveInterfaceInfo(
            friendly_name=str(adapter.get("FriendlyName") or "Unknown adapter"),
            status=str(adapter.get("Status") or "Unknown"),
            ipv4_address=(
                str(adapter["IPv4Address"]) if adapter.get("IPv4Address") else None
            ),
            gateway=str(adapter["Gateway"]) if adapter.get("Gateway") else None,
            interface_guid=str(adapter.get("InterfaceGuid") or ""),
            npcap_interface=npcap_interface,
        )

    raise ActiveInterfaceError(
        "No active Windows network interface could be mapped to an Npcap interface."
    )


__all__ = [
    "ActiveInterfaceError",
    "ActiveInterfaceInfo",
    "find_active_interface",
    "map_guid_to_npcap",
]