from __future__ import annotations

import logging
from typing import Callable, Any


class LiveCapture:
    def __init__(self, interface: str | None, callback: Callable[[Any], None], promiscuous: bool = True, logger: logging.Logger | None = None):
        self.interface = interface
        self.callback = callback
        self.promiscuous = promiscuous
        self.logger = logger or logging.getLogger("packet_watch.capture")

    @staticmethod
    def list_interfaces() -> list[str]:
        try:
            from scapy.all import get_if_list
            return list(get_if_list())
        except ImportError as exc:
            raise RuntimeError("Scapy is required. Install dependencies with 'pip install -r requirements.txt'.") from exc

    def run(self, stop_filter: Callable[[Any], bool] | None = None) -> None:
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise RuntimeError("Scapy is required for live capture.") from exc
        try:
            sniff(iface=self.interface, prn=self.callback, store=False, promisc=self.promiscuous, stop_filter=stop_filter)
        except PermissionError as exc:
            raise RuntimeError("Packet capture requires elevated Windows privileges. Run the terminal as Administrator.") from exc
        except OSError as exc:
            raise RuntimeError(f"Live capture failed. Check Npcap and interface selection: {exc}") from exc


__all__ = ["LiveCapture"]
