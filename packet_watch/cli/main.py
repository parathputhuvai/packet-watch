from __future__ import annotations

import argparse
from pathlib import Path

from packet_watch import __title__, __version__
from packet_watch.cli.app import PacketWatchApp
from packet_watch.config import load_settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="packet-watch", description="Packet Watch: Windows rule-based network intrusion analyzer")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", default=str(Path("config") / "config.json"), help="Path to JSON configuration file")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("interfaces", help="List Scapy/Npcap capture interfaces")
    monitor = sub.add_parser("monitor", help="Start continuous live capture and detection")
    monitor.add_argument("-i", "--interface", default=None, help="Capture interface name")
    export = sub.add_parser("export", help="Export the current in-memory session (for embedded/library use)")
    export.add_argument("--prefix", default="manual")
    sub.add_parser("info", help="Show project/session configuration information")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = load_settings(args.config)
    app = PacketWatchApp(settings)
    if args.command == "interfaces":
        app.show_banner(); app.list_interfaces(); return 0
    if args.command == "info":
        app.show_banner()
        app.console.print(f"Rolling window: {settings.rolling_window_seconds}s | Reporting interval: {settings.reporting_interval_seconds}s")
        app.console.print(f"Whitelisted IPs: {len(settings.whitelist_ips)} | Whitelisted ports: {len(settings.whitelist_ports)}")
        return 0
    if args.command == "export":
        app.export_reports(args.prefix); return 0
    if args.command == "monitor":
        app.show_banner(); interface = args.interface or settings.data["capture"].get("interface"); app.monitor(interface); return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
