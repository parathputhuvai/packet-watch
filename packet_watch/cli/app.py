from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from packet_watch import __title__, __version__
from packet_watch.capture import LiveCapture
from packet_watch.correlation import AlertTimeline
from packet_watch.detection import DetectionEngine
from packet_watch.detectors import build_detectors
from packet_watch.parser import PacketParser
from packet_watch.reporting import write_csv, write_pdf
from packet_watch.severity import SeverityScorer
from packet_watch.state import RollingStateTracker
from packet_watch.threat_intel import SSLBLClient, from_environment
from packet_watch.threat_intel.pipeline import enrich_tls_packet
from packet_watch.whitelist import WhitelistFilter
from packet_watch.utils import setup_logging


class PacketWatchApp:
    def __init__(self, settings):
        self.settings = settings
        self.console = Console()
        self.logger = setup_logging(settings.data.get("log_level", "INFO"))
        self.parser = PacketParser(self.logger)
        self.state = RollingStateTracker(settings.rolling_window_seconds)
        self.sslbl = SSLBLClient(logger=self.logger, **settings.sslbl)
        self.engine = DetectionEngine(build_detectors(settings), self.state, SeverityScorer(), WhitelistFilter(settings.whitelist_ips, settings.whitelist_ports), self.logger)
        self.abuseipdb = from_environment(settings.abuseipdb, self.logger)
        self.timeline = AlertTimeline()
        self.alerts = []
        self.session_started = datetime.now(timezone.utc)
        self.last_report_at = self.session_started

    def show_banner(self):
        self.console.print(Panel.fit(f"[bold]{__title__}[/bold]\nVersion {__version__}\nWindows live, passive, rule-based network analyzer"))

    def list_interfaces(self):
        interfaces = LiveCapture.list_interfaces()
        table = Table(title="Capture Interfaces")
        table.add_column("#"); table.add_column("Interface")
        for i, name in enumerate(interfaces, 1): table.add_row(str(i), name)
        self.console.print(table)

    def process_packet(self, raw_packet):
        parsed = self.parser.parse(raw_packet)
        if parsed is None: return
        enrich_tls_packet(parsed, self.sslbl)
        results = self.engine.process(parsed)
        for alert in results:
            if alert.source_ip:
                alert.reputation = self.abuseipdb.check(alert.source_ip)
            if parsed.tls_client_hello and parsed.tls_client_hello.get("ja3_fingerprint"):
                from packet_watch.models import JA3Result
                info = parsed.tls_client_hello
                alert.ja3 = JA3Result(fingerprint=info.get("ja3_fingerprint"), matched=bool(info.get("ja3_match")), listing_reason=info.get("ja3_listing_reason"), first_seen=info.get("ja3_first_seen"), last_seen=info.get("ja3_last_seen"), status=info.get("ja3_status", "unknown"))
            self.alerts.append(alert)
            self.timeline.add(alert)
            self._print_alert(alert)
        now = parsed.timestamp
        if (now - self.last_report_at).total_seconds() >= self.settings.reporting_interval_seconds:
            self.export_reports(prefix="periodic")
            self.last_report_at = now

    def _print_alert(self, alert):
        style = {"Low": "cyan", "Medium": "yellow", "High": "magenta", "Critical": "red"}.get(alert.severity.value, "white")
        title = f"{alert.attack_type} [{alert.severity.value}]"
        rows = [
            f"Rule: {alert.rule_id}", f"Time: {alert.timestamp.isoformat()}", f"Flow: {alert.source_ip or '-'}:{alert.source_port or '-'} -> {alert.destination_ip or '-'}:{alert.destination_port or '-'} ({alert.protocol})",
            f"Evidence: {alert.evidence}", f"Observed: {alert.observed}", f"MITRE: {alert.mitre.get('technique_id')} {alert.mitre.get('technique_name')} / {alert.mitre.get('tactic')}",
        ]
        if alert.reputation: rows.append(f"AbuseIPDB enrichment: {alert.reputation.status}, confidence={alert.reputation.abuse_confidence_score}")
        if alert.ja3: rows.append(f"JA3: {alert.ja3.fingerprint} | SSLBL={alert.ja3.status}")
        if alert.whitelisted: rows.append(f"WHITELIST SUPPRESSED: {alert.suppressed_reason}")
        if alert.confidence_note: rows.append(f"Note: {alert.confidence_note}")
        self.console.print(Panel("\n".join(rows), title=title, border_style=style))

    def monitor(self, interface: str | None):
        self.session_started = datetime.now(timezone.utc); self.last_report_at = self.session_started
        self.console.print(f"[bold green]Starting live capture[/bold green] on: {interface or 'default interface'}")
        self.console.print("Press Ctrl+C to stop and create a final report.")
        capture = LiveCapture(interface, self.process_packet, self.settings.data["capture"].get("promiscuous", True), self.logger)
        try:
            capture.run()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Capture stopped by user.[/yellow]")
        finally:
            self.export_reports(prefix="session")

    def export_reports(self, prefix: str = "session"):
        ended = datetime.now(timezone.utc)
        stamp = ended.strftime("%Y%m%d_%H%M%S")
        reports_dir = self.settings.root / "reports"
        audit_alerts = self.alerts + list(self.engine.suppressed_alerts)
        csv_path = write_csv(reports_dir / f"{prefix}_{stamp}.csv", audit_alerts)
        pdf_path = write_pdf(reports_dir / f"{prefix}_{stamp}.pdf", audit_alerts, self.session_started, ended)
        self.console.print(f"Reports written: {csv_path.name}, {pdf_path.name}")
        return csv_path, pdf_path
