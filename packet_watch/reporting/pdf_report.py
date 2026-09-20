from __future__ import annotations

from pathlib import Path
import textwrap

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from packet_watch.models import Alert, TimelineEvent


class IncidentPDF(FPDF):
    def footer(self):
        self.set_y(-15); self.set_font("Helvetica", size=8); self.cell(0, 8, f"Packet Watch | Page {self.page_no()}", align="C")


def write_pdf(path: str | Path, alerts: list[Alert], started_at, ended_at, timeline_events: list[TimelineEvent] | None = None) -> Path:
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    pdf = IncidentPDF(); pdf.set_auto_page_break(auto=True, margin=18); pdf.add_page()
    pdf.set_font("Helvetica", "B", 18); pdf.cell(0, 10, "Packet Watch - Incident Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=10); pdf.cell(0, 7, f"Session: {started_at.isoformat()} to {ended_at.isoformat()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT); pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12); pdf.cell(0, 8, f"Detections: {len(alerts)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT); pdf.ln(2)
    for alert in alerts:
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(0, 6, f"{alert.attack_type} | {alert.severity.value} | {alert.rule_id} | {alert.timestamp.isoformat()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", size=9)
        lines = [
            f"Source: {alert.source_ip or '-'}    Destination: {alert.destination_ip or '-'}    Protocol: {alert.protocol}",
            f"Ports: {alert.source_port or '-'} -> {alert.destination_port or '-'}",
            f"MITRE: {alert.mitre.get('technique_id', '-')} {alert.mitre.get('technique_name', '-')} | {alert.mitre.get('tactic', '-')}",
            f"Observed: {alert.observed}",
            f"Evidence: {alert.evidence}",
        ]
        if alert.reputation: lines.append(f"AbuseIPDB: status={alert.reputation.status}, confidence={alert.reputation.abuse_confidence_score}, reports={alert.reputation.total_reports}")
        if alert.ja3: lines.append(f"JA3: {alert.ja3.fingerprint} | matched={alert.ja3.matched} | status={alert.ja3.status} | reason={alert.ja3.listing_reason or '-'}")
        if alert.whitelisted: lines.append(f"Whitelist: SUPPRESSED ({alert.suppressed_reason})")
        for line in lines:
            for wrapped in textwrap.wrap(str(line), width=72, break_long_words=True, break_on_hyphens=False) or [""]:
                pdf.multi_cell(0, 5, wrapped, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if alert.confidence_note:
            for wrapped in textwrap.wrap(f"Note: {alert.confidence_note}", width=72, break_long_words=True, break_on_hyphens=False):
                pdf.multi_cell(0, 5, wrapped, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)
    if timeline_events is not None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Attack Timeline / Alert Correlation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if not timeline_events:
            pdf.set_font("Helvetica", size=9)
            pdf.cell(0, 6, "No correlated events", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            alerts_by_id = {alert.alert_id: alert for alert in alerts}
            events_by_source = {}
            for event in timeline_events:
                events_by_source.setdefault(event.source_ip or "unknown", []).append(event)
            for source_ip, events in events_by_source.items():
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 6, f"Source IP: {source_ip}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font("Helvetica", size=8)
                for sequence, event in enumerate(events, 1):
                    alert = alerts_by_id.get(event.alert_id)
                    status = " [SUPPRESSED/WHITELISTED]" if alert and alert.whitelisted else ""
                    line = f"{sequence}. {event.timestamp.isoformat()} | {event.source_ip or '-'} | {event.attack_type} | {event.severity.value} | {event.alert_id}{status}"
                    for wrapped in textwrap.wrap(line, width=100, break_long_words=True, break_on_hyphens=False) or [""]:
                        pdf.multi_cell(0, 5, wrapped, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    try: pdf.output(str(path))
    except Exception as exc: raise RuntimeError(f"PDF generation failed: {exc}") from exc
    return path
