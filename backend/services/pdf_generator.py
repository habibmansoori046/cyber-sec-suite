"""PDF report generator — produces professional security reports with ReportLab."""

import os
import uuid
import logging
from datetime import datetime
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)

from config import settings

logger = logging.getLogger(__name__)

# ──── Color scheme ────────────────────────────────────────────
NAVY = colors.HexColor("#0a0e17")
DARK_BG = colors.HexColor("#111827")
CYAN = colors.HexColor("#06b6d4")
RED = colors.HexColor("#ef4444")
ORANGE = colors.HexColor("#f97316")
YELLOW = colors.HexColor("#eab308")
GREEN = colors.HexColor("#22c55e")
GRAY = colors.HexColor("#9ca3af")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": RED,
    "high": ORANGE,
    "medium": YELLOW,
    "low": GREEN,
    "info": CYAN,
}


class PDFGenerator:
    """Generates PDF security reports."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Custom paragraph styles for security reports."""
        self.styles.add(ParagraphStyle(
            "ReportTitle",
            parent=self.styles["Heading1"],
            fontSize=22,
            textColor=NAVY,
            spaceAfter=20,
        ))
        self.styles.add(ParagraphStyle(
            "SectionHeader",
            parent=self.styles["Heading2"],
            fontSize=14,
            textColor=NAVY,
            spaceBefore=16,
            spaceAfter=8,
            borderWidth=0,
            borderColor=CYAN,
            borderPadding=4,
        ))
        self.styles.add(ParagraphStyle(
            "SubHeader",
            parent=self.styles["Heading3"],
            fontSize=11,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=10,
            spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            "BodyText_Custom",
            parent=self.styles["BodyText"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155"),
        ))
        self.styles.add(ParagraphStyle(
            "Meta",
            parent=self.styles["BodyText"],
            fontSize=9,
            textColor=GRAY,
        ))

    def _generate_filename(self, report_type: str) -> str:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        uid = uuid.uuid4().hex[:6]
        return f"{report_type}_report_{ts}_{uid}.pdf"

    def _build_header(self, elements: list, title: str, subtitle: str, meta: dict):
        """Standard report header block."""
        elements.append(Paragraph("CYBERSEC SUITE", self.styles["Meta"]))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(title, self.styles["ReportTitle"]))
        elements.append(Paragraph(subtitle, self.styles["BodyText_Custom"]))
        elements.append(Spacer(1, 8))

        # Meta table
        meta_data = [[Paragraph(f"<b>{k}:</b>", self.styles["Meta"]),
                       Paragraph(str(v), self.styles["Meta"])]
                      for k, v in meta.items()]
        if meta_data:
            t = Table(meta_data, colWidths=[2 * inch, 4.5 * inch])
            t.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            elements.append(t)

        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1, color=CYAN, spaceBefore=4, spaceAfter=12))

    def _severity_table(self, elements: list, counts: dict):
        """Severity distribution summary."""
        elements.append(Paragraph("Severity Distribution", self.styles["SubHeader"]))
        data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            data.append([sev.capitalize(), str(counts.get(sev, 0))])
        t = Table(data, colWidths=[2 * inch, 1.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

    # ──── Vulnerability Report ────────────────────────────────
    async def generate_vulnerability_report(self, scan, sections: List[str]) -> str:
        filename = self._generate_filename("vulnerability")
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)

        elements = []
        self._build_header(elements, "Vulnerability Assessment Report", f"Target: {scan.target}", {
            "Scan ID": scan.id,
            "Scan Type": scan.scan_type if isinstance(scan.scan_type, str) else scan.scan_type.value,
            "Status": scan.status if isinstance(scan.status, str) else scan.status.value,
            "Date": scan.created_at.strftime("%Y-%m-%d %H:%M UTC"),
            "Total Findings": str(scan.total_findings),
        })

        if "summary" in sections:
            elements.append(Paragraph("Executive Summary", self.styles["SectionHeader"]))
            elements.append(Paragraph(
                f"A {scan.scan_type if isinstance(scan.scan_type, str) else scan.scan_type.value} "
                f"scan was conducted against <b>{scan.target}</b>. The scan identified "
                f"<b>{scan.total_findings}</b> findings across {len(scan.ports)} open ports, "
                f"including {scan.critical_count} critical and {scan.high_count} high-severity vulnerabilities.",
                self.styles["BodyText_Custom"]
            ))
            elements.append(Spacer(1, 8))
            self._severity_table(elements, {
                "critical": scan.critical_count, "high": scan.high_count,
                "medium": scan.medium_count, "low": scan.low_count,
            })

        if "findings" in sections and scan.ports:
            elements.append(Paragraph("Open Ports", self.styles["SectionHeader"]))
            data = [["Port", "Service", "Version", "State", "Risk"]]
            for p in scan.ports:
                data.append([
                    str(p.port_number), p.service_name or "—",
                    p.service_version or "—", p.state, (p.risk_level or "info").capitalize()
                ])
            t = Table(data, colWidths=[0.8 * inch, 1.2 * inch, 2 * inch, 0.8 * inch, 1 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 12))

        if "findings" in sections and scan.vulnerabilities:
            elements.append(Paragraph("Vulnerabilities", self.styles["SectionHeader"]))
            for v in sorted(scan.vulnerabilities, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                x.severity.value if hasattr(x.severity, 'value') else x.severity, 4
            )):
                sev = v.severity.value if hasattr(v.severity, 'value') else v.severity
                elements.append(Paragraph(
                    f"<b>{v.cve_id or 'N/A'}</b> — {v.title} "
                    f"[{sev.upper()}] CVSS: {v.cvss_score or 'N/A'}",
                    self.styles["SubHeader"]
                ))
                if v.description:
                    elements.append(Paragraph(v.description, self.styles["BodyText_Custom"]))
                if v.remediation:
                    elements.append(Paragraph(
                        f"<b>Remediation:</b> {v.remediation}", self.styles["BodyText_Custom"]
                    ))
                elements.append(Spacer(1, 6))

        doc.build(elements)
        logger.info(f"Generated vulnerability report: {filepath}")
        return filepath

    # ──── Incident Report ─────────────────────────────────────
    async def generate_incident_report(self, incident, sections: List[str]) -> str:
        filename = self._generate_filename("incident")
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)

        elements = []
        self._build_header(elements, "Incident Response Report", incident.title, {
            "Incident": incident.incident_number,
            "Severity": incident.severity.upper(),
            "Status": incident.status.value if hasattr(incident.status, 'value') else incident.status,
            "Date": incident.created_at.strftime("%Y-%m-%d %H:%M UTC"),
            "Affected Hosts": str(incident.affected_hosts),
            "Attack Phases": str(incident.attack_phases),
        })

        if "summary" in sections:
            elements.append(Paragraph("Executive Summary", self.styles["SectionHeader"]))
            summary = incident.ai_summary or incident.description or "No summary available."
            elements.append(Paragraph(summary, self.styles["BodyText_Custom"]))
            elements.append(Spacer(1, 8))

            if incident.root_cause:
                elements.append(Paragraph("Root Cause", self.styles["SubHeader"]))
                elements.append(Paragraph(incident.root_cause, self.styles["BodyText_Custom"]))
                elements.append(Spacer(1, 8))

        if "timeline" in sections and incident.timeline:
            elements.append(Paragraph("Attack Timeline", self.styles["SectionHeader"]))
            data = [["#", "Time", "Event", "Phase", "Severity"]]
            for t in sorted(incident.timeline, key=lambda x: x.sequence):
                data.append([
                    str(t.sequence),
                    t.timestamp.strftime("%H:%M:%S"),
                    t.event[:60] + ("..." if len(t.event) > 60 else ""),
                    t.phase or "—",
                    t.severity.capitalize(),
                ])
            tbl = Table(data, colWidths=[0.4 * inch, 0.9 * inch, 2.5 * inch, 1.3 * inch, 0.8 * inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(tbl)
            elements.append(Spacer(1, 12))

        if "remediation" in sections and incident.remediations:
            elements.append(Paragraph("Remediation Plan", self.styles["SectionHeader"]))
            data = [["Priority", "Action", "Impact", "Effort", "Status"]]
            for r in sorted(incident.remediations, key=lambda x: x.priority):
                data.append([
                    r.priority, r.action[:50] + ("..." if len(r.action) > 50 else ""),
                    r.impact or "—", r.effort or "—", r.status.capitalize(),
                ])
            tbl = Table(data, colWidths=[0.6 * inch, 2.2 * inch, 1.3 * inch, 0.7 * inch, 0.8 * inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(tbl)

        doc.build(elements)
        logger.info(f"Generated incident report: {filepath}")
        return filepath

    # ──── Forensic Report ─────────────────────────────────────
    async def generate_forensic_report(self, case, sections: List[str]) -> str:
        filename = self._generate_filename("forensic")
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)

        elements = []
        self._build_header(elements, "Digital Forensics Report", case.title, {
            "Case Number": case.case_number,
            "Status": case.status.value if hasattr(case.status, 'value') else case.status,
            "Date": case.created_at.strftime("%Y-%m-%d %H:%M UTC"),
            "Total Log Entries": str(case.total_logs),
            "Anomalies Detected": str(case.anomaly_count),
            "YARA Matches": str(case.yara_match_count),
        })

        if "summary" in sections:
            elements.append(Paragraph("Case Summary", self.styles["SectionHeader"]))
            elements.append(Paragraph(
                case.description or "No description provided.",
                self.styles["BodyText_Custom"]
            ))
            elements.append(Spacer(1, 8))

        if "findings" in sections and case.yara_matches:
            elements.append(Paragraph("Malware Detection — YARA Matches", self.styles["SectionHeader"]))
            data = [["Rule", "File", "Severity", "Confidence", "SHA-256"]]
            for m in case.yara_matches:
                data.append([
                    m.rule_name,
                    os.path.basename(m.file_path),
                    m.severity.capitalize(),
                    f"{m.confidence:.0%}" if m.confidence else "—",
                    (m.file_hash_sha256 or "—")[:16] + "...",
                ])
            tbl = Table(data, colWidths=[1.3 * inch, 1.3 * inch, 0.8 * inch, 0.8 * inch, 1.5 * inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(tbl)
            elements.append(Spacer(1, 12))

        if "findings" in sections and case.evidence:
            elements.append(Paragraph("Evidence Chain", self.styles["SectionHeader"]))
            data = [["Type", "Title", "Collected", "SHA-256"]]
            for e in case.evidence:
                data.append([
                    e.evidence_type.capitalize(),
                    e.title[:40] + ("..." if len(e.title) > 40 else ""),
                    e.collected_at.strftime("%Y-%m-%d %H:%M"),
                    (e.hash_sha256 or "—")[:16] + "...",
                ])
            tbl = Table(data, colWidths=[0.9 * inch, 2.5 * inch, 1.2 * inch, 1.3 * inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(tbl)

        doc.build(elements)
        logger.info(f"Generated forensic report: {filepath}")
        return filepath
