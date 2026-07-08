"""RCA engine — correlates scan results, forensic logs, and YARA matches into attack timelines."""

import logging
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from models.scan import Scan, Port, Vulnerability
from models.forensic import ForensicCase, LogEntry, YaraMatch

logger = logging.getLogger(__name__)

# ──── MITRE ATT&CK technique mapping ─────────────────────────
MITRE_MAPPING = {
    # Event keywords → (Technique ID, Phase)
    "ssh login": ("T1021.004", "Lateral Movement"),
    "ssh accepted": ("T1021.004", "Lateral Movement"),
    "failed password": ("T1110", "Credential Access"),
    "brute force": ("T1110", "Credential Access"),
    "privilege escalation": ("T1068", "Privilege Escalation"),
    "sudo": ("T1548.003", "Privilege Escalation"),
    "uid changed": ("T1548", "Privilege Escalation"),
    "crontab": ("T1053.003", "Persistence"),
    "cron job": ("T1053.003", "Persistence"),
    "reverse shell": ("T1059.004", "Execution"),
    "bind shell": ("T1059.004", "Execution"),
    "port scan": ("T1046", "Discovery"),
    "network scan": ("T1046", "Discovery"),
    "nmap": ("T1046", "Discovery"),
    "firewall rule": ("T1562.004", "Defense Evasion"),
    "iptables": ("T1562.004", "Defense Evasion"),
    "dns tunnel": ("T1071.004", "Command and Control"),
    "dns query anomaly": ("T1071.004", "Command and Control"),
    "c2": ("T1071", "Command and Control"),
    "beacon": ("T1071", "Command and Control"),
    "exfiltration": ("T1041", "Exfiltration"),
    "data exfil": ("T1041", "Exfiltration"),
    "redis": ("T1190", "Initial Access"),
    "unauthenticated": ("T1190", "Initial Access"),
    "default credentials": ("T1078", "Initial Access"),
    "webshell": ("T1505.003", "Persistence"),
    "malware": ("T1204", "Execution"),
    "yara match": ("T1204", "Execution"),
    "lateral movement": ("T1021", "Lateral Movement"),
    "mimikatz": ("T1003", "Credential Access"),
    "credential harvesting": ("T1003", "Credential Access"),
}


class RCAEngine:
    """Correlates events from multiple sources into a unified attack timeline."""

    async def correlate(
        self,
        incident_id: str,
        scan_ids: List[str],
        forensic_case_id: Optional[str],
        db: AsyncSession,
    ) -> List[Dict]:
        """Pull data from scans and forensic cases, then build a correlated timeline."""
        events = []

        # ── Pull scan data ────────────────────────────────────
        for scan_id in scan_ids:
            result = await db.execute(
                select(Scan).where(Scan.id == scan_id)
                .options(selectinload(Scan.ports), selectinload(Scan.vulnerabilities))
            )
            scan = result.scalars().first()
            if not scan:
                continue

            # Convert open risky ports to events
            for port in scan.ports:
                if port.risk_level in ("critical", "high"):
                    ts = scan.started_at or scan.created_at
                    mitre_id, phase = self._map_mitre(f"{port.service_name} open {port.risk_level}")
                    events.append({
                        "timestamp": ts,
                        "event": f"Exposed {port.service_name} on port {port.port_number} ({port.risk_level} risk)",
                        "details": f"Service: {port.service_name} {port.service_version or ''}, State: {port.state}, "
                                   f"Host: {scan.target}",
                        "severity": port.risk_level,
                        "phase": phase,
                        "mitre_id": mitre_id,
                        "source_host": scan.target,
                        "dest_host": None,
                    })

            # Convert vulnerabilities to events
            for vuln in scan.vulnerabilities:
                ts = vuln.discovered_at or scan.created_at
                mitre_id, phase = self._map_mitre(vuln.title)
                events.append({
                    "timestamp": ts,
                    "event": f"Vulnerability: {vuln.title} (CVSS {vuln.cvss_score})",
                    "details": vuln.description,
                    "severity": vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity,
                    "phase": phase or "Initial Access",
                    "mitre_id": mitre_id or "T1190",
                    "source_host": scan.target,
                    "dest_host": None,
                })

        # ── Pull forensic log data ────────────────────────────
        if forensic_case_id:
            result = await db.execute(
                select(ForensicCase).where(ForensicCase.id == forensic_case_id)
                .options(
                    selectinload(ForensicCase.log_entries),
                    selectinload(ForensicCase.yara_matches),
                )
            )
            case = result.scalars().first()
            if case:
                # Anomalous log entries
                for entry in case.log_entries:
                    if entry.is_anomaly:
                        mitre_id, phase = self._map_mitre(f"{entry.event_type} {entry.raw_log or ''}")
                        events.append({
                            "timestamp": entry.timestamp,
                            "event": f"{entry.event_type}",
                            "details": entry.raw_log[:500] if entry.raw_log else None,
                            "severity": entry.severity,
                            "phase": phase,
                            "mitre_id": mitre_id,
                            "source_host": entry.source_ip,
                            "dest_host": entry.destination_ip,
                        })

                # YARA matches
                for match in case.yara_matches:
                    mitre_id, phase = self._map_mitre(f"yara match {match.rule_name}")
                    events.append({
                        "timestamp": match.detected_at,
                        "event": f"YARA match: {match.rule_name} on {match.file_path}",
                        "details": f"SHA256: {match.file_hash_sha256 or 'N/A'}, "
                                   f"Confidence: {match.confidence or 'N/A'}",
                        "severity": match.severity,
                        "phase": phase or "Execution",
                        "mitre_id": mitre_id or "T1204",
                        "source_host": None,
                        "dest_host": None,
                    })

        # ── Sort by timestamp and assign phases ───────────────
        events.sort(key=lambda e: e["timestamp"])

        # If no explicit phases were mapped, infer a kill chain order
        if events and not any(e.get("phase") for e in events):
            events = self._infer_kill_chain(events)

        logger.info(f"Correlated {len(events)} events for incident {incident_id}")
        return events

    def _map_mitre(self, text: str) -> tuple:
        """Map event text to MITRE ATT&CK technique ID and phase."""
        if not text:
            return None, None
        lower = text.lower()
        for keyword, (tech_id, phase) in MITRE_MAPPING.items():
            if keyword in lower:
                return tech_id, phase
        return None, None

    def _infer_kill_chain(self, events: List[Dict]) -> List[Dict]:
        """Apply a basic kill chain order when MITRE mapping is incomplete."""
        phases = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        ]
        n = len(events)
        for i, event in enumerate(events):
            if not event.get("phase"):
                phase_idx = min(int(i / max(n, 1) * len(phases)), len(phases) - 1)
                event["phase"] = phases[phase_idx]
        return events
