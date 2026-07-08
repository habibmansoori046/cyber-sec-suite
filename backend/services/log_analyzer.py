"""Log analyzer service — multi-format log parsing with anomaly detection."""

import re
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional
from collections import Counter

logger = logging.getLogger(__name__)

# ──── Suspicious patterns for anomaly scoring ─────────────────
SUSPICIOUS_PATTERNS = [
    (r"failed\s+(password|login|auth)", "Failed authentication", "high", 0.7),
    (r"(root|admin)\s+login", "Privileged account login", "high", 0.6),
    (r"(sudo|su)\s*:.*COMMAND", "Privilege escalation command", "medium", 0.5),
    (r"(reverse\s+shell|bind\s+shell|/bin/(ba)?sh\s+-i)", "Shell spawning", "critical", 0.95),
    (r"(wget|curl|nc|ncat)\s+.*(http|ftp|\/tmp)", "Remote file download / netcat", "high", 0.8),
    (r"(cron|crontab).*modified", "Crontab modification", "medium", 0.6),
    (r"(iptables|firewall|ufw).*(-A|-D|add|delete|allow|deny)", "Firewall rule change", "high", 0.75),
    (r"(segfault|segmentation\s+fault|core\s+dump)", "Process crash", "medium", 0.4),
    (r"(\/tmp\/\.\w+|\/dev\/shm\/)", "Hidden file in temp dir", "high", 0.85),
    (r"(exfiltrat|c2|beacon|callback|command.and.control)", "C2 / exfiltration indicator", "critical", 0.9),
    (r"(port\s+scan|nmap|masscan|zmap)", "Port scan activity", "medium", 0.5),
    (r"(dns.*txt.*query|dns.*tunnel)", "DNS tunneling indicator", "high", 0.8),
    (r"(privilege.escalat|privesc|CVE-\d{4}-\d+)", "Exploit / CVE reference", "critical", 0.85),
    (r"(unauthorized|permission\s+denied|access\s+denied).*root", "Unauthorized root access attempt", "high", 0.7),
    (r"(ssh|sshd).*accepted.*from\s+\d+\.\d+\.\d+\.\d+", "SSH login from external IP", "medium", 0.3),
]

# Syslog severity mapping
SYSLOG_FACILITY_MAP = {
    "emerg": "critical", "alert": "critical", "crit": "critical",
    "err": "high", "error": "high", "warning": "medium", "warn": "medium",
    "notice": "low", "info": "info", "debug": "info",
}


class LogAnalyzer:
    """Multi-format log parser with pattern-based anomaly detection."""

    async def analyze(self, raw_content: str, filename: str) -> List[Dict]:
        """Parse and analyze log content, returning structured entries with anomaly scores."""
        lines = raw_content.strip().split("\n")
        if not lines:
            return []

        # Detect format
        fmt = self._detect_format(lines[0], filename)
        logger.info(f"Detected log format: {fmt} for {filename} ({len(lines)} lines)")

        if fmt == "json":
            entries = self._parse_json_logs(lines)
        elif fmt == "csv":
            entries = self._parse_csv_logs(lines)
        else:
            entries = self._parse_syslog(lines)

        # Run anomaly detection on all entries
        for entry in entries:
            score, indicators = self._score_anomaly(entry.get("raw_log", ""))
            entry["anomaly_score"] = score
            entry["is_anomaly"] = score >= 0.5
            if indicators:
                entry["parsed_data"]["indicators"] = indicators

        logger.info(f"Parsed {len(entries)} entries, {sum(1 for e in entries if e['is_anomaly'])} anomalies")
        return entries

    def _detect_format(self, first_line: str, filename: str) -> str:
        """Auto-detect log format from first line and filename."""
        if filename.endswith(".json") or filename.endswith(".jsonl"):
            return "json"
        if filename.endswith(".csv") or filename.endswith(".tsv"):
            return "csv"
        try:
            json.loads(first_line)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
        if "," in first_line and first_line.count(",") >= 3:
            return "csv"
        return "syslog"

    # ──── Syslog Parser ───────────────────────────────────────
    SYSLOG_RE = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    )
    # Also handle ISO-format timestamps
    ISO_SYSLOG_RE = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    )

    def _parse_syslog(self, lines: List[str]) -> List[Dict]:
        entries = []
        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = self.ISO_SYSLOG_RE.match(line) or self.SYSLOG_RE.match(line)
            if match:
                d = match.groupdict()
                ts = self._parse_timestamp(d["timestamp"])
                severity = self._infer_severity(d.get("message", ""))
                ip = self._extract_ip(d.get("message", ""))

                entries.append({
                    "timestamp": ts,
                    "source_ip": ip or d.get("host"),
                    "destination_ip": self._extract_dest_ip(d.get("message", "")),
                    "event_type": d.get("process", "syslog"),
                    "severity": severity,
                    "raw_log": line,
                    "parsed_data": {
                        "host": d.get("host"),
                        "process": d.get("process"),
                        "pid": d.get("pid"),
                        "message": d.get("message"),
                    },
                })
            else:
                # Fallback: unparseable line
                entries.append({
                    "timestamp": datetime.utcnow(),
                    "source_ip": None,
                    "destination_ip": None,
                    "event_type": "raw",
                    "severity": self._infer_severity(line),
                    "raw_log": line,
                    "parsed_data": {"raw": line},
                })
        return entries

    # ──── JSON Log Parser ─────────────────────────────────────
    def _parse_json_logs(self, lines: List[str]) -> List[Dict]:
        entries = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts_raw = obj.get("timestamp") or obj.get("@timestamp") or obj.get("time") or obj.get("date")
            ts = self._parse_timestamp(ts_raw) if ts_raw else datetime.utcnow()
            severity = obj.get("severity") or obj.get("level") or obj.get("priority") or "info"
            severity = SYSLOG_FACILITY_MAP.get(severity.lower(), severity.lower()) if isinstance(severity, str) else "info"

            entries.append({
                "timestamp": ts,
                "source_ip": obj.get("source_ip") or obj.get("src") or obj.get("client_ip"),
                "destination_ip": obj.get("dest_ip") or obj.get("dst"),
                "event_type": obj.get("event_type") or obj.get("event") or obj.get("action") or "json_log",
                "severity": severity,
                "raw_log": line,
                "parsed_data": obj,
            })
        return entries

    # ──── CSV Log Parser ──────────────────────────────────────
    def _parse_csv_logs(self, lines: List[str]) -> List[Dict]:
        entries = []
        if len(lines) < 2:
            return entries

        # First line is header
        headers = [h.strip().lower() for h in lines[0].split(",")]
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            values = [v.strip().strip('"') for v in line.split(",")]
            row = dict(zip(headers, values))

            ts_raw = row.get("timestamp") or row.get("time") or row.get("date")
            ts = self._parse_timestamp(ts_raw) if ts_raw else datetime.utcnow()

            entries.append({
                "timestamp": ts,
                "source_ip": row.get("source_ip") or row.get("src_ip") or row.get("source"),
                "destination_ip": row.get("dest_ip") or row.get("dst_ip") or row.get("destination"),
                "event_type": row.get("event_type") or row.get("event") or row.get("action") or "csv_log",
                "severity": row.get("severity") or row.get("level") or "info",
                "raw_log": line,
                "parsed_data": row,
            })
        return entries

    # ──── Anomaly Scoring ─────────────────────────────────────
    def _score_anomaly(self, raw_log: str) -> tuple:
        """Score a log line for anomalous behavior. Returns (score, indicators)."""
        if not raw_log:
            return 0.0, []

        max_score = 0.0
        indicators = []
        lower = raw_log.lower()

        for pattern, label, severity, weight in SUSPICIOUS_PATTERNS:
            if re.search(pattern, lower):
                indicators.append({"pattern": label, "severity": severity})
                max_score = max(max_score, weight)

        return round(max_score, 2), indicators

    # ──── Helpers ──────────────────────────────────────────────
    IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    def _extract_ip(self, text: str) -> Optional[str]:
        match = self.IP_RE.search(text)
        return match.group(1) if match else None

    def _extract_dest_ip(self, text: str) -> Optional[str]:
        ips = self.IP_RE.findall(text)
        return ips[1] if len(ips) >= 2 else None

    def _infer_severity(self, message: str) -> str:
        lower = message.lower()
        for kw, sev in [
            ("critical", "critical"), ("emergency", "critical"), ("fatal", "critical"),
            ("error", "high"), ("fail", "high"), ("denied", "high"), ("attack", "high"),
            ("warning", "medium"), ("warn", "medium"), ("unusual", "medium"),
            ("notice", "low"), ("info", "info"),
        ]:
            if kw in lower:
                return sev
        return "info"

    def _parse_timestamp(self, ts_str) -> datetime:
        if isinstance(ts_str, datetime):
            return ts_str
        if not isinstance(ts_str, str):
            return datetime.utcnow()

        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.utcnow().year)
                return dt
            except ValueError:
                continue
        return datetime.utcnow()
