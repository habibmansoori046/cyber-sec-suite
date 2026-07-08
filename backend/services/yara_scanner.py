"""YARA scanner service — rule-based malware and IOC detection."""

import os
import hashlib
import logging
import asyncio
from typing import List, Dict
from datetime import datetime

from config import settings

logger = logging.getLogger(__name__)

# ──── Built-in starter rules (extend with domain-specific YARA) ─────
BUILTIN_RULES_SOURCE = """
rule Suspicious_Shell_Script {
    meta:
        description = "Detects shell scripts with reverse shell patterns"
        severity = "critical"
        author = "CyberSec Suite"
    strings:
        $bash_i = "/bin/bash -i" ascii
        $nc_shell = "nc -e /bin/sh" ascii
        $python_rev = "socket.socket" ascii
        $perl_rev = "exec(\"/bin/sh\")" ascii
        $dev_tcp = "/dev/tcp/" ascii
        $mkfifo = "mkfifo /tmp/" ascii
    condition:
        any of them
}

rule Persistence_Crontab {
    meta:
        description = "Detects crontab-based persistence mechanisms"
        severity = "high"
        author = "CyberSec Suite"
    strings:
        $cron1 = "crontab -" ascii
        $cron2 = "/etc/cron" ascii
        $cron3 = "/var/spool/cron" ascii
        $hidden_exec = "/tmp/." ascii
        $beacon = "beacon" ascii nocase
    condition:
        ($cron1 or $cron2 or $cron3) and ($hidden_exec or $beacon)
}

rule Credential_Harvesting {
    meta:
        description = "Detects credential harvesting tools and patterns"
        severity = "critical"
        author = "CyberSec Suite"
    strings:
        $mimikatz = "mimikatz" ascii nocase
        $shadow = "/etc/shadow" ascii
        $sam = "SAM" ascii
        $lsass = "lsass" ascii nocase
        $hashdump = "hashdump" ascii nocase
        $credential = "credential" ascii nocase
    condition:
        2 of them
}

rule Webshell_Generic {
    meta:
        description = "Detects common webshell patterns"
        severity = "critical"
        author = "CyberSec Suite"
    strings:
        $php_exec = "<?php" ascii
        $eval = "eval(" ascii
        $system = "system(" ascii
        $passthru = "passthru(" ascii
        $shell_exec = "shell_exec(" ascii
        $base64 = "base64_decode(" ascii
    condition:
        $php_exec and 2 of ($eval, $system, $passthru, $shell_exec, $base64)
}

rule Suspicious_Encoded_Payload {
    meta:
        description = "Detects base64-encoded payloads commonly used in attacks"
        severity = "high"
        author = "CyberSec Suite"
    strings:
        $b64_bash = "YmFzaCAt" ascii
        $b64_python = "cHl0aG9u" ascii
        $b64_wget = "d2dldCA" ascii
        $b64_curl = "Y3VybCA" ascii
        $powershell_enc = "-EncodedCommand" ascii nocase
        $powershell_b64 = "FromBase64String" ascii
    condition:
        any of them
}
"""


class YaraScanner:
    """YARA-based file and memory scanner for malware / IOC detection."""

    def __init__(self):
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules from built-in source and rules directory."""
        try:
            import yara

            sources = {"builtin": BUILTIN_RULES_SOURCE}

            # Load custom rules from disk if the directory exists
            rules_dir = settings.YARA_RULES_DIR
            if os.path.isdir(rules_dir):
                for fname in os.listdir(rules_dir):
                    if fname.endswith((".yar", ".yara")):
                        fpath = os.path.join(rules_dir, fname)
                        with open(fpath, "r") as f:
                            sources[fname] = f.read()
                        logger.info(f"Loaded YARA rule file: {fname}")

            self.rules = yara.compile(sources=sources)
            logger.info(f"YARA rules compiled: {len(sources)} source(s)")

        except ImportError:
            logger.warning("yara-python not installed — scanner will use pattern-based fallback")
            self.rules = None
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self.rules = None

    async def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a file against loaded YARA rules."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Compute hashes
        sha256, md5 = self._hash_file(file_path)

        if self.rules:
            return await self._yara_scan(file_path, sha256, md5)
        else:
            return await self._fallback_scan(file_path, sha256, md5)

    async def _yara_scan(self, file_path: str, sha256: str, md5: str) -> List[Dict]:
        """Scan using compiled YARA rules."""
        import yara

        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(None, lambda: self.rules.match(file_path))

        results = []
        for match in matches:
            meta = match.meta or {}
            results.append({
                "rule": match.rule,
                "sha256": sha256,
                "md5": md5,
                "severity": meta.get("severity", "high"),
                "confidence": self._match_confidence(match),
                "strings": [
                    {"offset": s[0], "identifier": s[1], "data": s[2].decode("utf-8", errors="replace")[:100]}
                    for s in match.strings[:10]  # Limit to 10 string matches
                ],
                "meta": meta,
                "tags": list(match.tags) if match.tags else [],
                "detected_at": datetime.utcnow().isoformat(),
            })

        return results

    async def _fallback_scan(self, file_path: str, sha256: str, md5: str) -> List[Dict]:
        """Pattern-based fallback when yara-python is not available."""
        results = []

        try:
            with open(file_path, "rb") as f:
                content = f.read(1024 * 1024)  # Read first 1MB
        except Exception:
            return results

        text = content.decode("utf-8", errors="replace")

        patterns = [
            (r"/bin/bash\s+-i", "Suspicious_Shell_Script", "critical", 0.95),
            (r"nc\s+-e\s+/bin/sh", "Suspicious_Shell_Script", "critical", 0.95),
            (r"/dev/tcp/", "Suspicious_Shell_Script", "critical", 0.9),
            (r"crontab.*(/tmp/\.|beacon)", "Persistence_Crontab", "high", 0.85),
            (r"mimikatz|/etc/shadow.*dump|hashdump", "Credential_Harvesting", "critical", 0.9),
            (r"<\?php.*(eval|system|passthru|shell_exec)\(", "Webshell_Generic", "critical", 0.9),
            (r"(YmFzaCAt|cHl0aG9u|d2dldCA|Y3VybCA)", "Suspicious_Encoded_Payload", "high", 0.8),
        ]

        import re
        matched_rules = set()
        for pattern, rule_name, severity, confidence in patterns:
            if re.search(pattern, text, re.IGNORECASE) and rule_name not in matched_rules:
                matched_rules.add(rule_name)
                results.append({
                    "rule": rule_name,
                    "sha256": sha256,
                    "md5": md5,
                    "severity": severity,
                    "confidence": confidence,
                    "strings": [],
                    "meta": {"description": f"Pattern match: {rule_name}", "author": "CyberSec Suite (fallback)"},
                    "tags": ["fallback"],
                    "detected_at": datetime.utcnow().isoformat(),
                })

        return results

    def _match_confidence(self, match) -> float:
        """Estimate confidence based on number of matched strings."""
        n = len(match.strings) if match.strings else 0
        if n >= 5:
            return 0.98
        if n >= 3:
            return 0.92
        if n >= 2:
            return 0.85
        return 0.7

    def _hash_file(self, file_path: str) -> tuple:
        """Compute SHA-256 and MD5 hashes for a file."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest(), md5.hexdigest()
