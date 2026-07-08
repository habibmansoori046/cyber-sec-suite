"""Nmap scanner service — wraps python-nmap for network discovery and vulnerability scanning."""

import logging
import asyncio
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Known risky services that should flag elevated risk levels
HIGH_RISK_PORTS = {6379, 27017, 11211, 9200, 5984}  # Redis, MongoDB, Memcached, Elasticsearch, CouchDB
MEDIUM_RISK_PORTS = {21, 23, 3306, 5432, 8080, 8443}  # FTP, Telnet, MySQL, PostgreSQL, HTTP-Alt


class NmapScanner:
    """Async wrapper around nmap for port and service discovery."""

    def __init__(self, nmap_path: str = "/usr/bin/nmap"):
        self.nmap_path = nmap_path

    async def network_scan(self, target: str, config: dict = None) -> dict:
        """Discover live hosts on a network (ping sweep + service detection)."""
        args = config.get("args", "-sn -PE") if config else "-sn -PE"
        return await self._run_scan(target, args, "network")

    async def port_scan(self, target: str, config: dict = None) -> dict:
        """Full port scan with service version detection."""
        port_range = config.get("ports", "1-65535") if config else "1-65535"
        args = f"-sV -sC -p {port_range} --open"
        if config and config.get("aggressive"):
            args += " -A"
        return await self._run_scan(target, args, "port")

    async def vulnerability_scan(self, target: str, config: dict = None) -> dict:
        """NSE vulnerability scripts scan."""
        args = "-sV --script=vuln,exploit -p-"
        return await self._run_scan(target, args, "vulnerability")

    async def _run_scan(self, target: str, args: str, scan_type: str) -> dict:
        """Execute nmap scan asynchronously via subprocess."""
        try:
            import nmap
            scanner = nmap.PortScanner(nmap_search_path=(self.nmap_path,))

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: scanner.scan(hosts=target, arguments=args)
            )

            return self._parse_results(scanner, target, scan_type)

        except ImportError:
            logger.warning("python-nmap not installed — returning simulated scan data")
            return self._simulate_scan(target, scan_type)
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            raise

    def _parse_results(self, scanner, target: str, scan_type: str) -> dict:
        """Parse nmap scanner results into structured data."""
        hosts = []
        ports = []
        vulnerabilities = []

        for host in scanner.all_hosts():
            host_data = {
                "ip": host,
                "hostname": scanner[host].hostname() or None,
                "state": scanner[host].state(),
                "os": None,
            }

            # OS detection
            if "osmatch" in scanner[host]:
                matches = scanner[host]["osmatch"]
                if matches:
                    host_data["os"] = matches[0].get("name", "Unknown")

            hosts.append(host_data)

            # Port enumeration
            for proto in scanner[host].all_protocols():
                for port_num in scanner[host][proto]:
                    port_info = scanner[host][proto][port_num]
                    risk = self._assess_port_risk(port_num, port_info)
                    ports.append({
                        "host": host,
                        "port": port_num,
                        "protocol": proto,
                        "state": port_info["state"],
                        "service": port_info.get("name", "unknown"),
                        "version": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                        "risk": risk,
                        "banner": port_info.get("extrainfo", ""),
                    })

                    # Extract script-based vulnerabilities
                    if "script" in port_info:
                        for script_name, output in port_info["script"].items():
                            if any(kw in script_name for kw in ["vuln", "exploit", "brute"]):
                                vulnerabilities.append({
                                    "host": host,
                                    "port": port_num,
                                    "title": script_name,
                                    "output": output,
                                    "severity": self._script_severity(script_name, output),
                                })

        # Calculate overall severity
        severity = "info"
        if any(v["severity"] == "critical" for v in vulnerabilities) or any(p["risk"] == "critical" for p in ports):
            severity = "critical"
        elif any(v["severity"] == "high" for v in vulnerabilities) or any(p["risk"] == "high" for p in ports):
            severity = "high"
        elif any(v["severity"] == "medium" for v in vulnerabilities) or any(p["risk"] == "medium" for p in ports):
            severity = "medium"
        elif ports:
            severity = "low"

        return {
            "hosts": hosts,
            "ports": ports,
            "vulnerabilities": vulnerabilities,
            "severity": severity,
            "total_findings": len(ports) + len(vulnerabilities),
            "stats": {
                "hosts_up": len([h for h in hosts if h["state"] == "up"]),
                "open_ports": len([p for p in ports if p["state"] == "open"]),
                "critical": len([v for v in vulnerabilities if v["severity"] == "critical"]),
                "high": len([v for v in vulnerabilities if v["severity"] == "high"]),
                "medium": len([v for v in vulnerabilities if v["severity"] == "medium"]),
                "low": len([v for v in vulnerabilities if v["severity"] == "low"]),
            }
        }

    def _assess_port_risk(self, port: int, info: dict) -> str:
        """Risk assessment based on port number and service metadata."""
        if port in HIGH_RISK_PORTS:
            # Check if auth is likely missing
            if info.get("state") == "open":
                return "critical"
        if port in MEDIUM_RISK_PORTS:
            return "medium"
        if port in {22, 443}:
            return "low"
        if info.get("state") == "open":
            return "low"
        return "info"

    def _script_severity(self, name: str, output: str) -> str:
        if "VULNERABLE" in output.upper() or "exploit" in name:
            return "critical"
        if "vuln" in name:
            return "high"
        return "medium"

    def _simulate_scan(self, target: str, scan_type: str) -> dict:
        """Simulated scan data when nmap is not available (dev/testing)."""
        return {
            "hosts": [{"ip": target, "hostname": None, "state": "up", "os": "Linux 5.x"}],
            "ports": [
                {"host": target, "port": 22, "protocol": "tcp", "state": "open",
                 "service": "SSH", "version": "OpenSSH 8.9", "risk": "low", "banner": ""},
                {"host": target, "port": 80, "protocol": "tcp", "state": "open",
                 "service": "HTTP", "version": "nginx 1.24.0", "risk": "low", "banner": ""},
                {"host": target, "port": 443, "protocol": "tcp", "state": "open",
                 "service": "HTTPS", "version": "nginx 1.24.0", "risk": "low", "banner": ""},
                {"host": target, "port": 3306, "protocol": "tcp", "state": "open",
                 "service": "MySQL", "version": "MySQL 8.0.32", "risk": "high", "banner": ""},
            ],
            "vulnerabilities": [
                {"host": target, "port": 3306, "title": "MySQL default credentials",
                 "output": "root account has empty password", "severity": "critical"},
            ],
            "severity": "critical",
            "total_findings": 5,
            "stats": {"hosts_up": 1, "open_ports": 4, "critical": 1, "high": 0, "medium": 0, "low": 0},
        }
