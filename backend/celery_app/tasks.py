"""Celery tasks — full automated pipeline: scan -> alerts -> forensic case -> RCA -> remediation."""

import os
import logging
import uuid
from datetime import datetime, timedelta

from celery_app import celery_app

logger = logging.getLogger(__name__)


def _sync_url():
    url = os.getenv("DATABASE_URL", "postgresql+asyncpg://cybersec:changeme@db:5432/cybersec")
    return url.replace("postgresql+asyncpg://", "postgresql://")


def _get_sync_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(_sync_url(), pool_pre_ping=True)
    return sessionmaker(bind=engine)()


def _create_alert(session, severity, message, source, source_id=None):
    from models.alert import Alert
    alert = Alert(severity=severity, message=message, source=source, source_id=source_id)
    session.add(alert)
    return alert


@celery_app.task(bind=True, name="celery_app.tasks.run_scan_task", max_retries=2)
def run_scan_task(self, scan_id, target, scan_type, config=None):
    """Execute scan and auto-populate ALL modules with results."""
    logger.info(f"Starting {scan_type} scan on {target} (scan_id={scan_id})")
    session = _get_sync_session()

    try:
        from models.scan import Scan, ScanStatus, Port, Vulnerability, Severity
        from models.forensic import ForensicCase, CaseStatus, LogEntry, Evidence
        from models.rca import Incident, IncidentStatus, RCATimeline, Remediation

        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {"error": "Scan not found"}

        scan.status = ScanStatus.RUNNING
        scan.progress = 10
        session.commit()

        # STEP 1: Run nmap
        scan_results = _run_nmap(target, scan_type)
        scan.progress = 50
        session.commit()

        # Check if scan returned an error (host unreachable, nmap failed, etc.)
        if scan_results.get("error") or scan_results.get("warning"):
            msg = scan_results.get("error") or scan_results.get("warning", "")
            if not scan_results["ports"] and not scan_results.get("vulnerabilities"):
                scan.status = ScanStatus.COMPLETED
                scan.total_findings = 0
                scan.severity = "info"
                scan.completed_at = datetime.utcnow()
                scan.duration_seconds = int((scan.completed_at - (scan.started_at or scan.created_at)).total_seconds())
                scan.progress = 100
                scan.raw_output = msg
                _create_alert(session, "info", f"Scan of {target}: {msg}", "Attack Simulation", scan_id)
                session.commit()
                return {"scan_id": scan_id, "findings": 0, "severity": "info", "message": msg}

        # STEP 2: Store ports and vulnerabilities
        crit = high = med = low = 0

        for p in scan_results["ports"]:
            port = Port(
                scan_id=scan_id, port_number=p["port"], protocol=p.get("protocol", "tcp"),
                state=p["state"], service_name=p.get("service"), service_version=p.get("version"),
                risk_level=p.get("risk", "info"), banner=p.get("banner"),
            )
            session.add(port)
            if p.get("risk") == "critical": crit += 1
            elif p.get("risk") == "high": high += 1
            elif p.get("risk") == "medium": med += 1
            elif p.get("risk") == "low": low += 1

        for v in scan_results.get("vulnerabilities", []):
            sev = v.get("severity", "medium")
            vuln = Vulnerability(
                scan_id=scan_id, title=v["title"],
                severity=Severity(sev) if sev in [e.value for e in Severity] else Severity.MEDIUM,
                cvss_score=v.get("cvss"), description=v.get("description") or v.get("output", ""),
                affected_component=f"{v.get('port', '?')}/{v.get('protocol', 'tcp')}", status="open",
            )
            session.add(vuln)
            if sev == "critical": crit += 1
            elif sev == "high": high += 1
            elif sev == "medium": med += 1

        total = len(scan_results["ports"]) + len(scan_results.get("vulnerabilities", []))
        if crit > 0: overall_sev = "critical"
        elif high > 0: overall_sev = "high"
        elif med > 0: overall_sev = "medium"
        elif total > 0: overall_sev = "low"
        else: overall_sev = "info"

        scan.total_findings = total
        scan.critical_count = crit
        scan.high_count = high
        scan.medium_count = med
        scan.low_count = low
        scan.severity = overall_sev
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.duration_seconds = int((scan.completed_at - (scan.started_at or scan.created_at)).total_seconds())
        scan.progress = 70
        session.commit()

        # STEP 3: Create alerts
        for p in scan_results["ports"]:
            if p.get("risk") in ("critical", "high"):
                _create_alert(session, p["risk"],
                    f"Exposed {p['service']} on port {p['port']} ({p.get('version', '?')}) — {p['risk']} risk",
                    "Attack Simulation", scan_id)

        for v in scan_results.get("vulnerabilities", []):
            _create_alert(session, v.get("severity", "medium"),
                f"Vulnerability: {v['title']} on {target}:{v.get('port', '?')}",
                "Attack Simulation", scan_id)

        if total > 0:
            _create_alert(session, overall_sev,
                f"Scan completed on {target}: {total} findings ({crit} critical, {high} high, {med} medium)",
                "Attack Simulation", scan_id)
        session.commit()

        # STEP 4: Auto-create forensic case
        forensic_case_id = None
        if total > 0:
            case = ForensicCase(
                case_number=f"FC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
                title=f"Auto: Scan findings on {target}",
                description=f"From {scan_type} scan. {total} findings ({crit} critical, {high} high).",
                status=CaseStatus.IN_PROGRESS,
                total_logs=len(scan_results["ports"]) + len(scan_results.get("vulnerabilities", [])),
                anomaly_count=crit + high, yara_match_count=0,
            )
            session.add(case)
            session.flush()
            forensic_case_id = case.id

            for p in scan_results["ports"]:
                session.add(LogEntry(
                    case_id=case.id, timestamp=datetime.utcnow(), source_ip=target,
                    event_type=f"Open port: {p['port']}/{p.get('protocol', 'tcp')}",
                    severity=p.get("risk", "info"),
                    raw_log=f"Port {p['port']} ({p.get('service', '?')}): {p.get('version', 'N/A')} — risk: {p.get('risk')}",
                    parsed_data=p, is_anomaly=p.get("risk") in ("critical", "high"),
                    anomaly_score=0.9 if p.get("risk") == "critical" else 0.7 if p.get("risk") == "high" else 0.3,
                ))

            for v in scan_results.get("vulnerabilities", []):
                session.add(LogEntry(
                    case_id=case.id, timestamp=datetime.utcnow(), source_ip=target,
                    event_type=f"Vuln: {v['title']}", severity=v.get("severity", "medium"),
                    raw_log=v.get("description", ""), parsed_data=v,
                    is_anomaly=True, anomaly_score=0.95,
                ))

            session.add(Evidence(
                case_id=case.id, evidence_type="scan_result",
                title=f"Nmap {scan_type} scan of {target}",
                description=f"{total} findings: {crit}C {high}H {med}M {low}L",
            ))
            session.commit()
            logger.info(f"Auto-created forensic case {case.case_number}")

        # STEP 5: Auto-create RCA incident
        if crit > 0 or high > 0:
            incident = Incident(
                incident_number=f"INC-{datetime.now().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}",
                title=f"Security findings on {target} — {crit} critical, {high} high",
                description=f"Auto-generated from {scan_type} scan. {total} findings. Review required.",
                severity=overall_sev, status=IncidentStatus.INVESTIGATING,
                scan_ids=[scan_id], forensic_case_id=forensic_case_id,
            )
            session.add(incident)
            session.flush()

            mitre_map = {
                "redis": ("T1190", "Initial Access", "Unauthenticated Redis allows RCE"),
                "mongodb": ("T1190", "Initial Access", "Unauthenticated MongoDB exposes all data"),
                "mysql": ("T1078", "Initial Access", "Database may have default credentials"),
                "postgresql": ("T1078", "Initial Access", "Database may have default credentials"),
                "ssh": ("T1021.004", "Lateral Movement", "SSH exposed — check auth config"),
                "ftp": ("T1021", "Lateral Movement", "FTP often allows anonymous access"),
                "telnet": ("T1021", "Lateral Movement", "Telnet sends credentials in cleartext"),
                "http": ("T1190", "Initial Access", "Web service — check for CVEs"),
                "elasticsearch": ("T1190", "Initial Access", "Unauthenticated Elasticsearch"),
                "memcached": ("T1190", "Initial Access", "Unauthenticated Memcached"),
            }

            seq = 1
            hosts = set()
            for p in scan_results["ports"]:
                if p.get("risk") in ("critical", "high", "medium"):
                    svc = (p.get("service") or "").lower()
                    mid, phase, detail = mitre_map.get(svc, ("T1046", "Discovery", f"Open port: {p['port']}"))
                    session.add(RCATimeline(
                        incident_id=incident.id, sequence=seq, timestamp=datetime.utcnow(),
                        event=f"Exposed {p.get('service', 'service')} on port {p['port']} ({p.get('risk')} risk)",
                        details=f"{detail}. Version: {p.get('version', '?')}, Host: {target}",
                        severity=p.get("risk", "medium"), phase=phase,
                        mitre_technique_id=mid, source_host=target,
                    ))
                    hosts.add(target)
                    seq += 1

            for v in scan_results.get("vulnerabilities", []):
                session.add(RCATimeline(
                    incident_id=incident.id, sequence=seq, timestamp=datetime.utcnow(),
                    event=f"Vulnerability: {v['title']}", details=v.get("description", ""),
                    severity=v.get("severity", "medium"), phase="Initial Access",
                    mitre_technique_id="T1190", source_host=target,
                ))
                seq += 1

            incident.affected_hosts = len(hosts)
            incident.attack_phases = len(set(
                e.phase for e in session.query(RCATimeline).filter(RCATimeline.incident_id == incident.id).all() if e.phase
            ))
            incident.mitre_techniques = list(set(
                e.mitre_technique_id for e in session.query(RCATimeline).filter(RCATimeline.incident_id == incident.id).all() if e.mitre_technique_id
            ))

            # Remediation plan
            rems = []
            for p in scan_results["ports"]:
                svc = (p.get("service") or "").lower()
                risk = p.get("risk", "info")
                if risk == "critical":
                    if "redis" in svc: rems.append(("P0", f"Bind Redis ({target}:{p['port']}) to 127.0.0.1 and enable AUTH", "Closes RCE vector", "15 min"))
                    elif "mongo" in svc: rems.append(("P0", f"Enable auth on MongoDB ({target}:{p['port']}), bind to internal only", "Prevents data theft", "30 min"))
                    else: rems.append(("P0", f"Restrict {svc} on {target}:{p['port']} immediately", "Eliminates critical exposure", "15 min"))
                elif risk == "high":
                    if "mysql" in svc or "postgres" in svc: rems.append(("P1", f"Enforce strong creds on {svc} ({target}:{p['port']})", "Prevents credential attack", "1 hr"))
                    elif "telnet" in svc or "ftp" in svc: rems.append(("P0", f"Disable {svc} ({target}:{p['port']}), use SSH/SFTP", "Eliminates cleartext creds", "30 min"))
                    else: rems.append(("P1", f"Harden {svc} on {target}:{p['port']}", "Reduces attack surface", "1 hr"))
                elif risk == "medium":
                    rems.append(("P2", f"Review access for {svc} on {target}:{p['port']}", "Hardens config", "1-2 hr"))

            if crit > 0 or high > 0:
                rems.append(("P1", f"Deploy network segmentation to isolate {target}", "Limits blast radius", "2-4 hr"))
                rems.append(("P2", "Deploy HIDS (OSSEC/Wazuh) and enable audit logging", "Future detection", "2-4 hr"))
                rems.append(("P3", "Implement weekly vulnerability scanning schedule", "Prevents exposure drift", "1 week"))

            for priority, action, impact, effort in rems:
                session.add(Remediation(
                    incident_id=incident.id, priority=priority, action=action,
                    impact=impact, effort=effort, ai_generated=False, status="pending",
                ))

            root_causes = [f"Unauthenticated {p.get('service')} on port {p['port']}" for p in scan_results["ports"] if p.get("risk") == "critical"]
            incident.root_cause = "; ".join(root_causes) if root_causes else f"Exposed services on {target}"
            incident.ai_summary = (
                f"Scan of {target}: {total} findings ({crit} critical, {high} high). "
                f"{'Critical: unauthenticated services allowing remote access. ' if crit > 0 else ''}"
                f"{len(rems)} remediation actions generated."
            )
            incident.ai_confidence = 0.85

            _create_alert(session, overall_sev,
                f"RCA incident created: {incident.incident_number} — {crit}C {high}H on {target}",
                "RCA Engine", incident.id)

            session.commit()
            logger.info(f"Auto-created incident {incident.incident_number} with {len(rems)} remediations")

        scan.progress = 100
        session.commit()
        return {"scan_id": scan_id, "findings": total, "severity": overall_sev}

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                from models.scan import ScanStatus
                scan.status = ScanStatus.FAILED
                scan.raw_output = str(e)
                session.commit()
        except: pass
        raise self.retry(exc=e, countdown=30)
    finally:
        session.close()


def _run_nmap(target, scan_type):
    """Run real nmap scan. Returns empty results if host is unreachable. Never returns fake data."""
    try:
        import nmap
    except ImportError:
        logger.error("python-nmap not installed in container")
        return {"ports": [], "vulnerabilities": [], "error": "nmap not available"}

    try:
        scanner = nmap.PortScanner()
        common_ports = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8000,8080,8443,9090,9200,11211,27017"
        args = {
            "network": f"-sT -sV --open -T4 -p {common_ports}",
            "port": f"-sT -sV -sC --open -T4 -p {common_ports}",
            "vulnerability": f"-sT -sV --script=vuln --open -T4 -p {common_ports}",
            "webapp": "-sT -sV --open -T4 -p 80,443,3000,4000,5000,8000,8080,8443,9090",
        }.get(scan_type, f"-sT -sV --open -T4 -p {common_ports}")

        logger.info(f"Running: nmap {args} {target}")
        scanner.scan(hosts=target, arguments=args)

        ports = []
        vulns = []
        HIGH_RISK = {6379, 27017, 11211, 9200, 5984}
        MED_RISK = {21, 23, 3306, 5432, 8080, 8443}
        hosts_found = scanner.all_hosts()

        if not hosts_found:
            logger.warning(f"No hosts found for {target} — host may be down or unreachable")
            return {"ports": [], "vulnerabilities": [], "warning": f"Host {target} appears to be down or unreachable"}

        for host in hosts_found:
            host_state = scanner[host].state()
            if host_state != "up":
                continue

            for proto in scanner[host].all_protocols():
                for pn in scanner[host][proto]:
                    info = scanner[host][proto][pn]
                    if info["state"] != "open":
                        continue
                    if pn in HIGH_RISK:
                        risk = "critical"
                    elif pn in MED_RISK:
                        risk = "high" if pn in (21, 23) else "medium"
                    elif pn in (22, 443):
                        risk = "low"
                    else:
                        risk = "low"
                    ver = f"{info.get('product', '')} {info.get('version', '')}".strip()
                    ports.append({
                        "host": host, "port": pn, "protocol": proto, "state": "open",
                        "service": info.get("name", "unknown"), "version": ver or "unknown",
                        "risk": risk, "banner": info.get("extrainfo", ""),
                    })

                    # Extract vulnerability script results
                    if "script" in info:
                        for sn, out in info["script"].items():
                            if any(k in sn for k in ["vuln", "exploit"]):
                                sv = "critical" if "VULNERABLE" in out.upper() else "high"
                                vulns.append({
                                    "title": sn.replace("-", " ").title(),
                                    "severity": sv, "port": pn, "protocol": proto,
                                    "description": out[:500],
                                    "cvss": 9.0 if sv == "critical" else 7.0,
                                })

        logger.info(f"Nmap found {len(ports)} ports, {len(vulns)} vulns on {target}")
        return {"ports": ports, "vulnerabilities": vulns}

    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan error on {target}: {e}")
        return {"ports": [], "vulnerabilities": [], "error": f"Scan failed: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected scan error on {target}: {e}")
        return {"ports": [], "vulnerabilities": [], "error": f"Scan error: {str(e)}"}


# Legacy simulated results — kept for dev/testing only, never called automatically
def _simulated_results(target, scan_type):
    return {
        "ports": [
            {"host": target, "port": 22, "protocol": "tcp", "state": "open", "service": "SSH", "version": "OpenSSH 8.9p1", "risk": "low", "banner": ""},
            {"host": target, "port": 80, "protocol": "tcp", "state": "open", "service": "HTTP", "version": "nginx 1.24.0", "risk": "low", "banner": ""},
            {"host": target, "port": 443, "protocol": "tcp", "state": "open", "service": "HTTPS", "version": "nginx 1.24.0", "risk": "low", "banner": ""},
            {"host": target, "port": 3306, "protocol": "tcp", "state": "open", "service": "MySQL", "version": "MySQL 8.0.32", "risk": "medium", "banner": ""},
            {"host": target, "port": 5432, "protocol": "tcp", "state": "open", "service": "PostgreSQL", "version": "PostgreSQL 16.3", "risk": "medium", "banner": ""},
            {"host": target, "port": 6379, "protocol": "tcp", "state": "open", "service": "Redis", "version": "Redis 7.0.11", "risk": "critical", "banner": ""},
            {"host": target, "port": 8080, "protocol": "tcp", "state": "open", "service": "HTTP-Alt", "version": "Jetty 9.4.51", "risk": "medium", "banner": ""},
            {"host": target, "port": 27017, "protocol": "tcp", "state": "open", "service": "MongoDB", "version": "MongoDB 6.0.8", "risk": "critical", "banner": ""},
        ],
        "vulnerabilities": [
            {"title": "Redis Unauthenticated Access", "severity": "critical", "port": 6379, "protocol": "tcp",
             "description": "Redis instance exposed without authentication. Attacker can execute CONFIG SET to write SSH keys.", "cvss": 9.8},
            {"title": "MongoDB No Authentication", "severity": "critical", "port": 27017, "protocol": "tcp",
             "description": "MongoDB accessible without auth. All databases readable and writable.", "cvss": 9.1},
            {"title": "MySQL Weak Credentials", "severity": "high", "port": 3306, "protocol": "tcp",
             "description": "MySQL accessible with default credentials (root/empty). Full database access.", "cvss": 8.1},
            {"title": "Jetty Information Disclosure", "severity": "medium", "port": 8080, "protocol": "tcp",
             "description": "Jetty exposes stack traces and version info in error pages.", "cvss": 5.3},
        ],
    }


@celery_app.task(name="celery_app.tasks.run_yara_scan_task")
def run_yara_scan_task(case_id, file_path):
    import asyncio
    from services.yara_scanner import YaraScanner
    scanner = YaraScanner()
    loop = asyncio.new_event_loop()
    try:
        matches = loop.run_until_complete(scanner.scan_file(file_path))
        return {"case_id": case_id, "matches": len(matches)}
    finally:
        loop.close()


@celery_app.task(name="celery_app.tasks.generate_report_task")
def generate_report_task(report_type, entity_id, sections):
    return {"report_type": report_type, "entity_id": entity_id, "status": "queued"}


@celery_app.task(name="celery_app.tasks.cleanup_old_results")
def cleanup_old_results():
    session = _get_sync_session()
    try:
        from models.scan import Scan
        cutoff = datetime.utcnow() - timedelta(days=90)
        count = session.query(Scan).filter(Scan.created_at < cutoff).delete()
        session.commit()
        return {"deleted": count}
    finally:
        session.close()
