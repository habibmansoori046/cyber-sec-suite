"""Pydantic schemas — request/response validation for all modules."""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum


# ──── Auth ────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: str
    username: str
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str

class UserOut(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ──── Scan (Attack Simulation) ────────────────────────────────
class ScanTypeEnum(str, Enum):
    NETWORK = "network"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    WEBAPP = "webapp"

class ScanCreate(BaseModel):
    target: str = Field(..., min_length=1, max_length=500)
    scan_type: ScanTypeEnum
    config: dict = Field(default_factory=dict)

class PortOut(BaseModel):
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str]
    service_version: Optional[str]
    risk_level: Optional[str]

    class Config:
        from_attributes = True

class VulnerabilityOut(BaseModel):
    id: str
    cve_id: Optional[str]
    title: str
    severity: str
    cvss_score: Optional[float]
    description: Optional[str]
    affected_component: Optional[str]
    status: str
    remediation: Optional[str]

    class Config:
        from_attributes = True

class ScanOut(BaseModel):
    id: str
    scan_type: str
    target: str
    status: str
    severity: Optional[str]
    progress: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    duration_seconds: Optional[int]
    ports: List[PortOut] = []
    vulnerabilities: List[VulnerabilityOut] = []

    class Config:
        from_attributes = True

class ScanListOut(BaseModel):
    id: str
    scan_type: str
    target: str
    status: str
    severity: Optional[str]
    total_findings: int
    created_at: datetime
    duration_seconds: Optional[int]

    class Config:
        from_attributes = True


# ──── Forensics ───────────────────────────────────────────────
class ForensicCaseCreate(BaseModel):
    title: str
    description: Optional[str] = None

class LogEntryOut(BaseModel):
    id: str
    timestamp: datetime
    source_ip: Optional[str]
    event_type: str
    severity: str
    raw_log: Optional[str]
    is_anomaly: bool
    anomaly_score: Optional[float]
    parsed_data: dict

    class Config:
        from_attributes = True

class YaraMatchOut(BaseModel):
    id: str
    rule_name: str
    file_path: str
    file_hash_sha256: Optional[str]
    confidence: Optional[float]
    severity: str
    matched_strings: Any
    detected_at: datetime

    class Config:
        from_attributes = True

class EvidenceOut(BaseModel):
    id: str
    evidence_type: str
    title: str
    description: Optional[str]
    hash_sha256: Optional[str]
    collected_at: datetime

    class Config:
        from_attributes = True

class ForensicCaseOut(BaseModel):
    id: str
    case_number: str
    title: str
    description: Optional[str]
    status: str
    total_logs: int
    anomaly_count: int
    yara_match_count: int
    created_at: datetime
    updated_at: datetime
    log_entries: List[LogEntryOut] = []
    yara_matches: List[YaraMatchOut] = []
    evidence: List[EvidenceOut] = []

    class Config:
        from_attributes = True


# ──── RCA ─────────────────────────────────────────────────────
class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "high"
    scan_ids: List[str] = []
    forensic_case_id: Optional[str] = None

class TimelineEventOut(BaseModel):
    id: str
    sequence: int
    timestamp: datetime
    event: str
    details: Optional[str]
    severity: str
    phase: Optional[str]
    mitre_technique_id: Optional[str]
    source_host: Optional[str]
    destination_host: Optional[str]

    class Config:
        from_attributes = True

class RemediationOut(BaseModel):
    id: str
    priority: str
    action: str
    impact: Optional[str]
    effort: Optional[str]
    status: str
    ai_generated: bool
    created_at: datetime

    class Config:
        from_attributes = True

class IncidentOut(BaseModel):
    id: str
    incident_number: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    root_cause: Optional[str]
    affected_hosts: int
    attack_phases: int
    mitre_techniques: Any
    iocs: Any
    duration_seconds: Optional[int]
    ai_summary: Optional[str]
    created_at: datetime
    resolved_at: Optional[datetime]
    timeline: List[TimelineEventOut] = []
    remediations: List[RemediationOut] = []

    class Config:
        from_attributes = True


# ──── Alerts ──────────────────────────────────────────────────
class AlertOut(BaseModel):
    id: str
    severity: str
    message: str
    source: str
    is_read: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ──── Dashboard ───────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_scans: int
    open_vulnerabilities: int
    active_incidents: int
    risk_score: int
    severity_distribution: dict
    trend_data: List[dict]
    recent_alerts: List[AlertOut]
    recent_scans: List[ScanListOut]


# ──── Reports ─────────────────────────────────────────────────
class ReportRequest(BaseModel):
    report_type: str  # incident, vulnerability, forensic, compliance
    entity_id: str  # ID of the scan/incident/case to report on
    include_sections: List[str] = ["summary", "findings", "remediation", "timeline"]
