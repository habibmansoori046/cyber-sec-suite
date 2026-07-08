"""Scan models — attack simulation, port scans, vulnerability scans."""

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Float, Text, ForeignKey, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base
import enum


class ScanType(str, enum.Enum):
    NETWORK = "network"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    WEBAPP = "webapp"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_type: Mapped[ScanType] = mapped_column(SAEnum(ScanType), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.QUEUED)
    severity: Mapped[str] = mapped_column(String(20), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)

    # Metadata
    initiated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    celery_task_id: Mapped[str] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=True)

    # Config
    scan_config: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_output: Mapped[str] = mapped_column(Text, nullable=True)

    # Stats
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    ports: Mapped[list["Port"]] = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    results: Mapped[list["ScanResult"]] = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), nullable=False)  # open, closed, filtered
    service_name: Mapped[str] = mapped_column(String(100), nullable=True)
    service_version: Mapped[str] = mapped_column(String(200), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=True)
    banner: Mapped[str] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="ports")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    affected_component: Mapped[str] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="open")  # open, remediated, accepted, false_positive
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    references: Mapped[dict] = mapped_column(JSON, default=list)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    os_guess: Mapped[str] = mapped_column(String(200), nullable=True)
    mac_address: Mapped[str] = mapped_column(String(20), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="results")
