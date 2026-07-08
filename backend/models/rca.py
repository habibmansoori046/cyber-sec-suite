"""RCA models — root cause analysis, attack timeline, remediation tracking."""

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Float, Text, ForeignKey, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base
import enum


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_number: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(SAEnum(IncidentStatus), default=IncidentStatus.OPEN)
    root_cause: Mapped[str] = mapped_column(Text, nullable=True)

    # Linked entities
    scan_ids: Mapped[dict] = mapped_column(JSON, default=list)
    forensic_case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=True)

    # Metrics
    affected_hosts: Mapped[int] = mapped_column(Integer, default=0)
    attack_phases: Mapped[int] = mapped_column(Integer, default=0)
    mitre_techniques: Mapped[dict] = mapped_column(JSON, default=list)
    iocs: Mapped[dict] = mapped_column(JSON, default=list)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=True)

    # AI analysis
    ai_summary: Mapped[str] = mapped_column(Text, nullable=True)
    ai_confidence: Mapped[float] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    timeline: Mapped[list["RCATimeline"]] = relationship("RCATimeline", back_populates="incident", cascade="all, delete-orphan")
    remediations: Mapped[list["Remediation"]] = relationship("Remediation", back_populates="incident", cascade="all, delete-orphan")


class RCATimeline(Base):
    __tablename__ = "rca_timeline"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    event: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    phase: Mapped[str] = mapped_column(String(100), nullable=True)  # MITRE ATT&CK phase
    mitre_technique_id: Mapped[str] = mapped_column(String(20), nullable=True)
    source_host: Mapped[str] = mapped_column(String(255), nullable=True)
    destination_host: Mapped[str] = mapped_column(String(255), nullable=True)
    evidence_refs: Mapped[dict] = mapped_column(JSON, default=list)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline")


class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    priority: Mapped[str] = mapped_column(String(5), nullable=False)  # P0, P1, P2, P3
    action: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(String(500), nullable=True)
    effort: Mapped[str] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="pending")  # pending, in_progress, completed, skipped
    assigned_to: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    ai_generated: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="remediations")
