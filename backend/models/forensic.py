"""Forensic models — digital forensics, log analysis, malware detection."""

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Float, Text, ForeignKey, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base
import enum


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    ARCHIVED = "archived"


class ForensicCase(Base):
    __tablename__ = "forensic_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[CaseStatus] = mapped_column(SAEnum(CaseStatus), default=CaseStatus.OPEN)
    assigned_to: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Aggregated stats
    total_logs: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_count: Mapped[int] = mapped_column(Integer, default=0)
    yara_match_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    log_entries: Mapped[list["LogEntry"]] = relationship("LogEntry", back_populates="case", cascade="all, delete-orphan")
    yara_matches: Mapped[list["YaraMatch"]] = relationship("YaraMatch", back_populates="case", cascade="all, delete-orphan")
    evidence: Mapped[list["Evidence"]] = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    raw_log: Mapped[str] = mapped_column(Text, nullable=True)
    parsed_data: Mapped[dict] = mapped_column(JSON, default=dict)
    is_anomaly: Mapped[bool] = mapped_column(default=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=True)
    tags: Mapped[dict] = mapped_column(JSON, default=list)

    case: Mapped["ForensicCase"] = relationship("ForensicCase", back_populates="log_entries")


class YaraMatch(Base):
    __tablename__ = "yara_matches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=True)
    file_hash_md5: Mapped[str] = mapped_column(String(32), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    matched_strings: Mapped[dict] = mapped_column(JSON, default=list)
    rule_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["ForensicCase"] = relationship("ForensicCase", back_populates="yara_matches")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # file, log, memory_dump, network_capture
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    file_path: Mapped[str] = mapped_column(String(500), nullable=True)
    hash_sha256: Mapped[str] = mapped_column(String(64), nullable=True)
    chain_of_custody: Mapped[dict] = mapped_column(JSON, default=list)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    collected_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    case: Mapped["ForensicCase"] = relationship("ForensicCase", back_populates="evidence")
