"""Forensics router — log analysis, YARA scanning, evidence collection."""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime
import uuid
import os

from database import get_db
from config import settings
from models.forensic import ForensicCase, CaseStatus, LogEntry, YaraMatch, Evidence
from schemas import ForensicCaseCreate, ForensicCaseOut
from services.log_analyzer import LogAnalyzer
from services.yara_scanner import YaraScanner

router = APIRouter()
log_analyzer = LogAnalyzer()
yara_scanner = YaraScanner()


@router.post("/cases", response_model=dict, status_code=201)
async def create_case(case_in: ForensicCaseCreate, db: AsyncSession = Depends(get_db)):
    """Create a new forensic investigation case."""
    case = ForensicCase(
        case_number=f"FC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
        title=case_in.title,
        description=case_in.description,
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return {"case_id": case.id, "case_number": case.case_number}


@router.get("/cases", response_model=list[dict])
async def list_cases(
    status: Optional[str] = None,
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
):
    query = select(ForensicCase).order_by(ForensicCase.created_at.desc()).limit(limit)
    if status:
        query = query.where(ForensicCase.status == status)
    result = await db.execute(query)
    cases = result.scalars().all()
    return [
        {
            "id": c.id, "case_number": c.case_number, "title": c.title,
            "status": c.status.value if hasattr(c.status, 'value') else c.status,
            "total_logs": c.total_logs, "anomaly_count": c.anomaly_count,
            "yara_match_count": c.yara_match_count, "created_at": c.created_at.isoformat(),
        }
        for c in cases
    ]


@router.get("/cases/{case_id}", response_model=ForensicCaseOut)
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ForensicCase).where(ForensicCase.id == case_id)
        .options(
            selectinload(ForensicCase.log_entries),
            selectinload(ForensicCase.yara_matches),
            selectinload(ForensicCase.evidence),
        )
    )
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/cases/{case_id}/upload-logs")
async def upload_logs(
    case_id: str,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload and analyze log files for a forensic case."""
    # Verify case exists
    result = await db.execute(select(ForensicCase).where(ForensicCase.id == case_id))
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Save uploaded file
    upload_dir = os.path.join(settings.SCAN_RESULTS_DIR, "forensics", case_id)
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    # Analyze logs
    parsed_entries = await log_analyzer.analyze(content.decode("utf-8", errors="replace"), file.filename)

    # Store parsed log entries
    anomaly_count = 0
    for entry in parsed_entries:
        log_entry = LogEntry(
            case_id=case_id,
            timestamp=entry["timestamp"],
            source_ip=entry.get("source_ip"),
            destination_ip=entry.get("destination_ip"),
            event_type=entry["event_type"],
            severity=entry["severity"],
            raw_log=entry.get("raw_log"),
            parsed_data=entry.get("parsed_data", {}),
            is_anomaly=entry.get("is_anomaly", False),
            anomaly_score=entry.get("anomaly_score"),
        )
        db.add(log_entry)
        if entry.get("is_anomaly"):
            anomaly_count += 1

    # Update case stats
    case.total_logs += len(parsed_entries)
    case.anomaly_count += anomaly_count
    case.status = CaseStatus.IN_PROGRESS
    await db.commit()

    # Save evidence record
    evidence = Evidence(
        case_id=case_id,
        evidence_type="log",
        title=f"Log file: {file.filename}",
        description=f"Uploaded log file with {len(parsed_entries)} entries, {anomaly_count} anomalies detected",
        file_path=file_path,
    )
    db.add(evidence)
    await db.commit()

    return {
        "entries_parsed": len(parsed_entries),
        "anomalies_detected": anomaly_count,
        "file_saved": file_path,
    }


@router.post("/cases/{case_id}/yara-scan")
async def run_yara_scan(
    case_id: str,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Scan an uploaded file against YARA rules."""
    result = await db.execute(select(ForensicCase).where(ForensicCase.id == case_id))
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Save file
    upload_dir = os.path.join(settings.SCAN_RESULTS_DIR, "forensics", case_id, "samples")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    # Run YARA scan
    matches = await yara_scanner.scan_file(file_path)

    # Store matches
    for match in matches:
        yara_match = YaraMatch(
            case_id=case_id,
            rule_name=match["rule"],
            file_path=file_path,
            file_hash_sha256=match.get("sha256"),
            confidence=match.get("confidence"),
            severity=match.get("severity", "high"),
            matched_strings=match.get("strings", []),
            rule_metadata=match.get("meta", {}),
        )
        db.add(yara_match)

    case.yara_match_count += len(matches)
    await db.commit()

    return {"matches": len(matches), "details": matches}


@router.get("/cases/{case_id}/logs")
async def get_logs(
    case_id: str,
    severity: Optional[str] = None,
    anomalies_only: bool = False,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve analyzed log entries with filters."""
    query = select(LogEntry).where(LogEntry.case_id == case_id).order_by(LogEntry.timestamp.desc())
    if severity:
        query = query.where(LogEntry.severity == severity)
    if anomalies_only:
        query = query.where(LogEntry.is_anomaly == True)
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    entries = result.scalars().all()
    return [
        {
            "id": e.id, "timestamp": e.timestamp.isoformat(), "source_ip": e.source_ip,
            "event_type": e.event_type, "severity": e.severity,
            "is_anomaly": e.is_anomaly, "anomaly_score": e.anomaly_score,
            "parsed_data": e.parsed_data,
        }
        for e in entries
    ]
