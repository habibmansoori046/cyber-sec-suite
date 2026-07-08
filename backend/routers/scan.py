"""Scan router — CRUD + async scan execution via Celery."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime

from database import get_db
from models.scan import Scan, ScanStatus, Port, Vulnerability
from schemas import ScanCreate, ScanOut, ScanListOut
from celery_app.tasks import run_scan_task

router = APIRouter()


@router.post("/", response_model=dict, status_code=202)
async def create_scan(scan_in: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Launch a new scan — queued for async execution via Celery."""
    scan = Scan(
        scan_type=scan_in.scan_type.value,
        target=scan_in.target,
        status=ScanStatus.QUEUED,
        scan_config=scan_in.config,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Dispatch to Celery
    task = run_scan_task.delay(scan.id, scan_in.target, scan_in.scan_type.value, scan_in.config)
    scan.celery_task_id = task.id
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    await db.commit()

    return {"scan_id": scan.id, "task_id": task.id, "status": "running"}


@router.get("/", response_model=list[ScanListOut])
async def list_scans(
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = Query(20, le=100),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List scans with optional filters."""
    query = select(Scan).order_by(Scan.created_at.desc())
    if status:
        query = query.where(Scan.status == status)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan details including ports and vulnerabilities."""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.ports), selectinload(Scan.vulnerabilities))
    )
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Poll scan progress — used for real-time UI updates."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id,
        "status": scan.status.value if hasattr(scan.status, 'value') else scan.status,
        "progress": scan.progress,
        "total_findings": scan.total_findings,
    }


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Cancel a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.celery_task_id and scan.status == ScanStatus.RUNNING:
        from celery_app.celery_config import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = ScanStatus.CANCELLED
    await db.commit()


@router.get("/stats/summary")
async def scan_stats(db: AsyncSession = Depends(get_db)):
    """Aggregate scan statistics for dashboard."""
    total = await db.execute(select(func.count(Scan.id)))
    running = await db.execute(select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING))
    vuln_count = await db.execute(select(func.count(Vulnerability.id)).where(Vulnerability.status == "open"))

    return {
        "total_scans": total.scalar() or 0,
        "running_scans": running.scalar() or 0,
        "open_vulnerabilities": vuln_count.scalar() or 0,
    }
