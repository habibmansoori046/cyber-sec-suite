"""Dashboard router — aggregated security metrics and stats."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta

from database import get_db
from models.scan import Scan, ScanStatus, Vulnerability
from models.forensic import ForensicCase
from models.rca import Incident, IncidentStatus
from models.alert import Alert

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Aggregated stats for the security dashboard."""
    # Total scans
    total_scans = await db.execute(select(func.count(Scan.id)))
    
    # Open vulnerabilities
    open_vulns = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.status == "open")
    )

    # Active incidents
    active_incidents = await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING])
        )
    )

    # Severity distribution of open vulnerabilities
    severity_dist = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.status == "open",
                Vulnerability.severity == sev,
            )
        )
        severity_dist[sev] = count.scalar() or 0

    # Calculate risk score (weighted severity)
    risk_score = min(100, (
        severity_dist.get("critical", 0) * 25 +
        severity_dist.get("high", 0) * 15 +
        severity_dist.get("medium", 0) * 8 +
        severity_dist.get("low", 0) * 3
    ))

    return {
        "total_scans": total_scans.scalar() or 0,
        "open_vulnerabilities": open_vulns.scalar() or 0,
        "active_incidents": active_incidents.scalar() or 0,
        "risk_score": risk_score,
        "severity_distribution": severity_dist,
    }


@router.get("/trend")
async def get_trend_data(days: int = 7, db: AsyncSession = Depends(get_db)):
    """Daily finding trend over the past N days."""
    trend = []
    for i in range(days - 1, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end = datetime.combine(day, datetime.max.time())

        counts = {}
        for sev in ["critical", "high", "medium", "low"]:
            result = await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.discovered_at >= day_start,
                    Vulnerability.discovered_at <= day_end,
                    Vulnerability.severity == sev,
                )
            )
            counts[sev] = result.scalar() or 0

        trend.append({"date": day.isoformat(), **counts})

    return trend


@router.get("/alerts")
async def get_recent_alerts(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Recent alerts across all modules."""
    result = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    )
    alerts = result.scalars().all()
    return [
        {
            "id": a.id, "severity": a.severity, "message": a.message,
            "source": a.source, "is_read": a.is_read,
            "created_at": a.created_at.isoformat(),
        }
        for a in alerts
    ]


@router.patch("/alerts/{alert_id}/read")
async def mark_alert_read(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if alert:
        alert.is_read = True
        await db.commit()
    return {"status": "ok"}
