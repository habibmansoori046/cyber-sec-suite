"""RCA router — root cause analysis, timeline correlation, AI-driven remediation."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime
import uuid

from database import get_db
from models.rca import Incident, IncidentStatus, RCATimeline, Remediation
from schemas import IncidentCreate, IncidentOut
from services.rca_engine import RCAEngine
from services.ai_recommendations import AIRecommendationEngine

router = APIRouter()
rca_engine = RCAEngine()
ai_engine = AIRecommendationEngine()


@router.post("/incidents", response_model=dict, status_code=201)
async def create_incident(incident_in: IncidentCreate, db: AsyncSession = Depends(get_db)):
    """Create a new incident for root cause analysis."""
    incident = Incident(
        incident_number=f"INC-{datetime.now().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}",
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        scan_ids=incident_in.scan_ids,
        forensic_case_id=incident_in.forensic_case_id,
        status=IncidentStatus.INVESTIGATING,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return {"incident_id": incident.id, "incident_number": incident.incident_number}


@router.get("/incidents", response_model=list[dict])
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident).order_by(Incident.created_at.desc()).limit(limit)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    result = await db.execute(query)
    incidents = result.scalars().all()
    return [
        {
            "id": i.id, "incident_number": i.incident_number, "title": i.title,
            "severity": i.severity,
            "status": i.status.value if hasattr(i.status, 'value') else i.status,
            "affected_hosts": i.affected_hosts, "attack_phases": i.attack_phases,
            "created_at": i.created_at.isoformat(),
        }
        for i in incidents
    ]


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
        .options(
            selectinload(Incident.timeline),
            selectinload(Incident.remediations),
        )
    )
    incident = result.scalars().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/incidents/{incident_id}/correlate")
async def correlate_events(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Run the RCA correlation engine on an incident's linked data.
    
    Pulls scan results, forensic logs, and YARA matches, then builds
    a correlated attack timeline with MITRE ATT&CK phase mapping.
    """
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalars().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Run correlation engine
    timeline_events = await rca_engine.correlate(
        incident_id=incident_id,
        scan_ids=incident.scan_ids or [],
        forensic_case_id=incident.forensic_case_id,
        db=db,
    )

    # Store timeline
    for seq, event in enumerate(timeline_events):
        entry = RCATimeline(
            incident_id=incident_id,
            sequence=seq + 1,
            timestamp=event["timestamp"],
            event=event["event"],
            details=event.get("details"),
            severity=event["severity"],
            phase=event.get("phase"),
            mitre_technique_id=event.get("mitre_id"),
            source_host=event.get("source_host"),
            destination_host=event.get("dest_host"),
        )
        db.add(entry)

    # Update incident stats
    phases = set(e.get("phase") for e in timeline_events if e.get("phase"))
    incident.attack_phases = len(phases)
    incident.affected_hosts = len(set(
        e.get("source_host") for e in timeline_events if e.get("source_host")
    ))
    incident.mitre_techniques = list(set(
        e.get("mitre_id") for e in timeline_events if e.get("mitre_id")
    ))
    await db.commit()

    return {
        "events_correlated": len(timeline_events),
        "phases_identified": len(phases),
        "hosts_affected": incident.affected_hosts,
    }


@router.post("/incidents/{incident_id}/analyze")
async def ai_analyze(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Generate AI-powered root cause analysis and remediation plan."""
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
        .options(selectinload(Incident.timeline))
    )
    incident = result.scalars().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Build context for AI
    timeline_data = [
        {"time": e.timestamp.isoformat(), "event": e.event, "severity": e.severity,
         "phase": e.phase, "details": e.details}
        for e in sorted(incident.timeline, key=lambda x: x.sequence)
    ]

    # Get AI analysis
    analysis = await ai_engine.analyze_incident(
        title=incident.title,
        description=incident.description or "",
        timeline=timeline_data,
        severity=incident.severity,
    )

    # Update incident with AI results
    incident.root_cause = analysis.get("root_cause")
    incident.ai_summary = analysis.get("summary")
    incident.ai_confidence = analysis.get("confidence")
    incident.iocs = analysis.get("iocs", [])

    # Store remediation plan
    for rem in analysis.get("remediations", []):
        remediation = Remediation(
            incident_id=incident_id,
            priority=rem["priority"],
            action=rem["action"],
            impact=rem.get("impact"),
            effort=rem.get("effort"),
            ai_generated=True,
        )
        db.add(remediation)

    await db.commit()

    return {
        "root_cause": analysis.get("root_cause"),
        "summary": analysis.get("summary"),
        "confidence": analysis.get("confidence"),
        "remediation_count": len(analysis.get("remediations", [])),
    }


@router.patch("/incidents/{incident_id}/remediations/{remediation_id}")
async def update_remediation(
    incident_id: str,
    remediation_id: str,
    status: str,
    db: AsyncSession = Depends(get_db),
):
    """Update remediation status (pending → in_progress → completed)."""
    result = await db.execute(
        select(Remediation).where(
            Remediation.id == remediation_id,
            Remediation.incident_id == incident_id,
        )
    )
    rem = result.scalars().first()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    rem.status = status
    if status == "completed":
        rem.completed_at = datetime.utcnow()
    await db.commit()
    return {"status": "updated"}
