"""Reports router — generate and serve PDF reports."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
import os

from database import get_db
from config import settings
from models.scan import Scan
from models.rca import Incident
from models.forensic import ForensicCase
from schemas import ReportRequest
from services.pdf_generator import PDFGenerator

router = APIRouter()
pdf_gen = PDFGenerator()


@router.post("/generate")
async def generate_report(req: ReportRequest, db: AsyncSession = Depends(get_db)):
    """Generate a PDF report for a scan, incident, or forensic case."""

    if req.report_type == "vulnerability":
        result = await db.execute(
            select(Scan).where(Scan.id == req.entity_id)
            .options(selectinload(Scan.ports), selectinload(Scan.vulnerabilities))
        )
        entity = result.scalars().first()
        if not entity:
            raise HTTPException(status_code=404, detail="Scan not found")

        filepath = await pdf_gen.generate_vulnerability_report(entity, req.include_sections)

    elif req.report_type == "incident":
        result = await db.execute(
            select(Incident).where(Incident.id == req.entity_id)
            .options(selectinload(Incident.timeline), selectinload(Incident.remediations))
        )
        entity = result.scalars().first()
        if not entity:
            raise HTTPException(status_code=404, detail="Incident not found")

        filepath = await pdf_gen.generate_incident_report(entity, req.include_sections)

    elif req.report_type == "forensic":
        result = await db.execute(
            select(ForensicCase).where(ForensicCase.id == req.entity_id)
            .options(
                selectinload(ForensicCase.log_entries),
                selectinload(ForensicCase.yara_matches),
                selectinload(ForensicCase.evidence),
            )
        )
        entity = result.scalars().first()
        if not entity:
            raise HTTPException(status_code=404, detail="Forensic case not found")

        filepath = await pdf_gen.generate_forensic_report(entity, req.include_sections)

    else:
        raise HTTPException(status_code=400, detail="Invalid report type")

    filename = os.path.basename(filepath)
    return {
        "report_url": f"/reports/{filename}",
        "filename": filename,
        "report_type": req.report_type,
    }


@router.get("/download/{filename}")
async def download_report(filename: str):
    filepath = os.path.join(settings.REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(filepath, media_type="application/pdf", filename=filename)
