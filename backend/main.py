"""CyberSecurity Suite — FastAPI application entry point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import logging
import os

from config import settings
from database import init_db
from routers import auth, scan, forensics, rca, dashboard, reports


# ──── Logging ─────────────────────────────────────────────────
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL))
logger = logging.getLogger(__name__)


# ──── Lifespan (startup / shutdown) ───────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CyberSecurity Suite API...")
    await init_db()
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    logger.info("Database initialized, directories ready.")
    yield
    logger.info("Shutting down.")


# ──── App ─────────────────────────────────────────────────────
app = FastAPI(
    title="CyberSecurity Suite API",
    description="Attack simulation, digital forensics, root cause analysis, and reporting.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ──── CORS ────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──── Static files (reports) ──────────────────────────────────
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
app.mount("/reports", StaticFiles(directory=settings.REPORTS_DIR), name="reports")

# ──── Routers ─────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan.router, prefix="/api/scans", tags=["Attack Simulation"])
app.include_router(forensics.router, prefix="/api/forensics", tags=["Digital Forensics"])
app.include_router(rca.router, prefix="/api/rca", tags=["Root Cause Analysis"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


# ──── Health check ────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "cybersec-suite", "version": "1.0.0"}
