# CyberSecurity Suite

Industry-grade security platform combining attack simulation, digital forensics, root cause analysis, and centralized reporting.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  React Frontend (Shadcn UI + Recharts)                               │
│  ┌─────────────┬──────────────┬──────────────┬────────────────────┐  │
│  │  Dashboard   │  Attack Sim  │  Forensics   │  RCA + Reports     │  │
│  └─────────────┴──────────────┴──────────────┴────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ REST API
┌───────────────────────────────▼──────────────────────────────────────┐
│  FastAPI Backend                                                      │
│  ┌──────────┐ ┌───────────┐ ┌───────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Auth/JWT │ │ Scan API  │ │Forensic API│ │ RCA API  │ │ Reports │ │
│  └──────────┘ └─────┬─────┘ └─────┬─────┘ └────┬─────┘ └────┬────┘ │
│                     │             │             │            │       │
│  ┌──────────────────▼─────────────▼─────────────▼────────────▼────┐ │
│  │  Service Layer                                                  │ │
│  │  NmapScanner │ LogAnalyzer │ YaraScanner │ RCAEngine │ AI/PDF  │ │
│  └────────────────────────────────┬───────────────────────────────┘ │
└───────────────────────────────────┼─────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
            ┌───────▼──────┐ ┌─────▼─────┐ ┌───────▼──────┐
            │ PostgreSQL   │ │  Redis     │ │ Celery       │
            │ (data store) │ │ (broker)   │ │ (async jobs) │
            └──────────────┘ └───────────┘ └──────────────┘
```

## Modules

**Attack Simulation** — Launches Nmap scans (network discovery, port scanning, vulnerability detection) via Celery workers. Stores open ports, service versions, and CVEs. Calculates risk scores per target.

**Digital Forensics** — Ingests log files (syslog, JSON, CSV), parses them with format auto-detection, runs pattern-based anomaly scoring, and scans file samples against YARA rules (5 built-in rules for shells, persistence, credential harvesting, webshells, encoded payloads).

**Root Cause Analysis** — Correlates scan results and forensic findings into a unified attack timeline with MITRE ATT&CK phase mapping. Calls Claude API for AI-powered root cause determination and prioritized remediation plans (P0–P3).

**Dashboard & Reports** — Aggregates severity distributions, finding trends, risk radar, and alerts across all modules. Generates PDF reports (vulnerability, incident, forensic) via ReportLab.

## Quick Start

### Prerequisites

- Docker & Docker Compose
- (Optional) Anthropic API key for AI-powered RCA

### 1. Clone and configure

```bash
cp .env.example .env
# Edit .env — at minimum set POSTGRES_PASSWORD and SECRET_KEY
# Add ANTHROPIC_API_KEY if you want AI-powered analysis
```

### 2. Start all services

```bash
docker compose up --build -d
```

This starts PostgreSQL, Redis, the FastAPI app, a Celery worker, and Celery beat.

### 3. Verify

```bash
curl http://localhost:8000/api/health
# {"status":"ok","service":"cybersec-suite","version":"1.0.0"}
```

API docs at **http://localhost:8000/api/docs** (Swagger) or **/api/redoc**.

### 4. Create a user and scan

```bash
# Register
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@corp.io","username":"admin","password":"SecurePass123!"}'

# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePass123!"}' | jq .access_token

# Launch a scan (use the token from login)
curl -X POST http://localhost:8000/api/scans/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1","scan_type":"port"}'
```

## Project Structure

```
cybersec-suite/
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                  # FastAPI app entry point
│   ├── config.py                # Pydantic settings
│   ├── database.py              # Async SQLAlchemy engine
│   ├── alembic.ini              # Migration config
│   ├── alembic/                 # DB migration scripts
│   ├── models/
│   │   ├── user.py              # User + RBAC
│   │   ├── scan.py              # Scan, Port, Vulnerability
│   │   ├── forensic.py          # ForensicCase, LogEntry, YaraMatch, Evidence
│   │   ├── rca.py               # Incident, RCATimeline, Remediation
│   │   └── alert.py             # Alert notifications
│   ├── schemas/
│   │   └── __init__.py          # Pydantic request/response schemas
│   ├── routers/
│   │   ├── auth.py              # JWT register/login
│   │   ├── scan.py              # Attack simulation CRUD
│   │   ├── forensics.py         # Log upload, YARA scan, evidence
│   │   ├── rca.py               # Incident, correlate, AI analyze
│   │   ├── dashboard.py         # Aggregated stats/trends/alerts
│   │   └── reports.py           # PDF generation/download
│   ├── services/
│   │   ├── nmap_scanner.py      # python-nmap wrapper + risk assessment
│   │   ├── log_analyzer.py      # Multi-format parser + anomaly scoring
│   │   ├── yara_scanner.py      # YARA rule engine + fallback patterns
│   │   ├── rca_engine.py        # Event correlation + MITRE mapping
│   │   ├── ai_recommendations.py # Claude API for RCA + remediation
│   │   └── pdf_generator.py     # ReportLab PDF reports
│   └── celery_app/
│       ├── __init__.py          # Celery config, routing, beat schedule
│       └── tasks.py             # Async scan, YARA, report, cleanup tasks
└── frontend/
    └── CyberSecuritySuite.jsx   # React frontend (also in outputs/)
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create user account |
| POST | `/api/auth/login` | JWT login |
| POST | `/api/scans/` | Launch a new scan |
| GET | `/api/scans/` | List scans (filterable) |
| GET | `/api/scans/{id}` | Scan details + ports + vulns |
| GET | `/api/scans/{id}/status` | Poll scan progress |
| DELETE | `/api/scans/{id}` | Cancel running scan |
| POST | `/api/forensics/cases` | Create forensic case |
| POST | `/api/forensics/cases/{id}/upload-logs` | Upload + analyze logs |
| POST | `/api/forensics/cases/{id}/yara-scan` | Scan file with YARA |
| GET | `/api/forensics/cases/{id}/logs` | Query analyzed logs |
| POST | `/api/rca/incidents` | Create incident |
| POST | `/api/rca/incidents/{id}/correlate` | Run RCA correlation |
| POST | `/api/rca/incidents/{id}/analyze` | AI-powered analysis |
| PATCH | `/api/rca/incidents/{id}/remediations/{rid}` | Update remediation status |
| GET | `/api/dashboard/stats` | Aggregated security metrics |
| GET | `/api/dashboard/trend` | Daily finding trend |
| GET | `/api/dashboard/alerts` | Recent alerts |
| POST | `/api/reports/generate` | Generate PDF report |
| GET | `/api/reports/download/{filename}` | Download PDF |

## Database Migrations

```bash
# Generate a migration after model changes
docker compose exec api alembic revision --autogenerate -m "description"

# Apply migrations
docker compose exec api alembic upgrade head
```

On first startup, `init_db()` auto-creates tables. Use Alembic for subsequent schema changes.

## Configuration

All config via environment variables (see `.env.example`):

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis broker URL |
| `SECRET_KEY` | Yes | JWT signing key |
| `ANTHROPIC_API_KEY` | No | Claude API key for AI-powered RCA |
| `NMAP_PATH` | No | Path to nmap binary (default: /usr/bin/nmap) |
| `YARA_RULES_DIR` | No | Directory for custom YARA rules |
| `CORS_ORIGINS` | No | Allowed frontend origins (JSON array) |
| `REPORTS_DIR` | No | PDF report output directory |

## Extending

**Adding YARA rules** — Drop `.yar` files into `YARA_RULES_DIR`. The scanner loads them on startup alongside the 5 built-in rules.

**Adding scan types** — Create a new method in `NmapScanner`, add the scan type to the `ScanType` enum in `models/scan.py`, and update the Celery task routing.

**OWASP ZAP integration** — Add a `ZapScanner` service class that talks to ZAP's REST API, wire it into the scan router alongside Nmap. ZAP's daemon lifecycle and scan policies need manual configuration.

**Volatility 3 integration** — Add a `VolatilityAnalyzer` service that shells out to the `vol3` CLI. Requires OS symbol tables for the target memory images.

## What You Handle

- Nmap, OWASP ZAP, Nikto installation on deployment hosts
- PostgreSQL + Redis infrastructure provisioning
- Volatility 3 setup with correct symbol tables
- Domain-specific YARA rule curation
- TLS termination, secrets management, CI/CD
- Authorization policies for running scans against targets
