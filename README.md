# Enterprise Attack Surface Management (ASM) Platform

An enterprise-grade ASM platform with:
- **EPSS + contextual risk scoring** (exploitability + business criticality + exposure context).
- **Real scan orchestration pipeline** with job queue, retry/backoff, prioritization, and scanner-node heartbeat.
- **Integrated tool execution** using subprocess pipelines for Nmap, Masscan, Subfinder, Assetfinder, Nikto, Nuclei, Amass, httpx, Naabu, and Wafw00f (with fallback mode when binaries are unavailable).
- **Vulnerability lifecycle operations**: assignment, ticket creation, exception request/approval with expiration, SLA tracking, and dedup by fingerprint.
- **Continuous monitoring automation** for registered targets.
- **Elegant frontend** with deep target intelligence drill-down.

## Core enterprise capabilities now implemented
- Async-like queued scan jobs: `POST /api/jobs/scan`, `GET /api/jobs`.
- Scanner-node observability: `GET /api/scanner-nodes`.
- Report-level detail API: `GET /api/reports/{report_id}`.
- Enterprise portfolio reporting API: `GET /api/reporting/portfolio` (KPIs, risk bands, BU posture, source-tool trends).
- Exposure workflow APIs:
  - `POST /api/exposures/{id}/assign`
  - `POST /api/exposures/{id}/ticket`
  - `POST /api/exposures/{id}/exception-request`
  - `POST /api/exposures/{id}/exception-approve`
  - `GET /api/exposures/sla-breaches`
- Continuous monitor target registration and automation status.

## API Endpoints
- `GET /health`
- `GET /api/summary`
- `GET /api/assets`
- `GET /api/assets/by-url`
- `GET /api/reports`
- `GET /api/reports/{report_id}`
- `GET /api/reports/{report_id}/tool-runs`
- `GET /api/reporting/portfolio`
- `POST /api/scan` (synchronous full scan)
- `POST /api/jobs/scan` (queued prioritized scan)
- `GET /api/jobs`
- `GET /api/scanner-nodes`
- `GET /api/automation`
- `GET /api/monitor-targets`
- `POST /api/monitor-targets`
- `GET /api/exposures`
- `POST /api/exposures/{id}/assign`
- `POST /api/exposures/{id}/ticket`
- `POST /api/exposures/{id}/exception-request`
- `POST /api/exposures/{id}/exception-approve`
- `GET /api/exposures/sla-breaches`
- `POST /api/ingest`

## Run with Docker
```bash
docker compose up --build
```
Open: `http://localhost:8000`

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
