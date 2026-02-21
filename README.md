# Enterprise Attack Surface Management (ASM) Platform

An enterprise-ready ASM system with:
- **EPSS-first risk prioritization** (no CVSS scoring dependency in ranking).
- **URL-driven ASM scanning workflow** (enter website URL → scan → report generation).
- **Integrated tool ingestion pipeline** for scanner findings.
- **Pro-level frontend dashboard with executive UX** for SOC and vulnerability management teams.
- **API-driven architecture** for SIEM/SOAR and ticketing integrations.

## Why EPSS over CVSS
This platform prioritizes exposures using **Exploit Prediction Scoring System (EPSS)** probabilities and percentiles to emphasize exploit likelihood in the wild.

## Architecture

### Backend (`FastAPI`)
- Asset inventory and ownership model.
- Exposure model enriched with EPSS score + percentile.
- Unified ingestion endpoint to normalize findings from tools (Nmap, Nessus, Burp, Nuclei, etc.).
- URL-based scan endpoint that simulates full attack-surface checks and generates persistent scan reports.
- Search and reporting endpoints.

### Frontend (Vanilla JS + modern CSS)
- Website scan form (enter URL and run scan).
- Generated reports table with tools executed, exposure count, and max EPSS.
- Executive KPI cards and modern split-pane SOC layout.
- Business-unit exposure pressure chart.
- Top EPSS findings feed for rapid triage.
- Searchable asset inventory with EPSS risk badges.

## Project Structure

```text
app/
  main.py
  models.py
  connectors/tool_connectors.py
  services/epss_service.py
  services/repository.py
  services/scanner_service.py
frontend/
  index.html
  styles.css
  app.js
tests/
  test_api.py
requirements.txt
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`.

## API Endpoints

- `GET /health`
- `GET /api/summary`
- `GET /api/assets`
- `GET /api/assets/{asset_id}`
- `GET /api/search?query=...`
- `POST /api/scan`
- `GET /api/reports`
- `POST /api/ingest`

## Example scan payload

```json
{
  "website_url": "https://example.com"
}
```

## Enterprise roadmap
- Replace deterministic EPSS estimator with live EPSS feed + cache.
- Add asynchronous scan workers (Celery/RQ/Kafka), schedules, and retries.
- Add SSO/SAML + RBAC and audit trails.
- Add PostgreSQL/Redis and background workers.
- Add connectors for cloud CSPM, EDR, ASM external scans, bug bounty, and ticketing sync.
- Add workflow automation (SLA policies, auto-routing, Jira/ServiceNow).
