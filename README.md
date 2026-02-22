# Enterprise Attack Surface Management (ASM) Platform

An enterprise-ready ASM system with:
- **EPSS-first risk prioritization** (no CVSS scoring dependency in ranking).
- **One-click full URL scan** (no port selection required by user).
- **Full port sweep simulation (1-65535)** and open service discovery.
- **Continuous automated scanning** for monitored targets.
- **Toolchain-integrated findings** from Nmap, Subfinder, Masscan, Nikto, Assetfinder, Nuclei, Amass, httpx, Naabu, and Wafw00f.
- **Position-aware asset visibility** (city/country + coordinates).

## Why EPSS over CVSS
This platform prioritizes vulnerabilities using **Exploit Prediction Scoring System (EPSS)** probabilities and percentiles so teams focus on likely exploitation.

## Core ASM Features Delivered
- Manual website scan (`POST /api/scan`) that scans the entire target attack surface.
- Continuous scan automation (background loop started on app startup).
- Target monitoring registration (`POST /api/monitor-targets`).
- Automation visibility (`GET /api/automation`).
- Historical report listing with position + open ports + tools + EPSS-ranked vulnerabilities (`GET /api/reports`).
- Clickable scan history rows in frontend to open deep target intelligence (URLs, emails, cloud assets, WAF, technologies).
- Asset inventory with location, open services, exposures, and EPSS risk bands.

## API Endpoints
- `GET /health`
- `GET /api/summary`
- `GET /api/assets`
- `GET /api/search?query=...`
- `POST /api/scan`
- `GET /api/reports`
- `GET /api/automation`
- `GET /api/monitor-targets`
- `POST /api/monitor-targets`
- `POST /api/ingest`

## Run with Docker (recommended after downloading ZIP)
```bash
docker compose up --build
```

Then open: `http://localhost:8000`

To run detached:
```bash
docker compose up --build -d
```

To stop:
```bash
docker compose down
```

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
