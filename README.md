# Enterprise Attack Surface Management (ASM) Platform

An enterprise-ready ASM system with:
- **EPSS-first risk prioritization** (no CVSS scoring dependency in ranking).
- **URL-driven and continuous scanning** (manual and automated cycles).
- **Position-aware asset visibility** (city/country + coordinates).
- **Open port and service inventory** per scan result.
- **Integrated tool ingestion pipeline** for scanner findings.
- **Pro-level frontend dashboard** for SOC and vulnerability teams.

## Why EPSS over CVSS
This platform prioritizes vulnerabilities using **Exploit Prediction Scoring System (EPSS)** probabilities and percentiles so teams focus on likely exploitation.

## Core ASM Features Delivered
- Manual website scan (`POST /api/scan`).
- Continuous scan automation service (background loop started on app startup).
- Target monitoring registration (`POST /api/monitor-targets`).
- Automation visibility (`GET /api/automation`).
- Historical report listing with position + open ports + EPSS-ranked vulnerabilities (`GET /api/reports`).
- Asset inventory with location, open services, exposures, and EPSS risk bands.

## Architecture

### Backend (`FastAPI`)
- Asset and exposure model with EPSS score/percentile.
- Position model (`GeoPosition`) and network attack surface model (`OpenPort`).
- Scan orchestration service that simulates enterprise ASM engines (Nmap/Nuclei/ZAP/SSLyze/WhatWeb).
- Continuous automation loop that repeatedly scans monitored targets by interval.

### Frontend
- Enterprise dark dashboard UX.
- Continuous monitoring target table.
- Scan history with target position and open ports.
- Top EPSS findings feed.
- Searchable asset inventory.

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

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
