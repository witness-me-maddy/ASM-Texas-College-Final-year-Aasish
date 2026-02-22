from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.connectors.tool_connectors import ToolIngestionAdapter
from app.models import (
    IngestRequest,
    IngestResult,
    MonitorRequest,
    MonitorResponse,
    ScanRequest,
    ScanResponse,
    SearchResult,
)
from app.services.epss_service import EPSSService
from app.services.repository import InMemoryRepository
from app.services.scanner_service import ASMScannerService

app = FastAPI(title="Enterprise ASM Platform", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

repo = InMemoryRepository()
epss_service = EPSSService()
ingestion_adapter = ToolIngestionAdapter(epss_service)
scanner_service = ASMScannerService(repo, ingestion_adapter, epss_service)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")


@app.on_event("startup")
def startup_event() -> None:
    scanner_service.start_automation()


@app.on_event("shutdown")
def shutdown_event() -> None:
    scanner_service.stop_automation()


@app.get("/")
def home() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/summary")
def get_summary():
    return {
        "summary": repo.summary(),
        "open_exposures_by_business_unit": repo.group_by_business_unit(),
        "risk_framework": "EPSS-first",
    }


@app.get("/api/assets")
def list_assets():
    return {"assets": repo.list_assets()}


@app.get("/api/reports")
def list_reports():
    return {"reports": repo.list_reports()}


@app.get("/api/automation")
def automation_status():
    return {"automation": scanner_service.automation_status()}


@app.get("/api/monitor-targets")
def list_monitor_targets():
    return {"targets": repo.list_monitored_targets()}


@app.post("/api/monitor-targets", response_model=MonitorResponse)
def register_monitor_target(payload: MonitorRequest):
    target = scanner_service.register_target(payload)
    return MonitorResponse(target=target)




@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    report = repo.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"report": report}

@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: str):
    asset = repo.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"asset": asset}


@app.get("/api/search", response_model=list[SearchResult])
def search_assets(query: str):
    results: list[SearchResult] = []
    for asset in repo.list_assets():
        if query.lower() in asset.name.lower() or query.lower() in asset.owner.lower():
            max_epss = max((e.epss_score for e in asset.exposures), default=0.0)
            results.append(
                SearchResult(asset=asset, risk_band=epss_service.risk_band(max_epss))
            )
    return results


@app.post("/api/scan", response_model=ScanResponse)
def scan_website(payload: ScanRequest):
    asset, report = scanner_service.scan_website(payload)
    return ScanResponse(report=report, asset=asset)


@app.post("/api/ingest", response_model=IngestResult)
def ingest_findings(payload: IngestRequest):
    grouped: dict[str, list] = {}
    for finding in payload.findings:
        grouped.setdefault(finding.target, []).append(finding)

    ingested = len(payload.findings)
    created = 0

    for target, findings in grouped.items():
        asset = repo.upsert_asset(
            name=target,
            owner="Automated Discovery",
            business_unit="Security Operations",
        )
        exposures = ingestion_adapter.normalize(findings)
        created += repo.add_exposures(asset.id, exposures)

    return IngestResult(ingested=ingested, exposures_created=created, exposures_updated=0)
