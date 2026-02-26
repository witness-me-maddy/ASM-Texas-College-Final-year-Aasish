from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.connectors.tool_connectors import ToolIngestionAdapter
from app.models import (
    AssignmentRequest,
    ExceptionApprovalRequest,
    ExceptionRequest,
    IngestRequest,
    IngestResult,
    JobSubmissionResponse,
    MonitorRequest,
    MonitorResponse,
    ScanRequest,
    ScanResponse,
    SearchResult,
    TicketRequest,
)
from app.services.epss_service import EPSSService
from app.services.repository import InMemoryRepository
from app.services.scanner_service import ASMScannerService

app = FastAPI(title="Enterprise ASM Platform", version="2.0.0")

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
        "risk_framework": "EPSS + contextual risk",
    }




@app.get("/api/reporting/portfolio")
def reporting_portfolio():
    return {"reporting": repo.reporting_snapshot()}



@app.get("/api/assets/by-url")
def assets_by_url_section():
    return {"sections": repo.url_asset_sections()}

@app.get("/api/assets")
def list_assets():
    return {"assets": repo.list_assets()}


@app.get("/api/reports")
def list_reports():
    return {"reports": repo.list_reports()}


@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    report = repo.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"report": report}


@app.get("/api/jobs")
def list_jobs():
    return {"jobs": repo.list_jobs()}


@app.post("/api/jobs/scan", response_model=JobSubmissionResponse)
def submit_scan_job(payload: ScanRequest):
    job = scanner_service.submit_scan_job(payload)
    return JobSubmissionResponse(job=job)




@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job": job}

@app.get("/api/scanner-nodes")
def list_scanner_nodes():
    return {"nodes": scanner_service.list_nodes()}


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


@app.get("/api/exposures")
def list_exposures():
    return {"exposures": repo.list_exposures()}


@app.post("/api/exposures/{exposure_id}/assign")
def assign_exposure(exposure_id: str, payload: AssignmentRequest):
    exposure = scanner_service.assign_exposure(exposure_id, payload)
    if not exposure:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return {"exposure": exposure}


@app.post("/api/exposures/{exposure_id}/exception-request")
def request_exception(exposure_id: str, payload: ExceptionRequest):
    exposure = scanner_service.request_exception(exposure_id, payload)
    if not exposure:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return {"exposure": exposure}


@app.post("/api/exposures/{exposure_id}/exception-approve")
def approve_exception(exposure_id: str, payload: ExceptionApprovalRequest):
    exposure = scanner_service.approve_exception(exposure_id, payload)
    if not exposure:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return {"exposure": exposure}


@app.post("/api/exposures/{exposure_id}/ticket")
def create_ticket(exposure_id: str, payload: TicketRequest):
    ticket = scanner_service.create_ticket(exposure_id, payload)
    if not ticket:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return {"ticket": ticket}


@app.get("/api/exposures/sla-breaches")
def list_sla_breaches():
    return {"breaches": scanner_service.sla_breaches()}


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
            results.append(SearchResult(asset=asset, risk_band=epss_service.risk_band(max_epss)))
    return results


@app.post("/api/scan", response_model=ScanResponse)
def scan_website(payload: ScanRequest):
    asset, report = scanner_service.scan_website_sync(payload)
    return ScanResponse(report=report, asset=asset)


@app.post("/api/ingest", response_model=IngestResult)
def ingest_findings(payload: IngestRequest):
    grouped: dict[str, list] = {}
    for finding in payload.findings:
        grouped.setdefault(finding.target, []).append(finding)

    ingested = len(payload.findings)
    created = 0
    deduped = 0

    for target, findings in grouped.items():
        asset = repo.upsert_asset(name=target, owner="Automated Discovery", business_unit="Security Operations")
        exposures = ingestion_adapter.normalize(findings, criticality=asset.criticality, internet_exposed=asset.internet_exposed)
        c, d = repo.add_exposures(asset.id, exposures)
        created += c
        deduped += d

    return IngestResult(ingested=ingested, exposures_created=created, exposures_updated=deduped)
