"""
FastAPI REST API Layer
Enterprise endpoints for dashboard consumption
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Security, Query
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
import asyncio
import logging
import os

from config.settings import ASMConfig, load_config
from core.models import Asset, Vulnerability, AttackPath, Severity, AssetType
from integrations.intelligence import (
    ShodanIntegration, CensysIntegration, AWSIntegration,
    CertificateTransparencyIntegration, GitHubLeakDetection
)
from graph.neo4j_engine import Neo4jGraphEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Enterprise ASM API",
    description="Attack Surface Management REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)

# Global instances
config = None
graph_engine = None
shodan = None
censys = None
aws_integration = None
ct_integration = None

# In-memory storage (replace with database in production)
assets_db: Dict[str, Asset] = {}
vulnerabilities_db: Dict[str, Vulnerability] = {}
scan_jobs_db: Dict[str, Dict] = {}


def get_config() -> ASMConfig:
    """Get configuration"""
    global config
    if config is None:
        config = load_config()
    return config


async def get_graph_engine() -> Neo4jGraphEngine:
    """Get or create graph engine"""
    global graph_engine
    if graph_engine is None:
        try:
            cfg = get_config()
            graph_engine = Neo4jGraphEngine(cfg)
            graph_engine.create_indexes()
        except Exception as e:
            logger.warning(f"Graph engine not available: {e}")
    return graph_engine


async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """Verify API key"""
    expected_key = os.getenv("ASM_API_KEY", "dev-key-123")
    if api_key != expected_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key


# Pydantic models for request/response
class AssetSearchRequest(BaseModel):
    query: str
    asset_types: Optional[List[str]] = None
    limit: int = Field(default=100, ge=1, le=1000)


class AssetResponse(BaseModel):
    id: str
    asset_type: str
    value: str
    canonical_value: Optional[str]
    ip_addresses: List[str]
    ports: List[int]
    services: List[str]
    exposure_score: float
    is_internet_facing: bool
    is_public: bool
    criticality_score: float
    vulnerability_count: int
    source: str
    first_discovered: datetime
    last_seen: datetime


class VulnerabilityResponse(BaseModel):
    id: str
    cve_id: Optional[str]
    title: str
    severity: str
    risk_score: float
    cvss_score: float
    epss_score: float
    status: str
    asset_id: str
    first_detected: datetime


class AttackPathResponse(BaseModel):
    id: str
    name: str
    entry_point_asset_id: str
    target_asset_id: str
    path_nodes: List[str]
    path_length: int
    total_risk_score: float
    lateral_movement_hops: int


class DashboardStats(BaseModel):
    total_assets: int
    internet_facing_assets: int
    crown_jewels: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    attack_paths_found: int
    avg_exposure_score: float
    assets_by_type: Dict[str, int]
    vulnerabilities_by_severity: Dict[str, int]


class ScanRequest(BaseModel):
    targets: List[str]
    scan_type: str = "full"
    priority: int = Field(default=5, ge=1, le=10)
    scanners: Optional[List[str]] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# Startup/Shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global shodan, censys, aws_integration, ct_integration
    cfg = get_config()
    shodan = ShodanIntegration(cfg)
    censys = CensysIntegration(cfg)
    aws_integration = AWSIntegration(cfg)
    ct_integration = CertificateTransparencyIntegration(cfg)
    logger.info("ASM API started")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global graph_engine, shodan, censys
    if graph_engine:
        graph_engine.close()
    if shodan:
        await shodan.close()
    if censys:
        await censys.close()
    logger.info("ASM API shutdown complete")


# API Endpoints
@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Enterprise ASM API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/stats", response_model=DashboardStats, tags=["Dashboard"])
async def get_dashboard_stats(api_key: str = Depends(verify_api_key)):
    """Get dashboard statistics"""
    graph = await get_graph_engine()
    
    stats = {
        "total_assets": len(assets_db),
        "internet_facing_assets": 0,
        "crown_jewels": 0,
        "total_vulnerabilities": len(vulnerabilities_db),
        "critical_vulnerabilities": 0,
        "high_vulnerabilities": 0,
        "attack_paths_found": 0,
        "avg_exposure_score": 0.0,
        "assets_by_type": {},
        "vulnerabilities_by_severity": {}
    }
    
    # Calculate from graph if available
    if graph:
        try:
            graph_stats = graph.calculate_graph_statistics()
            stats["total_assets"] = int(graph_stats.get('total_assets', stats["total_assets"]))
            stats["internet_facing_assets"] = int(graph_stats.get('internet_facing', 0))
            stats["crown_jewels"] = int(graph_stats.get('crown_jewels', 0))
            stats["avg_exposure_score"] = round(graph_stats.get('avg_exposure', 0), 2)
        except:
            pass
    
    # Calculate from memory
    for asset in assets_db.values():
        if asset.is_internet_facing:
            stats["internet_facing_assets"] += 1
        if asset.criticality_score >= 8.0:
            stats["crown_jewels"] += 1
        
        asset_type = asset.asset_type.value
        stats["assets_by_type"][asset_type] = stats["assets_by_type"].get(asset_type, 0) + 1
    
    for vuln in vulnerabilities_db.values():
        severity = vuln.severity.value
        stats["vulnerabilities_by_severity"][severity] = \
            stats["vulnerabilities_by_severity"].get(severity, 0) + 1
        
        if vuln.severity == Severity.CRITICAL:
            stats["critical_vulnerabilities"] += 1
        elif vuln.severity == Severity.HIGH:
            stats["high_vulnerabilities"] += 1
    
    return DashboardStats(**stats)


@app.get("/api/v1/assets", response_model=List[AssetResponse], tags=["Assets"])
async def list_assets(
    asset_type: Optional[str] = None,
    is_internet_facing: Optional[bool] = None,
    min_exposure: Optional[float] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    api_key: str = Depends(verify_api_key)
):
    """List all assets with optional filters"""
    filtered = []
    
    for asset in assets_db.values():
        if asset_type and asset.asset_type.value != asset_type:
            continue
        if is_internet_facing is not None and asset.is_internet_facing != is_internet_facing:
            continue
        if min_exposure and asset.exposure_score < min_exposure:
            continue
        
        filtered.append(asset)
        
        if len(filtered) >= limit:
            break
    
    return [
        AssetResponse(
            id=a.id,
            asset_type=a.asset_type.value,
            value=a.value,
            canonical_value=a.canonical_value,
            ip_addresses=a.ip_addresses,
            ports=a.ports,
            services=a.services,
            exposure_score=a.exposure_score,
            is_internet_facing=a.is_internet_facing,
            is_public=a.is_public,
            criticality_score=a.criticality_score,
            vulnerability_count=a.vulnerability_count,
            source=a.source,
            first_discovered=a.first_discovered,
            last_seen=a.last_seen
        )
        for a in filtered
    ]


@app.get("/api/v1/assets/{asset_id}", response_model=AssetResponse, tags=["Assets"])
async def get_asset(asset_id: str, api_key: str = Depends(verify_api_key)):
    """Get a specific asset by ID"""
    if asset_id not in assets_db:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    asset = assets_db[asset_id]
    return AssetResponse(
        id=asset.id,
        asset_type=asset.asset_type.value,
        value=asset.value,
        canonical_value=asset.canonical_value,
        ip_addresses=asset.ip_addresses,
        ports=asset.ports,
        services=asset.services,
        exposure_score=asset.exposure_score,
        is_internet_facing=asset.is_internet_facing,
        is_public=asset.is_public,
        criticality_score=asset.criticality_score,
        vulnerability_count=asset.vulnerability_count,
        source=asset.source,
        first_discovered=asset.first_discovered,
        last_seen=asset.last_seen
    )


@app.post("/api/v1/assets/discover", tags=["Assets"])
async def discover_assets(
    domains: List[str],
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """Discover assets from domains using all intelligence sources"""
    global ct_integration, shodan, censys
    
    discovered_count = 0
    
    # Certificate Transparency
    async for asset in ct_integration.discover_assets(domains):
        assets_db[asset.id] = asset
        discovered_count += 1
    
    # Shodan (if configured)
    if get_config().shodan.api_key:
        async for asset in shodan.discover_assets(domains):
            assets_db[asset.id] = asset
            discovered_count += 1
    
    return {
        "message": f"Discovered {discovered_count} assets",
        "domains_scanned": domains,
        "assets_found": discovered_count
    }


@app.get("/api/v1/vulnerabilities", response_model=List[VulnerabilityResponse], tags=["Vulnerabilities"])
async def list_vulnerabilities(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    min_risk_score: Optional[float] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    api_key: str = Depends(verify_api_key)
):
    """List vulnerabilities with filters"""
    filtered = []
    
    for vuln in vulnerabilities_db.values():
        if severity and vuln.severity.value != severity:
            continue
        if status and vuln.status != status:
            continue
        if min_risk_score and vuln.risk_score < min_risk_score:
            continue
        
        filtered.append(vuln)
        
        if len(filtered) >= limit:
            break
    
    return [
        VulnerabilityResponse(
            id=v.id,
            cve_id=v.cve.cve_id if v.cve else None,
            title=v.title,
            severity=v.severity.value,
            risk_score=v.risk_score,
            cvss_score=v.cvss_score,
            epss_score=v.epss_score,
            status=v.status,
            asset_id=v.asset_id,
            first_detected=v.first_detected
        )
        for v in filtered
    ]


@app.get("/api/v1/attack-paths", response_model=List[AttackPathResponse], tags=["Attack Paths"])
async def list_attack_paths(
    max_depth: int = Query(default=5, ge=1, le=10),
    api_key: str = Depends(verify_api_key)
):
    """Find attack paths from entry points to crown jewels"""
    graph = await get_graph_engine()
    
    if not graph:
        raise HTTPException(status_code=503, detail="Graph engine not available")
    
    # Get entry points and crown jewels
    entry_points = graph.get_entry_points()
    crown_jewels = graph.get_crown_jewels()
    
    if not entry_points or not crown_jewels:
        return []
    
    # Find paths
    paths = graph.find_attack_paths(
        [ep['id'] for ep in entry_points[:5]],
        [cj['id'] for cj in crown_jewels[:5]],
        max_depth=max_depth
    )
    
    return [
        AttackPathResponse(
            id=p.id,
            name=p.name,
            entry_point_asset_id=p.entry_point_asset_id,
            target_asset_id=p.target_asset_id,
            path_nodes=p.path_nodes,
            path_length=p.path_length,
            total_risk_score=p.total_risk_score,
            lateral_movement_hops=p.lateral_movement_hops
        )
        for p in paths
    ]


@app.post("/api/v1/scans", response_model=ScanResponse, tags=["Scanning"])
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """Create a new scan job"""
    import uuid
    
    scan_id = str(uuid.uuid4())
    scan_job = {
        "id": scan_id,
        "targets": scan_request.targets,
        "scan_type": scan_request.scan_type,
        "priority": scan_request.priority,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "scanners": scan_request.scanners or ["nuclei", "nmap"]
    }
    
    scan_jobs_db[scan_id] = scan_job
    
    # Queue scan in background
    background_tasks.add_task(run_scan, scan_id)
    
    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan {scan_id} created for {len(scan_request.targets)} targets"
    )


async def run_scan(scan_id: str):
    """Background task to run a scan"""
    if scan_id not in scan_jobs_db:
        return
    
    scan_job = scan_jobs_db[scan_id]
    scan_job["status"] = "running"
    scan_job["started_at"] = datetime.utcnow().isoformat()
    
    try:
        # Simulate scanning (integrate with Nuclei/Nmap workers in production)
        await asyncio.sleep(5)
        
        scan_job["status"] = "completed"
        scan_job["completed_at"] = datetime.utcnow().isoformat()
        scan_job["findings_count"] = 0
        
    except Exception as e:
        scan_job["status"] = "failed"
        scan_job["error_message"] = str(e)


@app.get("/api/v1/scans/{scan_id}", tags=["Scanning"])
async def get_scan_status(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Get scan job status"""
    if scan_id not in scan_jobs_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_jobs_db[scan_id]


@app.get("/api/v1/entry-points", tags=["Analysis"])
async def get_entry_points(api_key: str = Depends(verify_api_key)):
    """Get all internet-facing entry points"""
    graph = await get_graph_engine()
    
    if graph:
        return graph.get_entry_points()
    
    # Fallback to memory
    entry_points = [
        {
            "id": a.id,
            "value": a.value,
            "asset_type": a.asset_type.value,
            "exposure_score": a.exposure_score,
            "open_ports_count": a.open_ports_count,
            "admin_panel_exposed": a.admin_panel_exposed
        }
        for a in assets_db.values()
        if a.is_internet_facing or a.is_public
    ]
    
    return sorted(entry_points, key=lambda x: x['exposure_score'], reverse=True)[:50]


@app.get("/api/v1/crown-jewels", tags=["Analysis"])
async def get_crown_jewels(api_key: str = Depends(verify_api_key)):
    """Get crown jewel assets"""
    graph = await get_graph_engine()
    
    if graph:
        return graph.get_crown_jewels()
    
    # Fallback to memory
    crown_jewels = [
        {
            "id": a.id,
            "value": a.value,
            "asset_type": a.asset_type.value,
            "criticality_score": a.criticality_score,
            "business_unit": a.business_unit,
            "data_classification": a.data_classification
        }
        for a in assets_db.values()
        if a.criticality_score >= 8.0 or a.is_crown_jewel
    ]
    
    return sorted(crown_jewels, key=lambda x: x['criticality_score'], reverse=True)[:50]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
