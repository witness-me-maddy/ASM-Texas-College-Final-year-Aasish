from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class AssetType(str, Enum):
    domain = "domain"
    ip = "ip"
    cloud_resource = "cloud_resource"
    web_app = "web_app"


class ExposureStatus(str, Enum):
    open = "open"
    mitigated = "mitigated"
    accepted = "accepted"


class ScanStatus(str, Enum):
    completed = "completed"


class GeoPosition(BaseModel):
    city: str
    country: str
    latitude: float
    longitude: float


class OpenPort(BaseModel):
    port: int
    protocol: str
    service: str
    state: str = "open"


class Exposure(BaseModel):
    id: str
    title: str
    description: str
    cve: Optional[str] = None
    epss_score: float = Field(..., ge=0.0, le=1.0)
    epss_percentile: float = Field(..., ge=0.0, le=1.0)
    source_tool: str
    discovered_at: datetime
    status: ExposureStatus = ExposureStatus.open


class Asset(BaseModel):
    id: str
    name: str
    type: AssetType
    owner: str
    business_unit: str
    internet_exposed: bool = True
    criticality: int = Field(..., ge=1, le=5)
    tags: List[str] = Field(default_factory=list)
    position: Optional[GeoPosition] = None
    open_ports: List[OpenPort] = Field(default_factory=list)
    exposures: List[Exposure] = Field(default_factory=list)


class Summary(BaseModel):
    asset_count: int
    open_exposure_count: int
    high_risk_exposure_count: int
    internet_exposed_assets: int
    mean_epss: float


class ToolFinding(BaseModel):
    tool_name: str
    target: str
    finding_id: str
    title: str
    severity_hint: str
    cve: Optional[str] = None
    evidence_url: Optional[HttpUrl] = None


class IngestRequest(BaseModel):
    findings: List[ToolFinding]


class IngestResult(BaseModel):
    ingested: int
    exposures_created: int
    exposures_updated: int


class SearchResult(BaseModel):
    asset: Asset
    risk_band: str


class ScanRequest(BaseModel):
    website_url: HttpUrl


class MonitoredTarget(BaseModel):
    id: str
    website_url: HttpUrl
    enabled: bool = True
    scan_interval_seconds: int = Field(default=60, ge=10)
    last_scan_at: Optional[datetime] = None


class MonitorRequest(BaseModel):
    website_url: HttpUrl
    scan_interval_seconds: int = Field(default=60, ge=10)


class MonitorResponse(BaseModel):
    target: MonitoredTarget


class ScanReport(BaseModel):
    id: str
    website_url: HttpUrl
    target_host: str
    status: ScanStatus
    started_at: datetime
    completed_at: datetime
    tools_executed: List[str]
    scanned_port_range: str = "1-65535"
    assets_discovered: int
    exposures_discovered: int
    max_epss_score: float
    max_epss_percentile: float
    target_position: Optional[GeoPosition] = None
    open_ports: List[OpenPort] = Field(default_factory=list)
    discovered_subdomains: List[str] = Field(default_factory=list)
    discovered_ips: List[str] = Field(default_factory=list)
    discovered_technologies: List[str] = Field(default_factory=list)
    discovered_urls: List[str] = Field(default_factory=list)
    discovered_emails: List[str] = Field(default_factory=list)
    discovered_cloud_assets: List[str] = Field(default_factory=list)
    waf_detected: Optional[str] = None
    top_exposures: List[Exposure] = Field(default_factory=list)


class ScanResponse(BaseModel):
    report: ScanReport
    asset: Asset


class AutomationStatus(BaseModel):
    running: bool
    monitored_target_count: int
    last_cycle_at: Optional[datetime] = None
