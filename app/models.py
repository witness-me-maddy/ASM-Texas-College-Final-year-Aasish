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


class ScanReport(BaseModel):
    id: str
    website_url: HttpUrl
    target_host: str
    status: ScanStatus
    started_at: datetime
    completed_at: datetime
    tools_executed: List[str]
    assets_discovered: int
    exposures_discovered: int
    max_epss_score: float
    max_epss_percentile: float
    top_exposures: List[Exposure] = Field(default_factory=list)


class ScanResponse(BaseModel):
    report: ScanReport
    asset: Asset
