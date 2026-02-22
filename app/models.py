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
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ExceptionStatus(str, Enum):
    none = "none"
    requested = "requested"
    approved = "approved"
    rejected = "rejected"


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
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    source_tool: str
    discovered_at: datetime
    status: ExposureStatus = ExposureStatus.open
    asset_id: Optional[str] = None
    fingerprint: Optional[str] = None
    duplicate_of: Optional[str] = None
    assignee: Optional[str] = None
    ticket_id: Optional[str] = None
    sla_due_at: Optional[datetime] = None
    exception_status: ExceptionStatus = ExceptionStatus.none
    exception_requested_by: Optional[str] = None
    exception_reason: Optional[str] = None
    exception_expires_at: Optional[datetime] = None
    exception_approved_by: Optional[str] = None


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
    priority: int = Field(default=5, ge=1, le=10)


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
    queued_jobs: int = 0


class ScanJob(BaseModel):
    id: str
    website_url: HttpUrl
    priority: int
    status: ScanStatus
    attempts: int = 0
    max_attempts: int = 3
    next_retry_at: Optional[datetime] = None
    error: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    report_id: Optional[str] = None


class ScannerNode(BaseModel):
    id: str
    status: str
    last_heartbeat_at: datetime
    active_job_id: Optional[str] = None


class TicketRecord(BaseModel):
    id: str
    provider: str
    external_key: str
    exposure_id: str
    status: str
    created_at: datetime


class AssignmentRequest(BaseModel):
    assignee: str


class ExceptionRequest(BaseModel):
    requested_by: str
    reason: str
    expires_at: datetime


class ExceptionApprovalRequest(BaseModel):
    approved_by: str


class TicketRequest(BaseModel):
    provider: str = "jira"


class JobSubmissionResponse(BaseModel):
    job: ScanJob
