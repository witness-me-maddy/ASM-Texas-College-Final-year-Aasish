"""
Enterprise Asset Models
Comprehensive data models for ASM system
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import uuid

class AssetType(Enum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    SUBNET = "subnet"
    PORT = "port"
    SERVICE = "service"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    CLOUD_RESOURCE = "cloud_resource"
    S3_BUCKET = "s3_bucket"
    CONTAINER = "container"
    KUBERNETES_POD = "kubernetes_pod"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    DATABASE = "database"
    STORAGE_ACCOUNT = "storage_account"
    FUNCTION = "function"
    LOAD_BALANCER = "load_balancer"

class RelationshipType(Enum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    COMMUNICATES_WITH = "communicates_with"
    OWNED_BY = "owned_by"
    DEPENDS_ON = "depends_on"
    EXPOSES = "exposes"
    CONTAINS = "contains"
    AUTHENTICATES_AS = "authenticates_as"
    HAS_ACCESS_TO = "has_access_to"
    DEPLOYED_ON = "deployed_on"
    PROTECTED_BY = "protected_by"
    CONNECTED_TO = "connected_to"
    DERIVED_FROM = "derived_from"
    ISSUED_BY = "issued_by"
    POINTS_TO = "points_to"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ExploitMaturity(Enum):
    UNPROVEN = "unproven"
    PROOF_OF_CONCEPT = "poc"
    FUNCTIONAL = "functional"
    HIGH = "high"
    ACTIVE = "active"

@dataclass
class CVSS:
    version: str = ""
    base_score: float = 0.0
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    vector_string: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""

@dataclass
class CVE:
    cve_id: str
    description: str
    published_date: datetime
    last_modified: datetime
    cvss_v3: Optional[CVSS] = None
    cvss_v2: Optional[CVSS] = None
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    is_in_kev: bool = False
    kev_date_added: Optional[datetime] = None
    exploit_available: bool = False
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNPROVEN
    ransomware_associated: bool = False
    cwe_ids: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

@dataclass
class Vulnerability:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cve: Optional[CVE] = None
    asset_id: str = ""
    vulnerability_type: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    risk_score: float = 0.0
    cvss_score: float = 0.0
    epss_score: float = 0.0
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNPROVEN
    exposure_factor: float = 1.0
    asset_criticality: float = 5.0
    threat_context_score: float = 1.0
    first_detected: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    status: str = "open"
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    scanner_source: str = ""
    raw_finding: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def calculate_risk_score(self, weights: Dict[str, float]) -> float:
        """Calculate advanced risk score using enterprise formula"""
        cvss_normalized = self.cvss_score / 10.0
        epss_normalized = self.epss_score
        
        exploit_map = {
            ExploitMaturity.UNPROVEN: 0.2,
            ExploitMaturity.PROOF_OF_CONCEPT: 0.4,
            ExploitMaturity.FUNCTIONAL: 0.6,
            ExploitMaturity.HIGH: 0.8,
            ExploitMaturity.ACTIVE: 1.0
        }
        exploit_maturity_factor = exploit_map.get(self.exploit_maturity, 0.2)
        
        exposure_factor = min(1.0, self.exposure_factor)
        criticality_factor = min(1.0, self.asset_criticality / 10.0)
        threat_factor = min(1.0, self.threat_context_score / 10.0)
        
        risk = (
            (cvss_normalized ** weights.get('cvss_weight', 0.25)) *
            (epss_normalized ** weights.get('epss_weight', 0.20)) *
            (exploit_maturity_factor ** weights.get('exploit_maturity_weight', 0.15)) *
            (exposure_factor ** weights.get('exposure_weight', 0.15)) *
            (criticality_factor ** weights.get('asset_criticality_weight', 0.15)) *
            (threat_factor ** weights.get('threat_context_weight', 0.10))
        )
        
        self.risk_score = round(risk * 10.0, 2)
        return self.risk_score

@dataclass
class Asset:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_type: AssetType = AssetType.DOMAIN
    value: str = ""
    canonical_value: str = ""
    
    # Identification
    ip_addresses: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    
    # Cloud specific
    cloud_provider: str = ""
    cloud_region: str = ""
    cloud_account_id: str = ""
    resource_arn: str = ""
    resource_tags: Dict[str, str] = field(default_factory=dict)
    
    # DNS & Certificates
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    certificate_info: Optional[Dict[str, Any]] = None
    ssl_grade: str = ""
    
    # Exposure metrics
    exposure_score: float = 0.0
    is_internet_facing: bool = False
    is_public: bool = False
    open_ports_count: int = 0
    admin_panel_exposed: bool = False
    api_exposed: bool = False
    
    # Business context
    business_unit: str = ""
    owner: str = ""
    criticality_score: float = 5.0
    is_crown_jewel: bool = False
    data_classification: str = ""
    
    # Vulnerability summary
    vulnerability_count: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    
    # Timestamps
    first_discovered: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    last_scanned: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Metadata
    source: str = ""
    confidence_score: float = 1.0
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def normalize(self):
        """Normalize asset value based on type"""
        if self.asset_type == AssetType.DOMAIN:
            self.canonical_value = self.value.lower().strip('.')
        elif self.asset_type == AssetType.IP_ADDRESS:
            parts = self.value.split('.')
            if len(parts) == 4:
                self.canonical_value = '.'.join(str(int(p)) for p in parts)
            else:
                self.canonical_value = self.value
        else:
            self.canonical_value = self.value

@dataclass
class Relationship:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    target_id: str = ""
    relationship_type: RelationshipType = RelationshipType.RESOLVES_TO
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_cypher_properties(self) -> str:
        """Convert properties to Cypher format"""
        props = []
        for key, value in self.properties.items():
            if isinstance(value, str):
                props.append(f'{key}: "{value}"')
            elif isinstance(value, (int, float)):
                props.append(f'{key}: {value}')
            elif isinstance(value, bool):
                props.append(f'{key}: {str(value).lower()}')
            elif isinstance(value, datetime):
                props.append(f'{key}: "{value.isoformat()}"')
        return ", ".join(props)

@dataclass
class AttackPath:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    entry_point_asset_id: str = ""
    target_asset_id: str = ""
    path_nodes: List[str] = field(default_factory=list)
    path_relationships: List[Relationship] = field(default_factory=list)
    vulnerabilities_along_path: List[Vulnerability] = field(default_factory=list)
    
    # Scoring
    total_risk_score: float = 0.0
    avg_cvss: float = 0.0
    max_cvss: float = 0.0
    exploitability_score: float = 0.0
    path_length: int = 0
    lateral_movement_hops: int = 0
    
    # Context
    attack_techniques: List[str] = field(default_factory=list)
    mitre_attack_ids: List[str] = field(default_factory=list)
    estimated_time_to_exploit: str = ""
    
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def calculate_scores(self):
        """Calculate attack path scores"""
        self.path_length = len(self.path_nodes)
        self.lateral_movement_hops = max(0, self.path_length - 2)
        
        if self.vulnerabilities_along_path:
            cvss_scores = [v.cvss_score for v in self.vulnerabilities_along_path if v.cvss_score > 0]
            if cvss_scores:
                self.avg_cvss = sum(cvss_scores) / len(cvss_scores)
                self.max_cvss = max(cvss_scores)
            
            risk_scores = [v.risk_score for v in self.vulnerabilities_along_path]
            self.total_risk_score = sum(risk_scores)
            
            exploit_count = sum(1 for v in self.vulnerabilities_along_path 
                              if v.exploit_maturity in [ExploitMaturity.ACTIVE, ExploitMaturity.HIGH])
            self.exploitability_score = exploit_count / len(self.vulnerabilities_along_path) if self.vulnerabilities_along_path else 0

@dataclass
class ScanJob:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: str = ""
    target_assets: List[str] = field(default_factory=list)
    scanner_tool: str = ""
    priority: int = 5
    status: str = "pending"
    scheduled_time: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    findings_count: int = 0
    error_message: str = ""
    worker_id: str = ""
    scan_parameters: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Ticket:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ticket_system: str = ""
    ticket_id: str = ""
    ticket_url: str = ""
    vulnerability_id: str = ""
    asset_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: str = "open"
    assignee: str = ""
    reporter: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    sla_due_date: Optional[datetime] = None
    comments: List[str] = field(default_factory=list)
    raw_ticket_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    asset_ids: List[str] = field(default_factory=list)
    vulnerability_ids: List[str] = field(default_factory=list)
    triggered_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    acknowledged_by: str = ""
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    notification_channels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
