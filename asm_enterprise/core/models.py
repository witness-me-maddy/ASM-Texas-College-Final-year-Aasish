"""
Enterprise ASM System - Core Data Models
Comprehensive data models for assets, vulnerabilities, findings, and relationships
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set
from datetime import datetime
from enum import Enum
import uuid
import hashlib


class AssetType(Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    CIDR_BLOCK = "cidr_block"
    ASN = "asn"
    CLOUD_RESOURCE = "cloud_resource"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    CERTIFICATE = "certificate"
    STORAGE_BUCKET = "storage_bucket"
    DATABASE = "database"
    CONTAINER = "container"
    KUBERNETES_RESOURCE = "k8s_resource"
    IAM_ENTITY = "iam_entity"
    USER_ACCOUNT = "user_account"
    SERVICE_ACCOUNT = "service_account"
    GIT_REPOSITORY = "git_repository"
    THIRD_PARTY_SERVICE = "third_party_service"
    UNKNOWN = "unknown"


class AssetStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    DECOMMISSIONED = "decommissioned"
    PENDING_VERIFICATION = "pending_verification"


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA = "alibaba"
    OCI = "oci"
    IBM = "ibm"
    DIGITALOCEAN = "digitalocean"
    LINODE = "linode"
    VULTR = "vultr"
    OTHER = "other"


class ServiceProtocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    RDP = "rdp"
    SMB = "smb"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    REDIS = "redis"
    ELASTICSEARCH = "elasticsearch"
    KAFKA = "kafka"
    GRPC = "grpc"
    CUSTOM = "custom"


class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ExploitMaturity(Enum):
    NOT_EXPLOITABLE = "not_exploitable"
    PROOF_OF_CONCEPT = "poc"
    FUNCTIONAL = "functional"
    HIGH = "high"  # Exploit code is widely available
    ACTIVE = "active"  # Actively exploited in the wild


class FindingStatus(Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    REOPENED = "reopened"


class RelationshipType(Enum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    COMMUNICATES_WITH = "communicates_with"
    OWNED_BY = "owned_by"
    DEPENDS_ON = "depends_on"
    CONNECTED_TO = "connected_to"
    AUTHENTICATES_AS = "authenticates_as"
    EXPOSES = "exposes"
    CONTAINS = "contains"
    BELONGS_TO = "belongs_to"
    SERVES = "serves"
    PROXIES_TO = "proxies_to"
    LOAD_BALANCES = "load_balances"
    MONITORS = "monitors"
    MANAGES = "manages"


@dataclass
class GeoLocation:
    """Geographic location information"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[int] = None
    org: Optional[str] = None


@dataclass
class TLSInfo:
    """TLS/SSL certificate information"""
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    san_domains: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None


@dataclass
class Service:
    """Network service information"""
    port: int
    protocol: ServiceProtocol
    state: str = "open"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    banner: Optional[str] = None
    scripts: Dict[str, Any] = field(default_factory=dict)
    tls_info: Optional[TLSInfo] = None
    last_seen: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Asset:
    """Core asset representation with comprehensive metadata"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_type: AssetType = AssetType.UNKNOWN
    value: str = ""
    
    # Identification
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    labels: Dict[str, str] = field(default_factory=dict)
    
    # Ownership
    owner: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    cost_center: Optional[str] = None
    
    # Classification
    criticality: float = 0.5  # 0.0 to 1.0
    sensitivity: str = "internal"  # public, internal, confidential, restricted
    data_classification: Optional[str] = None
    
    # Status
    status: AssetStatus = AssetStatus.UNKNOWN
    first_discovered: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    last_verified: Optional[datetime] = None
    
    # Network information
    ip_addresses: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    
    # Cloud specific
    cloud_provider: Optional[CloudProvider] = None
    cloud_region: Optional[str] = None
    cloud_account_id: Optional[str] = None
    cloud_resource_id: Optional[str] = None
    cloud_resource_type: Optional[str] = None
    cloud_tags: Dict[str, str] = field(default_factory=dict)
    
    # DNS information
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    reverse_dns: List[str] = field(default_factory=list)
    
    # Geographic
    geo_location: Optional[GeoLocation] = None
    
    # Technology stack
    technologies: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    programming_languages: List[str] = field(default_factory=list)
    
    # External references
    external_ids: Dict[str, str] = field(default_factory=dict)
    source_urls: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Risk indicators
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    
    # Compliance
    compliance_status: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if not isinstance(other, Asset):
            return False
        return self.id == other.id
    
    def add_service(self, service: Service):
        """Add a service to the asset"""
        self.services.append(service)
        if service.port not in self.ports:
            self.ports.append(service.port)
        self.updated_at = datetime.utcnow()
    
    def update_risk_score(self, score: float):
        """Update the risk score"""
        self.risk_score = max(0.0, min(1.0, score))
        self.updated_at = datetime.utcnow()
    
    def add_tag(self, tag: str):
        """Add a tag to the asset"""
        self.tags.add(tag)
        self.updated_at = datetime.utcnow()
    
    def merge(self, other: 'Asset'):
        """Merge another asset into this one"""
        # Merge IP addresses
        for ip in other.ip_addresses:
            if ip not in self.ip_addresses:
                self.ip_addresses.append(ip)
        
        # Merge services
        for service in other.services:
            if not any(s.port == service.port and s.protocol == service.protocol 
                      for s in self.services):
                self.services.append(service)
        
        # Merge tags
        self.tags.update(other.tags)
        
        # Merge labels
        self.labels.update(other.labels)
        
        # Merge technologies
        for tech in other.technologies:
            if tech not in self.technologies:
                self.technologies.append(tech)
        
        # Update timestamps
        if other.first_discovered < self.first_discovered:
            self.first_discovered = other.first_discovered
        
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen
        
        self.updated_at = datetime.utcnow()


@dataclass
class Relationship:
    """Relationship between two assets"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_asset_id: str = ""
    target_asset_id: str = ""
    relationship_type: RelationshipType = RelationshipType.CONNECTED_TO
    
    # Additional properties
    properties: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    first_discovered: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0
    source: str = "auto_discovery"
    
    def __hash__(self):
        return hash((self.source_asset_id, self.target_asset_id, 
                    self.relationship_type.value))


@dataclass
class CVE:
    """Common Vulnerabilities and Exposures information"""
    cve_id: str = ""
    description: str = ""
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    url: Optional[str] = None
    
    # CVSS v3.1
    cvss_version: str = "3.1"
    cvss_base_score: float = 0.0
    cvss_vector_string: Optional[str] = None
    
    # CVSS metrics
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    
    # EPSS
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[datetime] = None
    
    # Exploit information
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_EXPLOITABLE
    has_exploit: bool = False
    exploit_count: int = 0
    exploit_sources: List[str] = field(default_factory=list)
    
    # Threat intelligence
    is_in_kev: bool = False  # CISA Known Exploited Vulnerabilities
    kev_date_added: Optional[datetime] = None
    ransomware_associated: bool = False
    actively_exploited: bool = False
    
    # References
    references: List[str] = field(default_factory=list)
    weakneses: List[str] = field(default_factory=list)  # CWE IDs
    
    # Vendor information
    vendor_advisories: List[Dict[str, Any]] = field(default_factory=list)
    patches_available: bool = False
    patch_urls: List[str] = field(default_factory=list)
    
    def calculate_priority_score(self) -> float:
        """Calculate priority score based on multiple factors"""
        base_score = self.cvss_base_score / 10.0
        
        # EPSS factor
        epss_factor = self.epss_score if self.epss_score else 0.0
        
        # Exploit maturity factor
        maturity_scores = {
            ExploitMaturity.ACTIVE: 1.0,
            ExploitMaturity.HIGH: 0.9,
            ExploitMaturity.FUNCTIONAL: 0.7,
            ExploitMaturity.PROOF_OF_CONCEPT: 0.5,
            ExploitMaturity.NOT_EXPLOITABLE: 0.1
        }
        exploit_factor = maturity_scores.get(self.exploit_maturity, 0.1)
        
        # KEV factor (actively exploited)
        kev_factor = 1.0 if self.is_in_kev or self.actively_exploited else 0.5
        
        # Ransomware factor
        ransomware_factor = 1.0 if self.ransomware_associated else 0.8
        
        # Weighted calculation
        priority = (
            base_score * 0.30 +
            epss_factor * 0.25 +
            exploit_factor * 0.20 +
            kev_factor * 0.15 +
            ransomware_factor * 0.10
        )
        
        return min(1.0, priority)


@dataclass
class Vulnerability:
    """Vulnerability instance found on an asset"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Identification
    vulnerability_type: str = ""  # CVE, misconfiguration, exposure, etc.
    vulnerability_id: str = ""  # CVE-ID or custom ID
    title: str = ""
    description: str = ""
    
    # Associated CVE
    cve: Optional[CVE] = None
    
    # Asset association
    asset_id: str = ""
    asset_details: Optional[Asset] = None
    
    # Service/Port information
    port: Optional[int] = None
    service: Optional[str] = None
    technology: Optional[str] = None
    
    # Severity
    severity: VulnerabilitySeverity = VulnerabilitySeverity.UNKNOWN
    original_severity: Optional[VulnerabilitySeverity] = None
    
    # Scoring
    cvss_score: float = 0.0
    risk_score: float = 0.0
    priority_score: float = 0.0
    
    # Detailed scoring components
    scoring_details: Dict[str, float] = field(default_factory=dict)
    
    # Evidence
    evidence: Optional[str] = None
    proof_of_concept: Optional[str] = None
    request_response: Optional[Dict[str, Any]] = None
    screenshots: List[str] = field(default_factory=list)
    
    # Location
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    
    # Status
    status: FindingStatus = FindingStatus.NEW
    false_positive_reason: Optional[str] = None
    mitigation: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    # Timeline
    first_discovered: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    confirmed_at: Optional[datetime] = None
    mitigated_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None
    
    # Discovery information
    scanner_type: str = ""
    scanner_name: str = ""
    scan_id: Optional[str] = None
    template_id: Optional[str] = None  # For Nuclei templates
    
    # Business context
    affected_data: Optional[str] = None
    business_impact: Optional[str] = None
    compliance_impact: List[str] = field(default_factory=list)
    
    # Workflow
    assigned_to: Optional[str] = None
    ticket_id: Optional[str] = None
    ticket_url: Optional[str] = None
    sla_due_date: Optional[datetime] = None
    comments: List[Dict[str, Any]] = field(default_factory=list)
    
    # Tags
    tags: Set[str] = field(default_factory=set)
    
    def calculate_risk_score(self, weights: Dict[str, float], 
                            exposure_factor: float = 1.0,
                            asset_criticality: float = 0.5,
                            threat_context: float = 1.0) -> float:
        """
        Calculate advanced risk score using the enterprise formula:
        Risk = CVSS × EPSS × ExploitMaturity × Exposure × AssetCriticality × ThreatContext
        """
        # Normalize CVSS (0-10 to 0-1)
        cvss_normalized = self.cvss_score / 10.0
        
        # EPSS score
        epss_score = 0.0
        if self.cve and self.cve.epss_score:
            epss_score = self.cve.epss_score
        
        # Exploit maturity score
        maturity_scores = {
            ExploitMaturity.ACTIVE: 1.0,
            ExploitMaturity.HIGH: 0.9,
            ExploitMaturity.FUNCTIONAL: 0.75,
            ExploitMaturity.PROOF_OF_CONCEPT: 0.5,
            ExploitMaturity.NOT_EXPLOITABLE: 0.2
        }
        exploit_maturity_score = maturity_scores.get(
            self.cve.exploit_maturity if self.cve else ExploitMaturity.NOT_EXPLOITABLE,
            0.2
        )
        
        # Apply weighted formula
        base_risk = (
            (cvss_normalized ** weights.get('cvss_base', 0.25)) *
            (epss_score ** weights.get('epss_score', 0.20)) *
            (exploit_maturity_score ** weights.get('exploit_maturity', 0.15)) *
            (exposure_factor ** weights.get('exposure_factor', 0.15)) *
            (asset_criticality ** weights.get('asset_criticality', 0.15)) *
            (threat_context ** weights.get('threat_context', 0.10))
        )
        
        # Time decay factor for older vulnerabilities
        age_days = (datetime.utcnow() - self.first_discovered).days
        time_decay = 0.95 ** (age_days / 30)  # 5% decay per month
        
        self.risk_score = min(1.0, base_risk * (1 + time_decay * 0.1))
        self.scoring_details = {
            'cvss_component': cvss_normalized,
            'epss_component': epss_score,
            'exploit_maturity_component': exploit_maturity_score,
            'exposure_factor': exposure_factor,
            'asset_criticality': asset_criticality,
            'threat_context': threat_context,
            'time_decay': time_decay,
            'age_days': age_days
        }
        
        return self.risk_score


@dataclass
class ScanJob:
    """Scan job definition"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Target specification
    target_type: str = "asset"  # asset, ip_range, domain, url
    targets: List[str] = field(default_factory=list)
    asset_ids: List[str] = field(default_factory=list)
    
    # Scan configuration
    scan_types: List[str] = field(default_factory=lambda: ["nuclei", "nmap"])
    scan_profile: str = "standard"  # quick, standard, deep, compliance
    templates: List[str] = field(default_factory=list)
    exclude_templates: List[str] = field(default_factory=list)
    
    # Scheduling
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Priority
    priority: int = 3  # 1=critical, 2=high, 3=medium, 4=low
    trigger_type: str = "scheduled"  # scheduled, manual, event_driven
    trigger_event: Optional[str] = None
    
    # Status
    status: str = "pending"  # pending, queued, running, completed, failed, cancelled
    progress: float = 0.0
    current_phase: Optional[str] = None
    
    # Results
    findings_count: int = 0
    vulnerabilities_found: int = 0
    assets_discovered: int = 0
    
    # Worker assignment
    worker_id: Optional[str] = None
    worker_host: Optional[str] = None
    
    # Error handling
    error_message: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    # Metadata
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def mark_started(self, worker_id: Optional[str] = None):
        """Mark scan as started"""
        self.status = "running"
        self.started_at = datetime.utcnow()
        self.worker_id = worker_id
        self.updated_at = datetime.utcnow()
    
    def mark_completed(self):
        """Mark scan as completed"""
        self.status = "completed"
        self.completed_at = datetime.utcnow()
        self.progress = 100.0
        self.updated_at = datetime.utcnow()
    
    def mark_failed(self, error: str):
        """Mark scan as failed"""
        self.status = "failed"
        self.error_message = error
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def update_progress(self, progress: float, phase: Optional[str] = None):
        """Update scan progress"""
        self.progress = max(0.0, min(100.0, progress))
        if phase:
            self.current_phase = phase
        self.updated_at = datetime.utcnow()


@dataclass
class AttackPath:
    """Simulated attack path through the infrastructure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Path identification
    name: str = ""
    description: str = ""
    
    # Path nodes (assets)
    nodes: List[str] = field(default_factory=list)  # Asset IDs in order
    node_details: List[Dict[str, Any]] = field(default_factory=list)
    
    # Edges (relationships used)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    
    # Entry and exit points
    entry_point: Optional[str] = None
    entry_asset: Optional[Asset] = None
    target_asset: Optional[Asset] = None
    crown_jewel: bool = False
    
    # Vulnerabilities exploited along the path
    vulnerabilities: List[str] = field(default_factory=list)  # Vulnerability IDs
    
    # Path scoring
    total_risk_score: float = 0.0
    average_risk_score: float = 0.0
    max_risk_score: float = 0.0
    path_length: int = 0
    
    # Exploitation details
    techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK techniques
    required_privileges: List[str] = field(default_factory=list)
    estimated_time: Optional[int] = None  # Estimated time in minutes
    
    # Detection
    detection_points: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_points: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    last_validated: Optional[datetime] = None
    is_active: bool = True
    
    # Simulation results
    simulation_success: bool = True
    simulation_notes: Optional[str] = None
    
    def calculate_path_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall path risk score"""
        if not vulnerabilities:
            return 0.0
        
        risk_scores = [v.risk_score for v in vulnerabilities if v.risk_score > 0]
        
        if not risk_scores:
            return 0.0
        
        self.max_risk_score = max(risk_scores)
        self.average_risk_score = sum(risk_scores) / len(risk_scores)
        
        # Path score considers both individual risks and chain effect
        # Longer chains with high-risk nodes are more dangerous
        chain_multiplier = 1 + (len(risk_scores) * 0.1)  # 10% increase per hop
        
        self.total_risk_score = min(1.0, self.average_risk_score * chain_multiplier)
        self.path_length = len(self.nodes)
        
        return self.total_risk_score


# Type aliases for cleaner code
AssetID = str
VulnerabilityID = str
FindingID = str
ScanID = str
RelationshipID = str
