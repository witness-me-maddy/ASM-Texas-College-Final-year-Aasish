"""
Enterprise ASM Configuration
Real API keys and connection settings
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import os

@dataclass
class ShodanConfig:
    api_key: str = field(default_factory=lambda: os.getenv("SHODAN_API_KEY", ""))
    base_url: str = "https://api.shodan.io"
    timeout: int = 30
    rate_limit_delay: float = 1.0

@dataclass
class CensysConfig:
    api_id: str = field(default_factory=lambda: os.getenv("CENSYS_API_ID", ""))
    api_secret: str = field(default_factory=lambda: os.getenv("CENSYS_API_SECRET", ""))
    base_url: str = "https://search.censys.io/api/v2"
    timeout: int = 30

@dataclass
class AWSConfig:
    access_key: str = field(default_factory=lambda: os.getenv("AWS_ACCESS_KEY_ID", ""))
    secret_key: str = field(default_factory=lambda: os.getenv("AWS_SECRET_ACCESS_KEY", ""))
    region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    role_arn: Optional[str] = None

@dataclass
class NVDConfig:
    api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    timeout: int = 60
    retry_attempts: int = 3

@dataclass
class EPSSConfig:
    feed_url: str = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    cache_file: str = "/tmp/epss_cache.csv"

@dataclass
class Neo4jConfig:
    uri: str = field(default_factory=lambda: os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    user: str = field(default_factory=lambda: os.getenv("NEO4J_USER", "neo4j"))
    password: str = field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", "password"))
    database: str = "neo4j"

@dataclass
class PostgreSQLConfig:
    host: str = field(default_factory=lambda: os.getenv("POSTGRES_HOST", "localhost"))
    port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    database: str = field(default_factory=lambda: os.getenv("POSTGRES_DB", "asm_db"))
    user: str = field(default_factory=lambda: os.getenv("POSTGRES_USER", "asm_user"))
    password: str = field(default_factory=lambda: os.getenv("POSTGRES_PASSWORD", ""))

@dataclass
class JiraConfig:
    url: str = field(default_factory=lambda: os.getenv("JIRA_URL", ""))
    email: str = field(default_factory=lambda: os.getenv("JIRA_EMAIL", ""))
    api_token: str = field(default_factory=lambda: os.getenv("JIRA_API_TOKEN", ""))
    project_key: str = field(default_factory=lambda: os.getenv("JIRA_PROJECT", "ASM"))
    issue_type: str = "Vulnerability"

@dataclass
class ServiceNowConfig:
    instance: str = field(default_factory=lambda: os.getenv("SNOW_INSTANCE", ""))
    username: str = field(default_factory=lambda: os.getenv("SNOW_USERNAME", ""))
    password: str = field(default_factory=lambda: os.getenv("SNOW_PASSWORD", ""))
    table: str = "incident"

@dataclass
class ScannerConfig:
    nuclei_path: str = "/usr/local/bin/nuclei"
    nmap_path: str = "/usr/local/bin/nmap"
    max_concurrent_scans: int = 10
    scan_timeout: int = 300
    rate_limit: int = 100

@dataclass
class RiskWeights:
    cvss_weight: float = 0.25
    epss_weight: float = 0.20
    exploit_maturity_weight: float = 0.15
    exposure_weight: float = 0.15
    asset_criticality_weight: float = 0.15
    threat_context_weight: float = 0.10

@dataclass
class ASMConfig:
    shodan: ShodanConfig = field(default_factory=ShodanConfig)
    censys: CensysConfig = field(default_factory=CensysConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)
    nvd: NVDConfig = field(default_factory=NVDConfig)
    epss: EPSSConfig = field(default_factory=EPSSConfig)
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)
    postgres: PostgreSQLConfig = field(default_factory=PostgreSQLConfig)
    jira: JiraConfig = field(default_factory=JiraConfig)
    servicenow: ServiceNowConfig = field(default_factory=ServiceNowConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    risk_weights: RiskWeights = field(default_factory=RiskWeights)
    
    # General settings
    user_agent: str = "Enterprise-ASM/1.0"
    request_timeout: int = 30
    max_retries: int = 3
    log_level: str = "INFO"
    
    # Asset criticality thresholds
    crown_jewel_score_threshold: float = 8.0
    high_risk_threshold: float = 7.0
    medium_risk_threshold: float = 4.0
    
    # Scan scheduling
    default_scan_interval_hours: int = 24
    high_priority_scan_interval_hours: int = 4
    continuous_monitoring_enabled: bool = True

def load_config() -> ASMConfig:
    """Load configuration from environment variables"""
    return ASMConfig()
