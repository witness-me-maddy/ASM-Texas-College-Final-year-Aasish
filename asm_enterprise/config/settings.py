"""
Enterprise ASM System - Configuration Module
Multi-Source Asset Intelligence Engine Configuration
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import os


class DataSourceType(Enum):
    DNS = "dns"
    SUBDOMAIN = "subdomain"
    ASN = "asn"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CERTIFICATE_TRANSPARENCY = "ct_logs"
    PASSIVE_DNS = "passive_dns"
    GITHUB = "github"
    DARK_WEB = "dark_web"
    THIRD_PARTY_SAAS = "saas"


class ScanPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DataSourceConfig:
    """Configuration for individual data sources"""
    name: str
    source_type: DataSourceType
    enabled: bool = True
    api_key: Optional[str] = None
    endpoint: Optional[str] = None
    rate_limit: int = 100  # requests per minute
    timeout: int = 30
    retry_count: int = 3
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudProviderConfig:
    """Cloud provider specific configuration"""
    provider: str
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    region: str = "us-east-1"
    account_id: Optional[str] = None
    role_arn: Optional[str] = None
    external_id: Optional[str] = None


@dataclass
class ScannerConfig:
    """Configuration for scanning workers"""
    nuclei: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "templates_path": "/opt/nuclei-templates",
        "rate_limit": 150,
        "bulk_size": 25,
        "timeout": 10,
        "retries": 2,
        "severity_filter": ["critical", "high", "medium"]
    })
    nmap: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "scan_type": "SYN",
        "top_ports": 1000,
        "version_detection": True,
        "os_detection": False,
        "script_scan": True,
        "timing_template": "T4"
    })
    cloud_scanner: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "providers": ["aws", "azure", "gcp"],
        "services": ["ec2", "s3", "rds", "lambda", "iam"],
        "compliance_checks": True
    })
    custom_scripts: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "scripts_path": "/opt/custom-scanners",
        "allowed_extensions": [".py", ".sh", ".go"]
    })


@dataclass
class GraphDBConfig:
    """Neo4j Graph Database configuration"""
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"
    database: str = "neo4j"
    max_pool_size: int = 50
    connection_timeout: int = 30
    max_retry_time: int = 60


@dataclass
class PostgreSQLConfig:
    """PostgreSQL relational database configuration"""
    host: str = "localhost"
    port: int = 5432
    database: str = "asm_db"
    username: str = "asm_user"
    password: str = "password"
    pool_size: int = 20
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600


@dataclass
class ElasticSearchConfig:
    """ElasticSearch configuration for log storage"""
    hosts: List[str] = field(default_factory=lambda: ["http://localhost:9200"])
    username: Optional[str] = None
    password: Optional[str] = None
    index_prefix: str = "asm"
    shard_count: int = 3
    replica_count: int = 1
    retention_days: int = 90


@dataclass
class KafkaConfig:
    """Apache Kafka message broker configuration"""
    bootstrap_servers: List[str] = field(default_factory=lambda: ["localhost:9092"])
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: Optional[str] = None
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None
    consumer_group: str = "asm-workers"
    auto_offset_reset: str = "earliest"
    enable_auto_commit: bool = False


@dataclass
class RiskModelConfig:
    """Advanced risk scoring model configuration"""
    weights: Dict[str, float] = field(default_factory=lambda: {
        "cvss_base": 0.25,
        "epss_score": 0.20,
        "exploit_maturity": 0.15,
        "exposure_factor": 0.15,
        "asset_criticality": 0.15,
        "threat_context": 0.10
    })
    thresholds: Dict[str, float] = field(default_factory=lambda: {
        "critical": 0.85,
        "high": 0.65,
        "medium": 0.40,
        "low": 0.20
    })
    time_decay_factor: float = 0.95
    age_multiplier_days: int = 30


@dataclass
class AlertingConfig:
    """Alerting and notification configuration"""
    email: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "smtp_host": "smtp.company.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_address": "asm@company.com",
        "recipients": []
    })
    slack: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "webhook_url": "",
        "channel": "#security-alerts",
        "username": "ASM Bot"
    })
    pagerduty: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "integration_key": "",
        "severity_mapping": {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info"
        }
    })
    jira: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "url": "",
        "username": "",
        "api_token": "",
        "project_key": "SEC",
        "issue_type": "Vulnerability",
        "priority_mapping": {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low"
        }
    })


@dataclass
class SchedulerConfig:
    """Scan scheduler configuration"""
    default_schedule: str = "0 2 * * *"  # Daily at 2 AM
    high_priority_interval: int = 3600  # 1 hour
    critical_asset_interval: int = 900  # 15 minutes
    full_scan_interval: int = 604800  # Weekly
    incremental_scan_interval: int = 86400  # Daily
    max_concurrent_scans: int = 50
    scan_timeout: int = 7200  # 2 hours
    retry_failed_scans: bool = True
    max_retries: int = 3


@dataclass
class SystemConfig:
    """Main system configuration"""
    # Application settings
    app_name: str = "Enterprise ASM System"
    version: str = "1.0.0"
    environment: str = "production"
    debug_mode: bool = False
    
    # Data sources
    data_sources: List[DataSourceConfig] = field(default_factory=list)
    
    # Cloud providers
    cloud_providers: List[CloudProviderConfig] = field(default_factory=list)
    
    # Scanner configuration
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    
    # Database configurations
    graph_db: GraphDBConfig = field(default_factory=GraphDBConfig)
    postgresql: PostgreSQLConfig = field(default_factory=PostgreSQLConfig)
    elasticsearch: ElasticSearchConfig = field(default_factory=ElasticSearchConfig)
    
    # Message broker
    kafka: KafkaConfig = field(default_factory=KafkaConfig)
    
    # Risk model
    risk_model: RiskModelConfig = field(default_factory=RiskModelConfig)
    
    # Alerting
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    
    # Scheduler
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    
    # Worker settings
    worker_count: int = 10
    worker_timeout: int = 300
    health_check_interval: int = 30
    
    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4
    api_key_header: str = "X-API-Key"
    
    # Security
    encryption_key: Optional[str] = None
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: str = "/var/log/asm/system.log"
    max_log_size_mb: int = 100
    log_retention_days: int = 30


def load_config_from_env() -> SystemConfig:
    """Load configuration from environment variables"""
    config = SystemConfig()
    
    # Override with environment variables if present
    config.environment = os.getenv("ASM_ENVIRONMENT", config.environment)
    config.debug_mode = os.getenv("ASM_DEBUG", "false").lower() == "true"
    config.worker_count = int(os.getenv("ASM_WORKER_COUNT", config.worker_count))
    config.api_host = os.getenv("ASM_API_HOST", config.api_host)
    config.api_port = int(os.getenv("ASM_API_PORT", config.api_port))
    config.log_level = os.getenv("ASM_LOG_LEVEL", config.log_level)
    
    # Database overrides
    config.graph_db.uri = os.getenv("ASM_GRAPH_DB_URI", config.graph_db.uri)
    config.graph_db.username = os.getenv("ASM_GRAPH_DB_USER", config.graph_db.username)
    config.graph_db.password = os.getenv("ASM_GRAPH_DB_PASSWORD", config.graph_db.password)
    
    config.postgresql.host = os.getenv("ASM_POSTGRES_HOST", config.postgresql.host)
    config.postgresql.database = os.getenv("ASM_POSTGRES_DB", config.postgresql.database)
    config.postgresql.username = os.getenv("ASM_POSTGRES_USER", config.postgresql.username)
    config.postgresql.password = os.getenv("ASM_POSTGRES_PASSWORD", config.postgresql.password)
    
    config.elasticsearch.hosts = os.getenv(
        "ASM_ES_HOSTS", 
        ",".join(config.elasticsearch.hosts)
    ).split(",")
    
    config.kafka.bootstrap_servers = os.getenv(
        "ASM_KAFKA_BOOTSTRAP", 
        ",".join(config.kafka.bootstrap_servers)
    ).split(",")
    
    return config


# Default configuration instance
DEFAULT_CONFIG = load_config_from_env()
