# Enterprise Attack Surface Management (ASM) System

A comprehensive, enterprise-grade Attack Surface Management platform with multi-source intelligence aggregation, graph-based asset correlation, advanced risk scoring, and attack path simulation.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ENTERPRISE ASM SYSTEM                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐      │
│  │   Intelligence   │  │     Graph        │  │  Vulnerability   │      │
│  │     Engine       │  │     Engine       │  │  Intel Engine    │      │
│  │                  │  │                  │  │                  │      │
│  │ • DNS/CT Logs    │  │ • Neo4j Graph DB │  │ • NVD/CVE        │      │
│  │ • Cloud APIs     │  │ • Asset Relations│  │ • EPSS Scores    │      │
│  │ • GitHub Leaks   │  │ • Attack Paths   │  │ • CISA KEV       │      │
│  │ • Passive DNS    │  │ • Lateral Move   │  │ • Risk Scoring   │      │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘      │
│           │                    │                    │                   │
│           └────────────────────┼────────────────────┘                   │
│                                │                                        │
│                     ┌──────────▼──────────┐                             │
│                     │   Main Orchestrator │                             │
│                     │   (EnterpriseASM)   │                             │
│                     └─────────────────────┘                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
asm_enterprise/
├── config/
│   ├── __init__.py
│   └── settings.py          # Comprehensive configuration system
├── core/
│   ├── __init__.py
│   └── models.py            # Data models (Assets, Vulns, Relationships)
├── engines/
│   ├── __init__.py
│   ├── intelligence.py      # Multi-source asset intelligence
│   ├── graph_engine.py      # Neo4j graph correlation
│   └── vulnerability_intel.py # Threat intel enrichment
├── workers/                 # Scanning workers (future)
├── integrations/            # Third-party integrations (future)
├── api/                     # REST API (future)
├── dashboard/               # Visualization (future)
├── scheduler/               # Job scheduling (future)
├── utils/                   # Utilities
└── main.py                  # Main entry point
```

## 🚀 Features

### 1. Multi-Source Asset Intelligence Engine
- **Certificate Transparency Logs**: Discover subdomains from SSL certificates
- **DNS Enumeration**: Subdomain discovery and DNS record analysis
- **Cloud Provider Integration**: AWS, Azure, GCP asset discovery
- **GitHub Leak Detection**: Search for exposed credentials and secrets
- **Passive DNS**: Historical DNS resolution data
- **Rate Limiting**: Built-in rate limiting for all sources

### 2. Asset Correlation & Graph Engine
- **Graph-Based Model**: Neo4j integration for relationship mapping
- **Node Types**: Domain, IP, Service, Application, Identity
- **Edge Types**: resolves_to, hosts, communicates_with, owned_by
- **Attack Path Analysis**: Find paths from entry points to crown jewels
- **Lateral Movement Simulation**: Simulate attacker movement

### 3. Vulnerability Intelligence Engine
- **CVE Enrichment**: Full CVE details from NVD
- **EPSS Integration**: Exploit Prediction Scoring
- **CISA KEV**: Known Exploited Vulnerabilities tracking
- **Exploit Detection**: Check for public exploits
- **Ransomware Association**: Track ransomware-linked CVEs

### 4. Advanced Risk Scoring Model

```
Risk = CVSS × EPSS × ExploitMaturity × Exposure × AssetCriticality × ThreatContext
```

**Components:**
- **CVSS Base Score** (25%): Standard severity
- **EPSS Score** (20%): Exploitation likelihood
- **Exploit Maturity** (15%): Exploit availability
- **Exposure Factor** (15%): Internet-facing status
- **Asset Criticality** (15%): Business importance
- **Threat Context** (10%): Active exploitation status

### 5. Comprehensive Data Models

**Asset Types:**
- Domains, Subdomains, IP Addresses
- Cloud Resources (EC2, S3, RDS, Lambda)
- Databases, Containers, Kubernetes
- IAM Entities, Service Accounts
- Git Repositories, Third-party Services

**Vulnerability Tracking:**
- Full CVE metadata
- CVSS v3.1 metrics
- EPSS scores and percentiles
- Exploit availability
- Patch status
- Business impact assessment

## 🔧 Installation

### Prerequisites
- Python 3.10+
- Neo4j Database (optional, for graph features)
- PostgreSQL (optional, for relational storage)
- Elasticsearch (optional, for log storage)

### Install Dependencies

```bash
pip install aiohttp neo4j sqlalchemy elasticsearch
```

### Configuration

Set environment variables or modify `config/settings.py`:

```bash
# Neo4j Configuration
export ASM_GRAPH_DB_URI="bolt://localhost:7687"
export ASM_GRAPH_DB_USER="neo4j"
export ASM_GRAPH_DB_PASSWORD="your_password"

# PostgreSQL Configuration
export ASM_POSTGRES_HOST="localhost"
export ASM_POSTGRES_DB="asm_db"
export ASM_POSTGRES_USER="asm_user"
export ASM_POSTGRES_PASSWORD="your_password"

# Elasticsearch Configuration
export ASM_ES_HOSTS="http://localhost:9200"

# System Configuration
export ASM_WORKER_COUNT="10"
export ASM_LOG_LEVEL="INFO"
```

## 📖 Usage

### Basic Usage

```python
from main import EnterpriseASM

async def main():
    # Create ASM instance
    asm = EnterpriseASM()
    
    # Initialize
    await asm.initialize()
    await asm.start()
    
    # Discover assets
    assets = await asm.discover_assets(["example.com"])
    print(f"Found {len(assets)} assets")
    
    # Analyze attack paths
    paths = await asm.analyze_attack_paths(max_hops=5)
    print(f"Found {len(paths)} attack paths")
    
    # Get dashboard data
    dashboard = asm.get_dashboard_data()
    print(dashboard['summary'])
    
    # Cleanup
    await asm.stop()

asyncio.run(main())
```

### Run Demo

```bash
cd asm_enterprise
python main.py
```

### Example Output

```
======================================================================
  ENTERPRISE ATTACK SURFACE MANAGEMENT SYSTEM
  Version 1.0.0
======================================================================

🔍 Running Asset Discovery...

✅ Discovered 16 assets:
   - subdomain: 16

🎯 Analyzing Attack Paths...

✅ Found 1 attack paths
   Path 1: Sample Attack Path
      - Risk Score: 0.75
      - Length: 3 hops
      - Crown Jewel: Yes

📊 System Statistics:
   - Assets Discovered: 16
   - Attack Paths: 1
   - Uptime: 0:00:30

📈 Dashboard Summary:
   - Total Assets: 16
   - Critical Vulnerabilities: 0
   - Critical Attack Paths: 1
```

## 📊 API Reference

### EnterpriseASM Class

#### Methods

| Method | Description |
|--------|-------------|
| `initialize()` | Initialize all engines |
| `start()` | Start the ASM system |
| `stop()` | Stop the ASM system |
| `discover_assets(targets)` | Discover assets from intelligence sources |
| `analyze_attack_paths(max_hops)` | Find attack paths through infrastructure |
| `enrich_vulnerabilities(vulns)` | Enrich vulnerabilities with threat intel |
| `get_statistics()` | Get system statistics |
| `get_dashboard_data()` | Get dashboard visualization data |

### Asset Model

```python
@dataclass
class Asset:
    id: str
    asset_type: AssetType
    value: str
    name: Optional[str]
    tags: Set[str]
    criticality: float  # 0.0 to 1.0
    ip_addresses: List[str]
    ports: List[int]
    services: List[Service]
    cloud_provider: Optional[CloudProvider]
    risk_score: float
    # ... and many more fields
```

### Vulnerability Model

```python
@dataclass
class Vulnerability:
    id: str
    vulnerability_id: str  # CVE-ID
    title: str
    description: str
    cvss_score: float
    risk_score: float
    cve: Optional[CVE]
    tags: Set[str]
    # ... comprehensive tracking fields
```

## 🔄 Workflow

```
1. Asset Ingestion
   ↓
2. Normalization & Deduplication
   ↓
3. Graph Construction
   ↓
4. Exposure Detection
   ↓
5. Intelligent Scan Orchestration
   ↓
6. Collect Findings
   ↓
7. Vulnerability Enrichment
   ↓
8. Risk Calculation
   ↓
9. Attack Path Analysis
   ↓
10. Alerting & Prioritization
   ↓
11. Remediation Workflow
   ↓
12. Continuous Feedback Loop
```

## 🛠️ Extending the System

### Adding New Intelligence Sources

```python
from engines.intelligence import BaseIntelligenceSource, IntelligenceResult

class MyCustomSource(BaseIntelligenceSource):
    async def fetch(self, query: str) -> IntelligenceResult:
        result = IntelligenceResult(
            source=self.name,
            source_type=DataSourceType.CUSTOM
        )
        
        # Fetch data from your source
        data = await self._make_request("GET", f"{self.config.endpoint}/{query}")
        
        # Process and create assets
        for item in data:
            asset = Asset(
                asset_type=AssetType.SUBDOMAIN,
                value=item['domain'],
                # ...
            )
            result.assets.append(asset)
        
        return result
```

### Custom Risk Scoring

```python
def custom_risk_score(vulnerability, context):
    # Your custom risk calculation
    base_score = vulnerability.cvss_score / 10.0
    
    # Add custom factors
    if is_critical_business_asset(vulnerability.asset_id):
        base_score *= 1.5
    
    return min(1.0, base_score)
```

## 📈 Metrics & Monitoring

The system provides comprehensive metrics:

- **Asset Discovery**: Count by type, source, time
- **Vulnerability Stats**: By severity, exploitability, age
- **Risk Distribution**: Critical/High/Medium/Low counts
- **Attack Paths**: Total, critical, average length
- **Engine Performance**: Cache hits, errors, latency

## 🔒 Security Considerations

- API keys stored in environment variables
- Rate limiting prevents abuse
- Encrypted communications (when configured)
- Access control ready (integration pending)
- Audit logging capabilities

## 🚧 Future Enhancements

- [ ] Distributed scanning workers (Nuclei, Nmap)
- [ ] REST API with authentication
- [ ] Real-time dashboard (WebSocket)
- [ ] Jira/ServiceNow integration
- [ ] Slack/PagerDuty alerting
- [ ] Machine learning for anomaly detection
- [ ] Compliance checking (CIS, SOC2, ISO27001)
- [ ] Drift detection
- [ ] Automated remediation

## 📄 License

Enterprise ASM System - Copyright 2024

## 🤝 Contributing

This is an enterprise-grade system. Contributions welcome for:
- Additional intelligence sources
- Scanner integrations
- UI/dashboard improvements
- Documentation enhancements

## 📞 Support

For enterprise support and customization, contact the development team.

---

**Built with ❤️ for Enterprise Security Teams**
