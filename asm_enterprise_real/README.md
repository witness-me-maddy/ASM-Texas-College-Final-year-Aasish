# Enterprise Attack Surface Management (ASM) System

A comprehensive, production-ready ASM platform with real integrations, graph-based attack path analysis, and SOAR automation.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ENTERPRISE ASM SYSTEM                          │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │   Shodan     │  │   Censys     │  │   AWS API    │              │
│  │  Integration │  │  Integration │  │  Integration │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
│         │                 │                  │                       │
│         └─────────────────┴──────────────────┘                       │
│                           │                                          │
│                  ┌────────▼────────┐                                 │
│                  │  Intelligence   │                                 │
│                  │     Engine      │                                 │
│                  └────────┬────────┘                                 │
│                           │                                          │
│         ┌─────────────────┼─────────────────┐                        │
│         │                 │                 │                        │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐                  │
│  │   Neo4j     │  │  FastAPI    │  │   Worker    │                  │
│  │   Graph     │  │    REST     │  │ Orchestrator│                  │
│  │   Engine    │  │    API      │  │             │                  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                  │
│         │                │                 │                          │
│         │         ┌──────▼──────┐         │                          │
│         │         │    SOAR     │         │                          │
│         │         │   Engine    │         │                          │
│         │         └──────┬──────┘         │                          │
│         │                │                │                          │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐                  │
│  │    Jira     │  │ ServiceNow  │  │  Nuclei/    │                  │
│  │  Tickets    │  │  Incidents  │  │   Nmap      │                  │
│  └─────────────┘  └─────────────┘  └─────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
asm_enterprise_real/
├── config/
│   └── settings.py          # Configuration management
├── core/
│   └── models.py            # Data models (Asset, Vulnerability, etc.)
├── integrations/
│   └── intelligence.py      # Shodan, Censys, AWS, CT logs
├── graph/
│   └── neo4j_engine.py      # Neo4j graph operations
├── api/
│   └── fastapi_server.py    # REST API endpoints
├── workers/
│   └── scanner_workers.py   # Nuclei, Nmap scanners
├── soar/
│   └── ticketing.py         # Jira, ServiceNow integration
├── requirements.txt
└── README.md
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd asm_enterprise_real
pip install -r requirements.txt
```

### 2. Configure Environment Variables

```bash
# API Keys (get from respective platforms)
export SHODAN_API_KEY="your_shodan_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
export NVD_API_KEY="your_nvd_key"

# AWS Credentials
export AWS_ACCESS_KEY_ID="your_aws_key"
export AWS_SECRET_ACCESS_KEY="your_aws_secret"
export AWS_REGION="us-east-1"

# Neo4j Connection
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="password"

# Jira Integration
export JIRA_URL="https://your-company.atlassian.net"
export JIRA_EMAIL="your-email@company.com"
export JIRA_API_TOKEN="your_jira_token"
export JIRA_PROJECT="SEC"

# ServiceNow Integration
export SNOW_INSTANCE="your-instance"
export SNOW_USERNAME="your_username"
export SNOW_PASSWORD="your_password"

# API Security
export ASM_API_KEY="your-api-key-for-rest-access"
```

### 3. Start Neo4j (Docker)

```bash
docker run -d \
  --name neo4j \
  -p 7474:7474 \
  -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  -e NEO4J_PLUGINS='["apoc"]' \
  neo4j:latest
```

### 4. Run the API Server

```bash
cd asm_enterprise_real
python -m uvicorn api.fastapi_server:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Access the Dashboard

Open your browser to:
- **API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🔌 Real Integrations

### Shodan
- Internet-facing asset discovery
- Port and service enumeration
- Vulnerability detection
- Exposure scoring

### Censys
- Host and certificate search
- TLS/SSL analysis
- Service fingerprinting
- Historical data

### AWS
- EC2 instance discovery
- S3 bucket misconfiguration detection
- RDS exposure analysis
- Lambda function scanning
- IAM role tracking

### Certificate Transparency
- Subdomain enumeration
- Shadow IT discovery
- Certificate monitoring

### GitHub Leak Detection
- Credential leak scanning
- API key exposure detection
- Code repository monitoring

## 📊 API Endpoints

### Assets
```bash
# List all assets
curl -H "X-API-Key: your-api-key" \
  http://localhost:8000/api/v1/assets

# Discover new assets
curl -X POST -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "test.com"]}' \
  http://localhost:8000/api/v1/assets/discover

# Get entry points
curl -H "X-API-Key: your-api-key" \
  http://localhost:8000/api/v1/entry-points

# Get crown jewels
curl -H "X-API-Key: your-api-key" \
  http://localhost:8000/api/v1/crown-jewels
```

### Vulnerabilities
```bash
# List vulnerabilities
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/vulnerabilities?severity=critical"
```

### Attack Paths
```bash
# Find attack paths
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/api/v1/attack-paths?max_depth=5"
```

### Scanning
```bash
# Create scan job
curl -X POST -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.1"], "scan_type": "full"}' \
  http://localhost:8000/api/v1/scans

# Check scan status
curl -H "X-API-Key: your-api-key" \
  http://localhost:8000/api/v1/scans/{scan_id}
```

### Dashboard
```bash
# Get statistics
curl -H "X-API-Key: your-api-key" \
  http://localhost:8000/api/v1/stats
```

## 🧠 Advanced Risk Scoring

The system uses an enterprise-grade risk formula:

```
Risk = CVSS^0.25 × EPSS^0.20 × ExploitMaturity^0.15 × 
       Exposure^0.15 × AssetCriticality^0.15 × ThreatContext^0.10
```

Factors considered:
- **CVSS**: Base vulnerability severity
- **EPSS**: Exploitation probability score
- **Exploit Maturity**: Active/PoC/Functional exploits
- **Exposure**: Internet-facing status, open ports
- **Asset Criticality**: Business importance
- **Threat Context**: CISA KEV, ransomware association

## 🔗 Graph-Based Attack Path Analysis

Using Neo4j, the system:
1. Maps all asset relationships
2. Identifies entry points (internet-facing assets)
3. Locates crown jewels (critical assets)
4. Finds attack paths using BFS/graph traversal
5. Calculates lateral movement hops
6. Scores paths by exploitability

## 🎫 SOAR Automation

### Auto-Ticket Creation
- **Jira**: Creates security issues with full context
- **ServiceNow**: Generates incidents with SLA tracking
- Severity-based prioritization
- Automatic assignment based on asset owner

### Auto-Remediation
- AWS misconfiguration fixes
- Security group updates
- S3 bucket policy corrections

## 🐳 Docker Deployment

### Build Scanner Workers

```bash
# Nuclei worker
docker build -f workers/Dockerfile.nuclei -t asm-nuclei-worker .

# Nmap worker
docker build -f workers/Dockerfile.nmap -t asm-nmap-worker .

# Orchestrator
docker build -f workers/Dockerfile.orchestrator -t asm-orchestrator .
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: asm-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: asm-api
  template:
    spec:
      containers:
      - name: api
        image: asm-enterprise:latest
        ports:
        - containerPort: 8000
        env:
        - name: NEO4J_URI
          value: "bolt://neo4j:7687"
        - name: SHODAN_API_KEY
          valueFrom:
            secretKeyRef:
              name: asm-secrets
              key: shodan-key
---
apiVersion: v1
kind: Service
metadata:
  name: asm-api
spec:
  selector:
    app: asm-api
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

## 📈 Monitoring & Metrics

Prometheus metrics available at `/metrics`:
- `asm_assets_total`: Total discovered assets
- `asm_vulnerabilities_total`: Total vulnerabilities by severity
- `asm_scan_jobs_total`: Scan jobs processed
- `asm_attack_paths_total`: Attack paths identified
- `asm_tickets_created_total`: Tickets created in ITSM tools

## 🔒 Security Considerations

1. **API Authentication**: Use strong API keys
2. **Rate Limiting**: Configure for external APIs
3. **Data Encryption**: Enable TLS for Neo4j
4. **Access Control**: Implement RBAC for dashboard
5. **Audit Logging**: Track all actions

## 🛠️ Development

### Run Tests
```bash
pytest tests/ -v
```

### Code Quality
```bash
black .
flake8
mypy .
```

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## 📞 Support

For enterprise support, contact: security-team@example.com
