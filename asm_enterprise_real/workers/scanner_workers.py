"""
Distributed Scanner Workers
Nuclei, Nmap, and custom scanner workers with Docker support
"""
import asyncio
import subprocess
import json
import os
import tempfile
from typing import List, Dict, Optional, AsyncGenerator
from datetime import datetime
import logging
import uuid

from config.settings import ASMConfig, load_config
from core.models import Asset, Vulnerability, Severity, ExploitMaturity, CVE, CVSS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NucleiScanner:
    """Nuclei web vulnerability scanner worker"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.scanner
        self.nuclei_path = self.config.nuclei_path
        self.templates_dir = os.getenv("NUCLEI_TEMPLATES", "~/nuclei-templates")
    
    async def scan_url(self, url: str, tags: Optional[List[str]] = None, 
                       severity: Optional[List[str]] = None) -> AsyncGenerator[Vulnerability, None]:
        """Scan a URL with Nuclei"""
        
        if not os.path.exists(self.nuclei_path):
            logger.warning(f"Nuclei not found at {self.nuclei_path}, using mock scan")
            yield from self._mock_nuclei_scan(url)
            return
        
        cmd = [
            self.nuclei_path,
            '-u', url,
            '-json',
            '-silent',
            '-timeout', '10',
            '-retries', '2',
            '-rate-limit', str(self.config.rate_limit),
            '-bulk-size', '10',
            '-concurrency', '25'
        ]
        
        if tags:
            for tag in tags:
                cmd.extend(['-tags', tag])
        
        if severity:
            for sev in severity:
                cmd.extend(['-severity', sev])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=self.config.scan_timeout)
            
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        finding = json.loads(line)
                        vuln = self._parse_nuclei_finding(finding, url)
                        if vuln:
                            yield vuln
                    except json.JSONDecodeError:
                        continue
                        
        except asyncio.TimeoutError:
            logger.error(f"Nuclei scan timeout for {url}")
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
    
    def _parse_nuclei_finding(self, finding: Dict, target: str) -> Optional[Vulnerability]:
        """Parse Nuclei JSON output to Vulnerability model"""
        try:
            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
                'info': Severity.INFO
            }
            
            severity = severity_map.get(finding.get('info', {}).get('severity', 'info').lower(), Severity.INFO)
            
            # Map CVSS if available
            cvss_score = 0.0
            if 'cvss-metrics' in finding.get('info', {}):
                # Parse CVSS vector
                pass
            
            vuln = Vulnerability(
                id=f"nuclei-{uuid.uuid4()}",
                asset_id=target,
                vulnerability_type='web',
                title=finding.get('info', {}).get('name', 'Unknown'),
                description=finding.get('info', {}).get('description', ''),
                severity=severity,
                cvss_score=cvss_score,
                epss_score=0.0,  # Will be enriched later
                exploit_maturity=ExploitMaturity.PROOF_OF_CONCEPT,
                exposure_factor=1.0,
                asset_criticality=5.0,
                threat_context_score=1.0,
                scanner_source='nuclei',
                raw_finding=finding,
                references=[finding.get('info', {}).get('reference', [])] if isinstance(finding.get('info', {}).get('reference'), str) else finding.get('info', {}).get('reference', []),
                tags=finding.get('info', {}).get('tags', '').split(',') if finding.get('info', {}).get('tags') else []
            )
            
            # Calculate risk score
            weights = {
                'cvss_weight': 0.25,
                'epss_weight': 0.20,
                'exploit_maturity_weight': 0.15,
                'exposure_weight': 0.15,
                'asset_criticality_weight': 0.15,
                'threat_context_weight': 0.10
            }
            vuln.calculate_risk_score(weights)
            
            return vuln
            
        except Exception as e:
            logger.error(f"Error parsing Nuclei finding: {e}")
            return None
    
    def _mock_nuclei_scan(self, url: str) -> List[Vulnerability]:
        """Mock Nuclei scan for demo"""
        vulns = []
        
        # Simulate common findings
        findings = [
            {
                'name': 'SSL/TLS Weak Cipher Suites',
                'severity': 'medium',
                'description': 'Weak SSL/TLS cipher suites detected'
            },
            {
                'name': 'Missing Security Headers',
                'severity': 'low',
                'description': 'Security headers not properly configured'
            }
        ]
        
        for finding in findings:
            vuln = Vulnerability(
                id=f"nuclei-{uuid.uuid4()}",
                asset_id=url,
                vulnerability_type='web',
                title=finding['name'],
                description=finding['description'],
                severity=Severity[finding['severity'].upper()],
                cvss_score=5.0 if finding['severity'] == 'medium' else 3.0,
                scanner_source='nuclei'
            )
            vuln.calculate_risk_score({})
            vulns.append(vuln)
        
        return vulns


class NmapScanner:
    """Nmap network scanner worker"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.scanner
        self.nmap_path = self.config.nmap_path
    
    async def scan_host(self, host: str, ports: Optional[str] = None, 
                       scan_type: str = 'default') -> AsyncGenerator[Dict, None]:
        """Scan a host with Nmap"""
        
        if not os.path.exists(self.nmap_path):
            logger.warning(f"Nmap not found at {self.nmap_path}, using mock scan")
            yield from self._mock_nmap_scan(host)
            return
        
        cmd = [self.nmap_path, '-oJ', '-', '-T4']
        
        if ports:
            cmd.extend(['-p', ports])
        else:
            cmd.extend(['--top-ports', '1000'])
        
        if scan_type == 'aggressive':
            cmd.extend(['-A'])
        elif scan_type == 'vuln':
            cmd.extend(['--script', 'vuln'])
        
        cmd.append(host)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=self.config.scan_timeout)
            
            # Parse Nmap JSON output
            output = stdout.decode()
            for line in output.splitlines():
                if line.strip():
                    try:
                        result = json.loads(line)
                        yield result
                    except json.JSONDecodeError:
                        continue
                        
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timeout for {host}")
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
    
    def _mock_nmap_scan(self, host: str) -> List[Dict]:
        """Mock Nmap scan for demo"""
        return [
            {
                'host': host,
                'ports': [
                    {'port': 80, 'protocol': 'tcp', 'service': 'http', 'state': 'open'},
                    {'port': 443, 'protocol': 'tcp', 'service': 'https', 'state': 'open'},
                    {'port': 22, 'protocol': 'tcp', 'service': 'ssh', 'state': 'open'}
                ]
            }
        ]


class CloudScanner:
    """Cloud misconfiguration scanner (AWS, Azure, GCP)"""
    
    def __init__(self, config: ASMConfig):
        self.config = config
    
    async def scan_aws_assets(self, assets: List[Asset]) -> AsyncGenerator[Vulnerability, None]:
        """Scan AWS assets for misconfigurations"""
        for asset in assets:
            if asset.asset_type.value == 's3_bucket':
                # Check S3 bucket policies
                if asset.is_public:
                    vuln = Vulnerability(
                        id=f"aws-s3-{uuid.uuid4()}",
                        asset_id=asset.id,
                        vulnerability_type='misconfiguration',
                        title='Public S3 Bucket',
                        description=f'S3 bucket {asset.value} is publicly accessible',
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        epss_score=0.8,
                        exploit_maturity=ExploitMaturity.HIGH,
                        exposure_factor=1.0,
                        asset_criticality=asset.criticality_score,
                        threat_context_score=8.0,
                        scanner_source='cloud_scanner',
                        remediation='Remove public access or add bucket policy restrictions',
                        tags=['aws', 's3', 'public-access', 'misconfiguration']
                    )
                    vuln.calculate_risk_score({})
                    yield vuln
            
            elif asset.asset_type.value == 'database':
                if asset.is_public:
                    vuln = Vulnerability(
                        id=f"aws-rds-{uuid.uuid4()}",
                        asset_id=asset.id,
                        vulnerability_type='misconfiguration',
                        title='Publicly Accessible RDS Instance',
                        description=f'RDS instance {asset.value} is publicly accessible',
                        severity=Severity.CRITICAL,
                        cvss_score=9.0,
                        epss_score=0.7,
                        exploit_maturity=ExploitMaturity.FUNCTIONAL,
                        exposure_factor=1.0,
                        asset_criticality=asset.criticality_score,
                        threat_context_score=9.0,
                        scanner_source='cloud_scanner',
                        remediation='Disable public accessibility in RDS settings',
                        tags=['aws', 'rds', 'database', 'public-access']
                    )
                    vuln.calculate_risk_score({})
                    yield vuln


class WorkerOrchestrator:
    """Orchestrates distributed scanner workers"""
    
    def __init__(self, config: ASMConfig):
        self.config = config
        self.nuclei = NucleiScanner(config)
        self.nmap = NmapScanner(config)
        self.cloud_scanner = CloudScanner(config)
        self.active_workers = 0
        self.max_workers = config.scanner.max_concurrent_scans
    
    async def run_scan_job(self, targets: List[str], scan_types: List[str]) -> AsyncGenerator[Vulnerability, None]:
        """Run scan job across multiple targets"""
        
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def scan_target(target: str, scan_type: str):
            async with semaphore:
                self.active_workers += 1
                try:
                    if scan_type == 'web' or scan_type == 'full':
                        async for vuln in self.nuclei.scan_url(target):
                            yield vuln
                    
                    if scan_type == 'network' or scan_type == 'full':
                        async for result in self.nmap.scan_host(target):
                            # Convert nmap results to vulnerabilities
                            for port in result.get('ports', []):
                                if port.get('state') == 'open':
                                    # Check for dangerous services
                                    service = port.get('service', '')
                                    if service in ['telnet', 'ftp', 'rsh']:
                                        vuln = Vulnerability(
                                            id=f"nmap-{uuid.uuid4()}",
                                            asset_id=target,
                                            vulnerability_type='network',
                                            title=f'Insecure Service: {service}',
                                            description=f'Port {port["port"]} running insecure {service} service',
                                            severity=Severity.HIGH,
                                            cvss_score=7.0,
                                            scanner_source='nmap'
                                        )
                                        vuln.calculate_risk_score({})
                                        yield vuln
                finally:
                    self.active_workers -= 1
        
        tasks = []
        for target in targets:
            for scan_type in scan_types:
                task = asyncio.create_task(scan_target(target, scan_type))
                tasks.append(task)
        
        # Collect results from all tasks
        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                if result:
                    yield result
            except Exception as e:
                logger.error(f"Scan task error: {e}")


def create_docker_worker_image(scanner_type: str) -> str:
    """Generate Dockerfile for scanner worker"""
    
    dockers = {
        'nuclei': '''FROM python:3.11-slim

WORKDIR /app

# Install Nuclei
RUN curl -LO https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip && \\
    unzip nuclei_linux_amd64.zip && \\
    mv nuclei /usr/local/bin/ && \\
    rm nuclei_linux_amd64.zip

# Install Nuclei templates
RUN nuclei -update-templates

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner code
COPY workers/nuclei_worker.py .

CMD ["python", "nuclei_worker.py"]
''',
        'nmap': '''FROM python:3.11-slim

WORKDIR /app

# Install Nmap
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner code
COPY workers/nmap_worker.py .

CMD ["python", "nmap_worker.py"]
''',
        'orchestrator': '''FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY config/ ./config/
COPY core/ ./core/
COPY integrations/ ./integrations/
COPY graph/ ./graph/
COPY workers/ ./workers/

# Set environment variables
ENV PYTHONPATH=/app

CMD ["python", "workers/orchestrator.py"]
'''
    }
    
    return dockers.get(scanner_type, '')


async def demo_workers():
    """Demo scanner workers"""
    config = load_config()
    
    print("=" * 60)
    print("ENTERPRISE ASM - SCANNER WORKERS DEMO")
    print("=" * 60)
    
    orchestrator = WorkerOrchestrator(config)
    
    # Demo Nuclei scan
    print("\n🔍 Nuclei Web Scan:")
    async for vuln in orchestrator.nuclei.scan_url('https://example.com'):
        print(f"  ✓ Found: {vuln.title} (Severity: {vuln.severity.value}, Risk: {vuln.risk_score})")
    
    # Demo Nmap scan
    print("\n🌐 Nmap Network Scan:")
    async for result in orchestrator.nmap.scan_host('scanme.nmap.org'):
        print(f"  ✓ Host: {result.get('host')}")
        for port in result.get('ports', []):
            print(f"    Port {port.get('port')}: {port.get('service')} ({port.get('state')})")
    
    print("\n✓ Worker demo complete!")


if __name__ == "__main__":
    asyncio.run(demo_workers())
