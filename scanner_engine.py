"""
Advanced Scanner Engine for Attack Surface Management
Integrates multiple scanning technologies to discover and assess assets
"""

import nmap
import docker
import subprocess
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import scapy.all as sc
from pyshark import FileCapture
import netaddr


class ScanType(Enum):
    NETWORK_DISCOVERY = "network_discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    WEB_APPLICATION = "web_application"
    PORT_SCAN = "port_scan"


@dataclass
class ScanResult:
    scan_type: ScanType
    target: str
    timestamp: datetime
    findings: List[Dict]
    metadata: Dict


class NetworkScanner:
    """Handles network-level scanning and discovery"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.docker_client = docker.from_env()
    
    def network_discovery(self, target_network: str) -> ScanResult:
        """Perform network discovery using nmap"""
        print(f"[INFO] Starting network discovery on {target_network}")
        
        # Perform host discovery
        self.nm.scan(hosts=target_network, arguments='-sn')
        
        hosts = []
        for host in self.nm.all_hosts():
            host_info = {
                'ip': host,
                'hostname': self.nm[host].hostname(),
                'state': self.nm[host].state(),
                'mac': None,
                'vendor': None
            }
            
            # Get MAC and vendor if available
            if 'addresses' in self.nm[host]:
                addresses = self.nm[host]['addresses']
                if 'mac' in addresses:
                    host_info['mac'] = addresses['mac']
                    if 'vendor' in self.nm[host]['vendor']:
                        host_info['vendor'] = self.nm[host]['vendor'][addresses['mac']]
            
            hosts.append(host_info)
        
        return ScanResult(
            scan_type=ScanType.NETWORK_DISCOVERY,
            target=target_network,
            timestamp=datetime.now(),
            findings=hosts,
            metadata={'scanner': 'nmap', 'network': target_network}
        )
    
    def port_scan(self, target: str, ports: str = '1-1000') -> ScanResult:
        """Perform port scanning on target"""
        print(f"[INFO] Starting port scan on {target} for ports {ports}")
        
        # Perform port scan
        self.nm.scan(target, ports, '-sV')
        
        open_ports = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                lport = self.nm[host][proto].keys()
                for port in lport:
                    if self.nm[host][proto][port]['state'] == 'open':
                        port_info = {
                            'host': host,
                            'port': port,
                            'protocol': proto,
                            'service': self.nm[host][proto][port]['name'],
                            'version': self.nm[host][proto][port]['version'],
                            'product': self.nm[host][proto][port]['product'],
                            'state': self.nm[host][proto][port]['state']
                        }
                        open_ports.append(port_info)
        
        return ScanResult(
            scan_type=ScanType.PORT_SCAN,
            target=target,
            timestamp=datetime.now(),
            findings=open_ports,
            metadata={'scanner': 'nmap', 'ports': ports}
        )


class WebApplicationScanner:
    """Handles web application vulnerability scanning"""
    
    def __init__(self):
        self.zap_host = 'http://zap-proxy:8080'
    
    def web_app_scan(self, target_url: str) -> ScanResult:
        """Perform web application security scan using OWASP ZAP"""
        print(f"[INFO] Starting web application scan on {target_url}")
        
        try:
            import requests
            
            # Start ZAP session
            requests.get(f"{self.zap_host}/JSON/core/action/newSession/")
            
            # Spider the target
            spider_resp = requests.get(f"{self.zap_host}/JSON/spider/action/scan/", 
                                     params={'url': target_url})
            spider_task_id = spider_resp.json()['scan']
            
            # Wait for spider to complete
            while True:
                status_resp = requests.get(f"{self.zap_host}/JSON/spider/view/status/", 
                                         params={'scanId': spider_task_id})
                status = status_resp.json()['status']
                
                if status == '100':
                    break
                time.sleep(5)
            
            # Active scan
            scan_resp = requests.get(f"{self.zap_host}/JSON/ascan/action/scan/", 
                                   params={'url': target_url})
            scan_task_id = scan_resp.json()['scan']
            
            # Wait for active scan to complete
            while True:
                status_resp = requests.get(f"{self.zap_host}/JSON/ascan/view/status/", 
                                         params={'scanId': scan_task_id})
                status = status_resp.json()['status']
                
                if status == '100':
                    break
                time.sleep(10)
            
            # Get alerts
            alerts_resp = requests.get(f"{self.zap_host}/JSON/core/view/alerts/", 
                                     params={'baseurl': target_url})
            alerts = alerts_resp.json()['alerts']
            
            return ScanResult(
                scan_type=ScanType.WEB_APPLICATION,
                target=target_url,
                timestamp=datetime.now(),
                findings=alerts,
                metadata={'scanner': 'owasp_zap', 'url': target_url}
            )
            
        except Exception as e:
            print(f"[ERROR] Web application scan failed: {str(e)}")
            return ScanResult(
                scan_type=ScanType.WEB_APPLICATION,
                target=target_url,
                timestamp=datetime.now(),
                findings=[],
                metadata={'scanner': 'owasp_zap', 'error': str(e)}
            )


class ContainerScanner:
    """Scans Docker containers for vulnerabilities"""
    
    def __init__(self):
        self.docker_client = docker.from_env()
    
    def container_scan(self) -> ScanResult:
        """Scan running containers for vulnerabilities"""
        print("[INFO] Scanning running containers")
        
        containers = self.docker_client.containers.list()
        container_vulns = []
        
        for container in containers:
            container_info = {
                'id': container.id[:12],
                'name': container.name,
                'image': container.image.tags,
                'status': container.status,
                'ports': container.ports
            }
            
            # In a real implementation, we would use a tool like Trivy or Clair
            # For now, we'll simulate finding some vulnerabilities
            simulated_vulns = [
                {
                    'container_id': container.id[:12],
                    'vulnerability': 'Base OS has unfixed CVEs',
                    'severity': 'medium',
                    'cve': 'CVE-2023-XXXX'
                }
            ]
            
            container_vulns.extend(simulated_vulns)
        
        return ScanResult(
            scan_type=ScanType.VULNERABILITY_SCAN,
            target='all_containers',
            timestamp=datetime.now(),
            findings=container_vulns,
            metadata={'scanner': 'docker_scanner', 'count': len(containers)}
        )


class TrafficAnalyzer:
    """Analyzes network traffic to discover hidden assets"""
    
    def __init__(self):
        pass
    
    def analyze_pcap(self, pcap_file: str) -> ScanResult:
        """Analyze PCAP file for network activity"""
        print(f"[INFO] Analyzing PCAP file: {pcap_file}")
        
        try:
            capture = FileCapture(pcap_file)
            hosts = {}
            
            for packet in capture:
                try:
                    if hasattr(packet, 'ip'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        
                        # Track source hosts
                        if src_ip not in hosts:
                            hosts[src_ip] = {'seen_as': set(), 'protocols': set()}
                        hosts[src_ip]['seen_as'].add('source')
                        if hasattr(packet, '_layer_names'):
                            hosts[src_ip]['protocols'].update(packet._layer_names)
                        
                        # Track destination hosts
                        if dst_ip not in hosts:
                            hosts[dst_ip] = {'seen_as': set(), 'protocols': set()}
                        hosts[dst_ip]['seen_as'].add('destination')
                        if hasattr(packet, '_layer_names'):
                            hosts[dst_ip]['protocols'].update(packet._layer_names)
                            
                except AttributeError:
                    # Packet doesn't have IP layer
                    continue
            
            # Convert to list of dicts
            host_list = []
            for ip, info in hosts.items():
                host_list.append({
                    'ip': ip,
                    'seen_as': list(info['seen_as']),
                    'protocols': list(info['protocols'])
                })
            
            return ScanResult(
                scan_type=ScanType.NETWORK_DISCOVERY,
                target=pcap_file,
                timestamp=datetime.now(),
                findings=host_list,
                metadata={'scanner': 'traffic_analyzer', 'file': pcap_file}
            )
            
        except Exception as e:
            print(f"[ERROR] PCAP analysis failed: {str(e)}")
            return ScanResult(
                scan_type=ScanType.NETWORK_DISCOVERY,
                target=pcap_file,
                timestamp=datetime.now(),
                findings=[],
                metadata={'scanner': 'traffic_analyzer', 'error': str(e)}
            )


class AdvancedScannerEngine:
    """Main scanner engine orchestrating all scanning activities"""
    
    def __init__(self):
        self.network_scanner = NetworkScanner()
        self.web_scanner = WebApplicationScanner()
        self.container_scanner = ContainerScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        self.scan_results = []
    
    def run_comprehensive_scan(self, targets: List[str], scan_types: List[ScanType] = None) -> List[ScanResult]:
        """Run comprehensive scan across all targets and scan types"""
        if scan_types is None:
            scan_types = list(ScanType)
        
        all_results = []
        
        for target in targets:
            print(f"[INFO] Scanning target: {target}")
            
            for scan_type in scan_types:
                try:
                    if scan_type == ScanType.NETWORK_DISCOVERY:
                        result = self.network_scanner.network_discovery(target)
                    elif scan_type == ScanType.PORT_SCAN:
                        result = self.network_scanner.port_scan(target)
                    elif scan_type == ScanType.WEB_APPLICATION:
                        result = self.web_scanner.web_app_scan(target)
                    elif scan_type == ScanType.VULNERABILITY_SCAN:
                        # For network targets, skip web scans
                        if target.startswith(('http://', 'https://')):
                            result = self.web_scanner.web_app_scan(target)
                        else:
                            continue
                    
                    if 'result' in locals():
                        all_results.append(result)
                        self.scan_results.append(result)
                        
                except Exception as e:
                    print(f"[ERROR] Failed to run {scan_type.value} on {target}: {str(e)}")
        
        return all_results
    
    def save_results(self, filename: str):
        """Save scan results to JSON file"""
        results_json = []
        for result in self.scan_results:
            result_dict = {
                'scan_type': result.scan_type.value,
                'target': result.target,
                'timestamp': result.timestamp.isoformat(),
                'findings': result.findings,
                'metadata': result.metadata
            }
            results_json.append(result_dict)
        
        with open(filename, 'w') as f:
            json.dump(results_json, f, indent=2)
        
        print(f"[INFO] Results saved to {filename}")
    
    def generate_report(self) -> Dict:
        """Generate a summary report of all scans"""
        report = {
            'scan_summary': {},
            'total_findings': 0,
            'by_severity': {},
            'assets_discovered': 0,
            'last_scan': datetime.now().isoformat()
        }
        
        for result in self.scan_results:
            scan_type = result.scan_type.value
            if scan_type not in report['scan_summary']:
                report['scan_summary'][scan_type] = 0
            report['scan_summary'][scan_type] += len(result.findings)
            report['total_findings'] += len(result.findings)
        
        # Count unique assets discovered
        unique_assets = set()
        for result in self.scan_results:
            for finding in result.findings:
                if 'ip' in finding:
                    unique_assets.add(finding['ip'])
                elif 'host' in finding:
                    unique_assets.add(finding['host'])
        
        report['assets_discovered'] = len(unique_assets)
        
        return report


# Example usage
if __name__ == "__main__":
    scanner = AdvancedScannerEngine()
    
    # Define targets for scanning
    targets = [
        "10.0.0.0/24",  # Internal network
        "https://example.com",  # External web app
        "http://localhost:8080"  # Internal web app
    ]
    
    # Run comprehensive scan
    results = scanner.run_comprehensive_scan(targets)
    
    # Generate report
    report = scanner.generate_report()
    print("\n[REPORT]")
    print(json.dumps(report, indent=2))
    
    # Save results
    scanner.save_results("scan_results.json")