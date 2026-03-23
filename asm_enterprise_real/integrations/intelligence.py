"""
Real Intelligence Integrations
Shodan, Censys, AWS, Certificate Transparency, GitHub
"""
import asyncio
import aiohttp
import json
import time
from typing import List, Dict, Optional, AsyncGenerator
from datetime import datetime
import gzip
import io
import logging

from config.settings import ASMConfig, load_config
from core.models import Asset, AssetType, CVE, CVSS, ExploitMaturity, Vulnerability, Severity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ShodanIntegration:
    """Real Shodan API integration for internet-facing asset discovery"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.shodan
        self.base_url = self.config.base_url
        self.session = None
        
    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            headers = {"User-Agent": "Enterprise-ASM/1.0"}
            self.session = aiohttp.ClientSession(headers=headers)
        return self.session
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def search(self, query: str, limit: int = 100) -> List[Dict]:
        """Search Shodan for assets matching query"""
        if not self.config.api_key:
            logger.warning("Shodan API key not configured")
            return []
        
        results = []
        page = 1
        session = await self._get_session()
        
        try:
            while len(results) < limit:
                url = f"{self.base_url}/shodan/host/search"
                params = {
                    'key': self.config.api_key,
                    'query': query,
                    'page': page,
                    'limit': min(100, limit - len(results))
                }
                
                async with session.get(url, params=params, timeout=self.config.timeout) as resp:
                    if resp.status == 401:
                        logger.error("Invalid Shodan API key")
                        break
                    elif resp.status != 200:
                        logger.error(f"Shodan API error: {resp.status}")
                        break
                    
                    data = await resp.json()
                    matches = data.get('matches', [])
                    
                    for match in matches:
                        results.append(match)
                    
                    if len(matches) < 100 or len(results) >= limit:
                        break
                    
                    page += 1
                    await asyncio.sleep(self.config.rate_limit_delay)
                    
        except Exception as e:
            logger.error(f"Shodan search error: {e}")
        
        return results[:limit]
    
    async def host_lookup(self, ip: str) -> Optional[Dict]:
        """Lookup specific IP in Shodan"""
        if not self.config.api_key:
            return None
        
        session = await self._get_session()
        try:
            url = f"{self.base_url}/shodan/host/{ip}"
            params = {'key': self.config.api_key}
            
            async with session.get(url, params=params, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    return await resp.json()
                return None
        except Exception as e:
            logger.error(f"Shodan host lookup error: {e}")
            return None
    
    async def discover_assets(self, domains: List[str]) -> AsyncGenerator[Asset, None]:
        """Discover assets from domains using Shodan"""
        for domain in domains:
            try:
                # Search by domain
                results = await self.search(f'hostname:{domain}', limit=50)
                
                for result in results:
                    asset = Asset(
                        asset_type=AssetType.IP_ADDRESS,
                        value=result.get('ip_str', ''),
                        cloud_provider=result.get('cloud', {}).get('provider', ''),
                        cloud_region=result.get('cloud', {}).get('region', ''),
                        is_internet_facing=True,
                        is_public=True,
                        source='shodan',
                        raw_data=result
                    )
                    
                    # Extract ports and services
                    asset.ports = [port.get('port') for port in result.get('ports', [])]
                    asset.services = list(set([
                        port.get('product', '') + ' ' + port.get('version', '')
                        for port in result.get('ports', [])
                        if port.get('product')
                    ]))
                    
                    # Calculate exposure score
                    asset.exposure_score = self._calculate_exposure(result)
                    asset.open_ports_count = len(asset.ports)
                    
                    # Check for admin panels
                    for port in result.get('ports', []):
                        service = port.get('http', {})
                        if service:
                            title = service.get('title', '').lower()
                            if any(x in title for x in ['admin', 'login', 'dashboard', 'wp-admin']):
                                asset.admin_panel_exposed = True
                                break
                    
                    asset.normalize()
                    yield asset
                    
            except Exception as e:
                logger.error(f"Error discovering assets for {domain}: {e}")
    
    def _calculate_exposure(self, data: Dict) -> float:
        """Calculate exposure score based on Shodan data"""
        score = 0.0
        
        # More ports = higher exposure
        port_count = len(data.get('ports', []))
        score += min(3.0, port_count * 0.3)
        
        # Dangerous ports
        dangerous_ports = [21, 22, 23, 25, 110, 143, 445, 3389, 6379, 27017]
        for port in data.get('ports', []):
            if port.get('port') in dangerous_ports:
                score += 1.0
        
        # Vulnerabilities found
        vulns = data.get('vulns', [])
        score += min(4.0, len(vulns) * 1.0)
        
        # Cloud exposure
        if data.get('cloud'):
            score += 1.0
        
        return min(10.0, score)


class CensysIntegration:
    """Real Censys API integration for comprehensive asset discovery"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.censys
        self.base_url = self.config.base_url
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(auth=aiohttp.BasicAuth(
                self.config.api_id,
                self.config.api_secret
            ))
        return self.session
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def search_hosts(self, query: str, limit: int = 100) -> List[Dict]:
        """Search Censys for hosts"""
        if not self.config.api_id or not self.config.api_secret:
            logger.warning("Censys credentials not configured")
            return []
        
        results = []
        session = await self._get_session()
        
        try:
            url = f"{self.base_url}/hosts/search"
            payload = {
                'q': query,
                'per_page': min(100, limit),
                'sort_order': 'RELEVANCE',
                'virtual_hosts': 'EXCLUDE'
            }
            
            async with session.post(url, json=payload, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get('result', {}).get('hits', [])
                else:
                    logger.error(f"Censys API error: {resp.status}")
                    
        except Exception as e:
            logger.error(f"Censys search error: {e}")
        
        return results[:limit]
    
    async def get_host_details(self, ip: str) -> Optional[Dict]:
        """Get detailed host information"""
        if not self.config.api_id or not self.config.api_secret:
            return None
        
        session = await self._get_session()
        try:
            url = f"{self.base_url}/hosts/{ip}"
            params = {'at_time': datetime.utcnow().isoformat()}
            
            async with session.get(url, params=params, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    return (await resp.json()).get('result', {})
                return None
        except Exception as e:
            logger.error(f"Censys host details error: {e}")
            return None
    
    async def search_certificates(self, query: str, limit: int = 100) -> List[Dict]:
        """Search Censys certificates"""
        if not self.config.api_id or not self.config.api_secret:
            return []
        
        results = []
        session = await self._get_session()
        
        try:
            url = f"{self.base_url}/certificates/search"
            payload = {
                'q': query,
                'per_page': min(100, limit),
                'sort_order': 'RELEVANCE'
            }
            
            async with session.post(url, json=payload, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get('result', {}).get('hits', [])
                    
        except Exception as e:
            logger.error(f"Censys certificate search error: {e}")
        
        return results[:limit]
    
    async def discover_assets(self, domains: List[str]) -> AsyncGenerator[Asset, None]:
        """Discover assets from domains using Censys"""
        for domain in domains:
            try:
                # Search by domain
                results = await self.search_hosts(f'services.tls.certificates.names: {domain}', limit=50)
                
                for result in results:
                    ip = result.get('ip', '')
                    if not ip:
                        continue
                    
                    asset = Asset(
                        asset_type=AssetType.IP_ADDRESS,
                        value=ip,
                        is_internet_facing=True,
                        is_public=True,
                        source='censys',
                        raw_data=result
                    )
                    
                    # Extract services
                    services = result.get('services', [])
                    asset.ports = [int(s.get('port', 0)) for s in services if s.get('port')]
                    asset.services = list(set([
                        s.get('service_name', '') 
                        for s in services 
                        if s.get('service_name')
                    ]))
                    
                    # TLS info
                    for service in services:
                        if 'tls' in service:
                            tls_info = service['tls']
                            if 'certificate' in tls_info:
                                cert = tls_info['certificate']
                                asset.certificate_info = {
                                    'subject': cert.get('names', []),
                                    'issuer': cert.get('parsed', {}).get('issuer', {}),
                                    'fingerprint': cert.get('fingerprint_sha256', '')
                                }
                    
                    asset.exposure_score = self._calculate_exposure(result)
                    asset.open_ports_count = len(asset.ports)
                    asset.normalize()
                    
                    yield asset
                    
            except Exception as e:
                logger.error(f"Error discovering assets for {domain} via Censys: {e}")
    
    def _calculate_exposure(self, data: Dict) -> float:
        """Calculate exposure score based on Censys data"""
        score = 0.0
        
        service_count = len(data.get('services', []))
        score += min(3.0, service_count * 0.3)
        
        # Check for dangerous services
        dangerous_services = ['TELNET', 'FTP', 'SSH', 'RDP', 'SMB']
        for service in data.get('services', []):
            if service.get('service_name') in dangerous_services:
                score += 1.0
        
        # Open databases
        db_services = ['MYSQL', 'POSTGRESQL', 'MONGODB', 'REDIS', 'ELASTICSEARCH']
        for service in data.get('services', []):
            if service.get('service_name') in db_services:
                score += 1.5
        
        return min(10.0, score)


class AWSIntegration:
    """Real AWS API integration for cloud asset discovery"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.aws
        self.client_cache = {}
        
    def _get_client(self, service_name: str):
        """Get boto3 client for AWS service"""
        try:
            import boto3
            from botocore.exceptions import NoCredentialsError
            
            if service_name not in self.client_cache:
                session = boto3.Session(
                    aws_access_key_id=self.config.access_key,
                    aws_secret_access_key=self.config.secret_key,
                    region_name=self.config.region
                )
                
                if self.config.role_arn:
                    sts = session.client('sts')
                    assumed_role = sts.assume_role(
                        RoleArn=self.config.role_arn,
                        RoleSessionName="ASMScanner"
                    )
                    credentials = assumed_role['Credentials']
                    session = boto3.Session(
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                    )
                
                self.client_cache[service_name] = session.client(service_name)
            
            return self.client_cache[service_name]
            
        except ImportError:
            logger.warning("boto3 not installed. Install with: pip install boto3")
            return None
        except NoCredentialsError:
            logger.warning("AWS credentials not configured")
            return None
        except Exception as e:
            logger.error(f"AWS client error: {e}")
            return None
    
    def discover_ec2_instances(self) -> List[Asset]:
        """Discover EC2 instances"""
        ec2 = self._get_client('ec2')
        if not ec2:
            return []
        
        assets = []
        try:
            response = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}]
            )
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    asset = Asset(
                        asset_type=AssetType.CLOUD_RESOURCE,
                        value=instance.get('InstanceId', ''),
                        cloud_provider='aws',
                        cloud_region=self.config.region,
                        resource_arn=f"arn:aws:ec2:{self.config.region}:instance/{instance.get('InstanceId')}",
                        source='aws_ec2',
                        raw_data=instance
                    )
                    
                    # Network info
                    networking = instance.get('NetworkInterfaces', [])
                    if networking:
                        public_ip = networking[0].get('Association', {}).get('PublicIp')
                        private_ip = networking[0].get('PrivateIpAddress')
                        if public_ip:
                            asset.ip_addresses.append(public_ip)
                            asset.is_public = True
                            asset.is_internet_facing = True
                        if private_ip:
                            asset.ip_addresses.append(private_ip)
                    
                    # Tags
                    for tag in instance.get('Tags', []):
                        asset.resource_tags[tag['Key']] = tag['Value']
                        if tag['Key'].lower() in ['owner', 'contact']:
                            asset.owner = tag['Value']
                        if tag['Key'].lower() in ['businessunit', 'bu', 'department']:
                            asset.business_unit = tag['Value']
                        if tag['Key'].lower() == 'criticality':
                            try:
                                asset.criticality_score = float(tag['Value'])
                            except:
                                pass
                    
                    # Instance type for criticality
                    instance_type = instance.get('InstanceType', '')
                    if instance_type.startswith(('m5.', 'm6g.', 'r5.', 'r6g.')):
                        asset.criticality_score = max(asset.criticality_score, 7.0)
                    
                    asset.normalize()
                    assets.append(asset)
                    
        except Exception as e:
            logger.error(f"EC2 discovery error: {e}")
        
        return assets
    
    def discover_s3_buckets(self) -> List[Asset]:
        """Discover S3 buckets and check for misconfigurations"""
        s3 = self._get_client('s3')
        if not s3:
            return []
        
        assets = []
        try:
            response = s3.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name', '')
                
                asset = Asset(
                    asset_type=AssetType.S3_BUCKET,
                    value=bucket_name,
                    cloud_provider='aws',
                    cloud_region='global',
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    source='aws_s3',
                    raw_data=bucket
                )
                
                # Check bucket policy and ACL
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    
                    # Check for public access
                    is_public = False
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            is_public = True
                            break
                    
                    if policy and 'Policy' in policy:
                        policy_doc = json.loads(policy['Policy'])
                        for statement in policy_doc.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                principal = statement.get('Principal', {})
                                if principal == '*' or principal.get('AWS') == '*':
                                    is_public = True
                                    break
                    
                    asset.is_public = is_public
                    asset.exposure_score = 8.0 if is_public else 2.0
                    
                except Exception as e:
                    logger.debug(f"Could not check bucket {bucket_name}: {e}")
                    asset.exposure_score = 3.0
                
                asset.normalize()
                assets.append(asset)
                
        except Exception as e:
            logger.error(f"S3 discovery error: {e}")
        
        return assets
    
    def discover_lambda_functions(self) -> List[Asset]:
        """Discover Lambda functions"""
        lambda_client = self._get_client('lambda')
        if not lambda_client:
            return []
        
        assets = []
        try:
            paginator = lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for function in page.get('Functions', []):
                    asset = Asset(
                        asset_type=AssetType.FUNCTION,
                        value=function.get('FunctionName', ''),
                        cloud_provider='aws',
                        cloud_region=function.get('Region', self.config.region),
                        resource_arn=function.get('FunctionArn', ''),
                        source='aws_lambda',
                        raw_data=function
                    )
                    
                    # Check for public URL
                    config = function.get('FunctionUrlConfig', {})
                    if config.get('AuthType') == 'NONE':
                        asset.is_public = True
                        asset.is_internet_facing = True
                        asset.exposure_score = 7.0
                        asset.api_exposed = True
                    else:
                        asset.exposure_score = 3.0
                    
                    asset.normalize()
                    assets.append(asset)
                    
        except Exception as e:
            logger.error(f"Lambda discovery error: {e}")
        
        return assets
    
    def discover_rds_instances(self) -> List[Asset]:
        """Discover RDS instances"""
        rds = self._get_client('rds')
        if not rds:
            return []
        
        assets = []
        try:
            paginator = rds.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for instance in page.get('DBInstances', []):
                    asset = Asset(
                        asset_type=AssetType.DATABASE,
                        value=instance.get('DBInstanceIdentifier', ''),
                        cloud_provider='aws',
                        cloud_region=instance.get('AvailabilityZone', self.config.region),
                        resource_arn=instance.get('DbiResourceId', ''),
                        source='aws_rds',
                        raw_data=instance
                    )
                    
                    # Check if publicly accessible
                    if instance.get('PubliclyAccessible', False):
                        asset.is_public = True
                        asset.is_internet_facing = True
                        asset.exposure_score = 9.0
                    else:
                        asset.exposure_score = 4.0
                    
                    # Database engine criticality
                    engine = instance.get('Engine', '')
                    if engine in ['oracle-ee', 'sqlserver-ee']:
                        asset.criticality_score = 9.0
                    elif engine in ['mysql', 'postgres']:
                        asset.criticality_score = 7.0
                    
                    asset.normalize()
                    assets.append(asset)
                    
        except Exception as e:
            logger.error(f"RDS discovery error: {e}")
        
        return assets
    
    def discover_all_assets(self) -> List[Asset]:
        """Discover all AWS assets"""
        all_assets = []
        all_assets.extend(self.discover_ec2_instances())
        all_assets.extend(self.discover_s3_buckets())
        all_assets.extend(self.discover_lambda_functions())
        all_assets.extend(self.discover_rds_instances())
        return all_assets


class CertificateTransparencyIntegration:
    """Certificate Transparency log integration for domain discovery"""
    
    def __init__(self, config: ASMConfig):
        self.config = config
        self.ct_logs = [
            "https://ct.googleapis.com/logs/argon2024/",
            "https://ct.cloudflare.com/logs/nimbus2024/",
        ]
    
    async def search_domains(self, domain: str) -> List[str]:
        """Search CT logs for subdomains"""
        subdomains = set()
        
        async with aiohttp.ClientSession() as session:
            for log_url in self.ct_logs:
                try:
                    # Use certspotter API as a CT log aggregator
                    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
                    
                    async with session.get(url, timeout=30) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for entry in data:
                                dns_names = entry.get('dns_names', [])
                                for name in dns_names:
                                    if name.startswith('*'):
                                        continue
                                    clean_name = name.lower().strip()
                                    if clean_name.endswith(domain.lower()):
                                        subdomains.add(clean_name)
                    
                    await asyncio.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    logger.debug(f"CT log search error: {e}")
                    continue
        
        return list(subdomains)
    
    async def discover_assets(self, domains: List[str]) -> AsyncGenerator[Asset, None]:
        """Discover assets from CT logs"""
        for domain in domains:
            try:
                subdomains = await self.search_domains(domain)
                
                for subdomain in subdomains:
                    asset = Asset(
                        asset_type=AssetType.DOMAIN,
                        value=subdomain,
                        source='certificate_transparency',
                        confidence_score=0.9
                    )
                    asset.normalize()
                    yield asset
                    
            except Exception as e:
                logger.error(f"CT discovery error for {domain}: {e}")


class GitHubLeakDetection:
    """GitHub code search for credential leaks"""
    
    def __init__(self, config: ASMConfig):
        self.config = config
        self.github_token = os.getenv("GITHUB_TOKEN", "")
    
    async def search_leaks(self, organization: str) -> List[Dict]:
        """Search GitHub for potential leaks"""
        if not self.github_token:
            logger.warning("GitHub token not configured")
            return []
        
        results = []
        queries = [
            f'org:{organization} password',
            f'org:{organization} api_key',
            f'org:{organization} secret',
            f'org:{organization} aws_access_key',
            f'org:{organization} private_key',
        ]
        
        async with aiohttp.ClientSession() as session:
            for query in queries:
                try:
                    url = "https://api.github.com/search/code"
                    headers = {
                        'Authorization': f'token {self.github_token}',
                        'Accept': 'application/vnd.github.v3+json'
                    }
                    params = {'q': query, 'per_page': 10}
                    
                    async with session.get(url, headers=headers, params=params, timeout=30) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            results.extend(data.get('items', []))
                        elif resp.status == 403:
                            logger.warning("GitHub API rate limited")
                            break
                        
                    await asyncio.sleep(10)  # GitHub rate limiting
                    
                except Exception as e:
                    logger.error(f"GitHub search error: {e}")
        
        return results


async def demo_integrations():
    """Demo real integrations"""
    config = load_config()
    
    print("=" * 60)
    print("ENTERPRISE ASM - REAL INTEGRATIONS DEMO")
    print("=" * 60)
    
    # Demo Certificate Transparency
    print("\n📜 Certificate Transparency Discovery:")
    ct_integration = CertificateTransparencyIntegration(config)
    domains_found = []
    async for asset in ct_integration.discover_assets(['example.com']):
        print(f"  ✓ Found: {asset.value}")
        domains_found.append(asset.value)
    
    # Demo Shodan (if configured)
    print("\n🔍 Shodan Integration:")
    shodan = ShodanIntegration(config)
    if config.shodan.api_key:
        print(f"  ✓ API Key configured: {config.shodan.api_key[:8]}...")
        async for asset in shodan.discover_assets(['example.com']):
            print(f"  ✓ Found IP: {asset.value} (Ports: {asset.ports}, Exposure: {asset.exposure_score})")
    else:
        print("  ⚠️  Shodan API key not configured (set SHODAN_API_KEY env var)")
    
    # Demo Censys (if configured)
    print("\n🌐 Censys Integration:")
    censys = CensysIntegration(config)
    if config.censys.api_id and config.censys.api_secret:
        print(f"  ✓ API ID configured: {config.censys.api_id}")
        async for asset in censys.discover_assets(['example.com']):
            print(f"  ✓ Found IP: {asset.value} (Services: {asset.services})")
    else:
        print("  ⚠️  Censys credentials not configured")
    
    # Demo AWS (if configured)
    print("\n☁️  AWS Integration:")
    aws = AWSIntegration(config)
    if config.aws.access_key:
        print(f"  ✓ AWS credentials configured for region: {config.aws.region}")
        assets = aws.discover_all_assets()
        for asset in assets:
            print(f"  ✓ Found {asset.asset_type.value}: {asset.value} (Public: {asset.is_public})")
    else:
        print("  ⚠️  AWS credentials not configured")
    
    print("\n" + "=" * 60)
    print("Integration demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo_integrations())
