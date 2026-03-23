"""
Enterprise ASM System - Multi-Source Asset Intelligence Engine
Continuous intelligence aggregation from multiple sources
"""
import asyncio
import aiohttp
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Any, AsyncGenerator, Set
from dataclasses import dataclass, field
import logging
from enum import Enum

from core.models import (
    Asset, AssetType, AssetStatus, CloudProvider, Service, 
    ServiceProtocol, GeoLocation, Relationship, RelationshipType
)
from config.settings import (
    DataSourceConfig, DataSourceType, SystemConfig, DEFAULT_CONFIG
)


logger = logging.getLogger(__name__)


class IntelligenceSourceStatus(Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"


@dataclass
class IntelligenceResult:
    """Result from an intelligence source"""
    source: str
    source_type: DataSourceType
    assets: List[Asset] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    raw_data: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Metadata
    fetched_at: datetime = field(default_factory=datetime.utcnow)
    fetch_duration_ms: int = 0
    items_count: int = 0
    new_items_count: int = 0
    updated_items_count: int = 0
    
    # Status
    status: IntelligenceSourceStatus = IntelligenceSourceStatus.ACTIVE
    confidence_score: float = 1.0


@dataclass
class RateLimiter:
    """Token bucket rate limiter"""
    rate_limit: int  # requests per minute
    tokens: float = field(init=False)
    last_update: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        self.tokens = float(self.rate_limit)
    
    async def acquire(self) -> bool:
        """Acquire a token, waiting if necessary"""
        now = datetime.utcnow()
        elapsed = (now - self.last_update).total_seconds()
        
        # Replenish tokens
        self.tokens = min(
            float(self.rate_limit),
            self.tokens + (elapsed * self.rate_limit / 60.0)
        )
        self.last_update = now
        
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        
        return False
    
    async def wait_for_token(self):
        """Wait until a token is available"""
        while not await self.acquire():
            wait_time = (1.0 - self.tokens) * 60.0 / self.rate_limit
            await asyncio.sleep(min(wait_time, 5.0))


class BaseIntelligenceSource:
    """Base class for all intelligence sources"""
    
    def __init__(self, config: DataSourceConfig):
        self.config = config
        self.name = config.name
        self.source_type = config.source_type
        self.enabled = config.enabled
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.session: Optional[aiohttp.ClientSession] = None
        self.status = IntelligenceSourceStatus.ACTIVE
        self.last_success: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.error_count = 0
        self.success_count = 0
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        headers = {
            "User-Agent": "Enterprise-ASM/1.0",
            **self.config.headers
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def fetch(self, query: Any) -> IntelligenceResult:
        """Fetch intelligence data - to be implemented by subclasses"""
        raise NotImplementedError
    
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        **kwargs
    ) -> Dict[str, Any]:
        """Make an HTTP request with rate limiting and retry logic"""
        await self.rate_limiter.wait_for_token()
        
        for attempt in range(self.config.retry_count):
            try:
                async with self.session.request(method, url, **kwargs) as response:
                    if response.status == 429:
                        # Rate limited
                        self.status = IntelligenceSourceStatus.RATE_LIMITED
                        retry_after = int(response.headers.get('Retry-After', 60))
                        logger.warning(f"Rate limited by {self.name}, waiting {retry_after}s")
                        await asyncio.sleep(retry_after)
                        continue
                    
                    response.raise_for_status()
                    
                    # Success
                    self.status = IntelligenceSourceStatus.ACTIVE
                    self.last_success = datetime.utcnow()
                    self.success_count += 1
                    self.error_count = 0
                    
                    return await response.json()
                    
            except aiohttp.ClientError as e:
                self.last_error = str(e)
                self.error_count += 1
                
                if attempt == self.config.retry_count - 1:
                    self.status = IntelligenceSourceStatus.FAILED
                    logger.error(f"Failed to fetch from {self.name}: {e}")
                    raise
                
                # Exponential backoff
                wait_time = min(2 ** attempt, 30)
                await asyncio.sleep(wait_time)
        
        raise Exception(f"Failed after {self.config.retry_count} attempts")


class DNSSource(BaseIntelligenceSource):
    """DNS and subdomain discovery source"""
    
    async def fetch(self, domain: str) -> IntelligenceResult:
        """Fetch DNS records and subdomains for a domain"""
        result = IntelligenceResult(
            source=self.name,
            source_type=self.source_type
        )
        
        start_time = datetime.utcnow()
        
        try:
            # Example: Fetch from DNS enumeration API
            # In production, integrate with services like SecurityTrails, VirusTotal, etc.
            url = f"{self.config.endpoint}/subdomains/{domain}"
            
            if self.config.api_key:
                headers = {"X-API-Key": self.config.api_key}
            else:
                headers = {}
            
            data = await self._make_request("GET", url, headers=headers)
            
            # Parse subdomains
            subdomains = data.get('subdomains', [])
            for subdomain in subdomains:
                asset = Asset(
                    asset_type=AssetType.SUBDOMAIN,
                    value=subdomain,
                    name=subdomain,
                    status=AssetStatus.ACTIVE,
                    dns_records=data.get('dns_records', {}),
                    source_urls=[url]
                )
                asset.add_tag("discovered_via_dns")
                asset.add_tag(f"source:{self.name}")
                
                result.assets.append(asset)
                
                # Create relationship to parent domain
                relationship = Relationship(
                    source_asset_id=asset.id,
                    target_asset_id=hashlib.md5(domain.encode()).hexdigest(),
                    relationship_type=RelationshipType.BELONGS_TO,
                    confidence=0.95,
                    source=self.name
                )
                result.relationships.append(relationship)
            
            result.raw_data = [data]
            result.items_count = len(subdomains)
            result.new_items_count = len(subdomains)  # Assume all new for now
            
        except Exception as e:
            result.errors.append(str(e))
            result.status = IntelligenceSourceStatus.FAILED
        
        result.fetched_at = datetime.utcnow()
        result.fetch_duration_ms = int((result.fetched_at - start_time).total_seconds() * 1000)
        
        return result


class CertificateTransparencySource(BaseIntelligenceSource):
    """Certificate Transparency logs source"""
    
    async def fetch(self, domain: str) -> IntelligenceResult:
        """Fetch certificates from CT logs"""
        result = IntelligenceResult(
            source=self.name,
            source_type=DataSourceType.CERTIFICATE_TRANSPARENCY
        )
        
        start_time = datetime.utcnow()
        
        try:
            # Example: Fetch from crt.sh or similar CT log API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    seen_domains: Set[str] = set()
                    
                    for cert in data:
                        # Extract domain names from certificate
                        name_entry = cert.get('name_value', '')
                        domains = name_entry.split('\n')
                        
                        for d in domains:
                            d = d.strip().lower()
                            if d and d not in seen_domains and domain in d:
                                seen_domains.add(d)
                                
                                asset = Asset(
                                    asset_type=AssetType.SUBDOMAIN,
                                    value=d,
                                    name=d,
                                    status=AssetStatus.ACTIVE,
                                    metadata={
                                        'certificate_serial': cert.get('serial_number', ''),
                                        'issuer': cert.get('issuer_name', ''),
                                        'not_before': cert.get('not_before', ''),
                                        'not_after': cert.get('not_after', '')
                                    },
                                    source_urls=[url]
                                )
                                asset.add_tag("discovered_via_ct")
                                asset.add_tag(f"source:{self.name}")
                                
                                result.assets.append(asset)
                    
                    result.raw_data = data
                    result.items_count = len(seen_domains)
                    result.new_items_count = len(seen_domains)
                    
        except Exception as e:
            result.errors.append(str(e))
            result.status = IntelligenceSourceStatus.FAILED
        
        result.fetched_at = datetime.utcnow()
        result.fetch_duration_ms = int((result.fetched_at - start_time).total_seconds() * 1000)
        
        return result


class AWSCloudSource(BaseIntelligenceSource):
    """AWS Cloud asset discovery source"""
    
    def __init__(self, config: DataSourceConfig, account_config: Dict[str, Any]):
        super().__init__(config)
        self.account_config = account_config
        self.region = account_config.get('region', 'us-east-1')
    
    async def fetch(self, resource_types: Optional[List[str]] = None) -> IntelligenceResult:
        """Fetch AWS cloud resources"""
        result = IntelligenceResult(
            source=self.name,
            source_type=DataSourceType.AWS
        )
        
        start_time = datetime.utcnow()
        
        try:
            # In production, use boto3 or AWS SDK
            # This is a simplified example
            
            resource_types = resource_types or ['ec2', 's3', 'rds', 'lambda']
            
            for resource_type in resource_types:
                # Simulate fetching resources
                # In production: ec2.describe_instances(), s3.list_buckets(), etc.
                
                if resource_type == 'ec2':
                    # EC2 instances
                    instances = await self._fetch_ec2_instances()
                    for instance in instances:
                        asset = self._create_ec2_asset(instance)
                        result.assets.append(asset)
                
                elif resource_type == 's3':
                    # S3 buckets
                    buckets = await self._fetch_s3_buckets()
                    for bucket in buckets:
                        asset = self._create_s3_asset(bucket)
                        result.assets.append(asset)
                
                elif resource_type == 'rds':
                    # RDS databases
                    databases = await self._fetch_rds_instances()
                    for db in databases:
                        asset = self._create_rds_asset(db)
                        result.assets.append(asset)
            
            result.items_count = len(result.assets)
            
        except Exception as e:
            result.errors.append(str(e))
            result.status = IntelligenceSourceStatus.FAILED
        
        result.fetched_at = datetime.utcnow()
        result.fetch_duration_ms = int((result.fetched_at - start_time).total_seconds() * 1000)
        
        return result
    
    async def _fetch_ec2_instances(self) -> List[Dict]:
        """Fetch EC2 instances - placeholder for actual AWS API call"""
        # In production: Use boto3 client
        return []
    
    def _create_ec2_asset(self, instance: Dict) -> Asset:
        """Create Asset from EC2 instance data"""
        instance_id = instance.get('InstanceId', '')
        
        asset = Asset(
            asset_type=AssetType.CLOUD_RESOURCE,
            value=instance_id,
            name=instance.get('Tags', [{}])[0].get('Value', instance_id),
            cloud_provider=CloudProvider.AWS,
            cloud_region=instance.get('Placement', {}).get('AvailabilityZone', '')[:-1],
            cloud_account_id=self.account_config.get('account_id', ''),
            cloud_resource_id=instance_id,
            cloud_resource_type='ec2_instance',
            cloud_tags={t['Key']: t['Value'] for t in instance.get('Tags', [])},
            ip_addresses=[
                instance.get('PublicIpAddress'),
                instance.get('PrivateIpAddress')
            ],
            status=AssetStatus.ACTIVE if instance.get('State', {}).get('Name') == 'running' 
                   else AssetStatus.INACTIVE,
            metadata=instance
        )
        
        asset.add_tag("aws")
        asset.add_tag("ec2")
        asset.add_tag(f"source:{self.name}")
        
        return asset
    
    async def _fetch_s3_buckets(self) -> List[Dict]:
        """Fetch S3 buckets - placeholder"""
        return []
    
    def _create_s3_asset(self, bucket: Dict) -> Asset:
        """Create Asset from S3 bucket data"""
        bucket_name = bucket.get('Name', '')
        
        asset = Asset(
            asset_type=AssetType.STORAGE_BUCKET,
            value=bucket_name,
            name=bucket_name,
            cloud_provider=CloudProvider.AWS,
            cloud_account_id=self.account_config.get('account_id', ''),
            cloud_resource_id=bucket_name,
            cloud_resource_type='s3_bucket',
            status=AssetStatus.ACTIVE,
            metadata=bucket
        )
        
        asset.add_tag("aws")
        asset.add_tag("s3")
        asset.add_tag(f"source:{self.name}")
        
        return asset
    
    async def _fetch_rds_instances(self) -> List[Dict]:
        """Fetch RDS instances - placeholder"""
        return []
    
    def _create_rds_asset(self, db_instance: Dict) -> Asset:
        """Create Asset from RDS instance data"""
        db_id = db_instance.get('DBInstanceIdentifier', '')
        
        asset = Asset(
            asset_type=AssetType.DATABASE,
            value=db_id,
            name=db_id,
            cloud_provider=CloudProvider.AWS,
            cloud_region=db_instance.get('AvailabilityZone', '')[:-1],
            cloud_account_id=self.account_config.get('account_id', ''),
            cloud_resource_id=db_id,
            cloud_resource_type='rds_instance',
            cloud_tags={t['Key']: t['Value'] for t in db_instance.get('TagList', [])},
            status=AssetStatus.ACTIVE if db_instance.get('DBInstanceStatus') == 'available'
                   else AssetStatus.INACTIVE,
            metadata=db_instance
        )
        
        asset.add_tag("aws")
        asset.add_tag("rds")
        asset.add_tag(f"source:{self.name}")
        
        return asset


class GitHubLeakSource(BaseIntelligenceSource):
    """GitHub and Git leak detection source"""
    
    async def fetch(self, query: str) -> IntelligenceResult:
        """Search for potential leaks on GitHub"""
        result = IntelligenceResult(
            source=self.name,
            source_type=DataSourceType.GITHUB
        )
        
        start_time = datetime.utcnow()
        
        try:
            # Search GitHub for potential leaks
            search_queries = [
                f'"{query}" password',
                f'"{query}" api_key',
                f'"{query}" secret',
                f'"{query}" credential',
                f'org:{query}'
            ]
            
            for search_query in search_queries:
                url = "https://api.github.com/search/code"
                params = {"q": search_query}
                
                if self.config.api_key:
                    headers = {
                        "Authorization": f"token {self.config.api_key}",
                        "Accept": "application/vnd.github.v3+json"
                    }
                else:
                    headers = {"Accept": "application/vnd.github.v3+json"}
                
                try:
                    data = await self._make_request("GET", url, headers=headers, params=params)
                    
                    items = data.get('items', [])
                    for item in items:
                        repo = item.get('repository', {})
                        
                        asset = Asset(
                            asset_type=AssetType.GIT_REPOSITORY,
                            value=f"{repo.get('full_name', '')}/{item.get('path', '')}",
                            name=item.get('path', ''),
                            status=AssetStatus.ACTIVE,
                            metadata={
                                'repository': repo.get('full_name', ''),
                                'repository_url': repo.get('html_url', ''),
                                'file_path': item.get('path', ''),
                                'file_url': item.get('html_url', ''),
                                'search_query': search_query
                            },
                            source_urls=[item.get('html_url', '')]
                        )
                        
                        asset.add_tag("github")
                        asset.add_tag("potential_leak")
                        asset.add_tag(f"source:{self.name}")
                        
                        result.assets.append(asset)
                    
                    result.raw_data.append(data)
                    
                except Exception as e:
                    result.warnings.append(f"Search failed for '{search_query}': {e}")
            
            result.items_count = len(result.assets)
            
        except Exception as e:
            result.errors.append(str(e))
            result.status = IntelligenceSourceStatus.FAILED
        
        result.fetched_at = datetime.utcnow()
        result.fetch_duration_ms = int((result.fetched_at - start_time).total_seconds() * 1000)
        
        return result


class PassiveDNSSource(BaseIntelligenceSource):
    """Passive DNS source"""
    
    async def fetch(self, ip_or_domain: str) -> IntelligenceResult:
        """Fetch passive DNS data"""
        result = IntelligenceResult(
            source=self.name,
            source_type=DataSourceType.PASSIVE_DNS
        )
        
        start_time = datetime.utcnow()
        
        try:
            # Example: Fetch from Passive DNS API (e.g., CIRCL, RiskIQ, etc.)
            url = f"{self.config.endpoint}/pdns/{ip_or_domain}"
            
            if self.config.api_key:
                headers = {"X-API-Key": self.config.api_key}
            else:
                headers = {}
            
            data = await self._make_request("GET", url, headers=headers)
            
            # Process passive DNS records
            records = data.get('results', [])
            
            seen_relationships: Set[str] = set()
            
            for record in records:
                rrname = record.get('rrname', '')
                rrtype = record.get('rrtype', '')
                rdata = record.get('rdata', '')
                
                # Create assets for discovered domains/IPs
                if rrtype in ['A', 'AAAA']:
                    # IP address asset
                    ip_asset = Asset(
                        asset_type=AssetType.IP_ADDRESS,
                        value=rdata,
                        name=rdata,
                        status=AssetStatus.ACTIVE,
                        metadata={
                            'record_type': rrtype,
                            'first_seen': record.get('time_first', ''),
                            'last_seen': record.get('time_last', ''),
                            'count': record.get('count', 0)
                        }
                    )
                    ip_asset.add_tag("passive_dns")
                    ip_asset.add_tag(f"source:{self.name}")
                    
                    result.assets.append(ip_asset)
                    
                    # Create relationship
                    rel_key = f"{rrname}->{rdata}"
                    if rel_key not in seen_relationships:
                        relationship = Relationship(
                            source_asset_id=hashlib.md5(rrname.encode()).hexdigest(),
                            target_asset_id=ip_asset.id,
                            relationship_type=RelationshipType.RESOLVES_TO,
                            properties={
                                'record_type': rrtype,
                                'first_seen': record.get('time_first', ''),
                                'last_seen': record.get('time_last', '')
                            },
                            confidence=0.9,
                            source=self.name
                        )
                        result.relationships.append(relationship)
                        seen_relationships.add(rel_key)
            
            result.raw_data = [data]
            result.items_count = len(result.assets)
            
        except Exception as e:
            result.errors.append(str(e))
            result.status = IntelligenceSourceStatus.FAILED
        
        result.fetched_at = datetime.utcnow()
        result.fetch_duration_ms = int((result.fetched_at - start_time).total_seconds() * 1000)
        
        return result


class AssetIntelligenceEngine:
    """
    Multi-Source Asset Intelligence Engine
    Aggregates intelligence from multiple sources continuously
    """
    
    def __init__(self, config: SystemConfig = DEFAULT_CONFIG):
        self.config = config
        self.sources: Dict[str, BaseIntelligenceSource] = {}
        self.asset_cache: Dict[str, Asset] = {}
        self.relationship_cache: List[Relationship] = []
        self._initialized = False
    
    def register_source(self, source: BaseIntelligenceSource):
        """Register an intelligence source"""
        if source.enabled:
            self.sources[source.name] = source
            logger.info(f"Registered intelligence source: {source.name}")
    
    async def initialize(self):
        """Initialize all registered sources"""
        for name, source in self.sources.items():
            try:
                await source.__aenter__()
                logger.info(f"Initialized source: {name}")
            except Exception as e:
                logger.error(f"Failed to initialize source {name}: {e}")
        
        self._initialized = True
    
    async def shutdown(self):
        """Shutdown all sources"""
        for name, source in self.sources.items():
            try:
                await source.__aexit__(None, None, None)
                logger.info(f"Shutdown source: {name}")
            except Exception as e:
                logger.error(f"Error shutting down source {name}: {e}")
    
    async def discover_assets(
        self, 
        seed_targets: List[str],
        source_types: Optional[List[DataSourceType]] = None
    ) -> AsyncGenerator[IntelligenceResult, None]:
        """
        Discover assets from multiple sources
        Yields results as they become available
        """
        if not self._initialized:
            await self.initialize()
        
        tasks = []
        
        for target in seed_targets:
            for source_name, source in self.sources.items():
                if source_types and source.source_type not in source_types:
                    continue
                
                if not source.enabled:
                    continue
                
                task = asyncio.create_task(self._fetch_with_timeout(source, target))
                tasks.append(task)
        
        # Yield results as they complete
        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                yield result
            except Exception as e:
                logger.error(f"Intelligence fetch failed: {e}")
                yield IntelligenceResult(
                    source="unknown",
                    source_type=DataSourceType.DNS,
                    errors=[str(e)],
                    status=IntelligenceSourceStatus.FAILED
                )
    
    async def _fetch_with_timeout(
        self, 
        source: BaseIntelligenceSource, 
        target: str
    ) -> IntelligenceResult:
        """Fetch from a source with timeout"""
        try:
            return await asyncio.wait_for(
                source.fetch(target),
                timeout=self.config.worker_timeout
            )
        except asyncio.TimeoutError:
            return IntelligenceResult(
                source=source.name,
                source_type=source.source_type,
                errors=[f"Timeout after {self.config.worker_timeout}s"],
                status=IntelligenceSourceStatus.FAILED
            )
    
    def merge_results(self, results: List[IntelligenceResult]) -> tuple:
        """
        Merge multiple intelligence results
        Deduplicates assets and relationships
        """
        merged_assets: Dict[str, Asset] = {}
        merged_relationships: Dict[str, Relationship] = {}
        all_errors: List[str] = []
        all_warnings: List[str] = []
        
        for result in results:
            all_errors.extend(result.errors)
            all_warnings.extend(result.warnings)
            
            # Merge assets
            for asset in result.assets:
                # Generate consistent ID based on asset value and type
                asset_key = f"{asset.asset_type.value}:{asset.value.lower()}"
                
                if asset_key in merged_assets:
                    # Merge with existing asset
                    merged_assets[asset_key].merge(asset)
                else:
                    merged_assets[asset_key] = asset
            
            # Merge relationships
            for rel in result.relationships:
                rel_key = f"{rel.source_asset_id}:{rel.target_asset_id}:{rel.relationship_type.value}"
                
                if rel_key not in merged_relationships:
                    merged_relationships[rel_key] = rel
        
        return (
            list(merged_assets.values()),
            list(merged_relationships.values()),
            all_errors,
            all_warnings
        )
    
    async def continuous_discovery(
        self,
        seed_targets: List[str],
        interval_seconds: int = 3600
    ) -> AsyncGenerator[tuple, None]:
        """
        Continuous asset discovery loop
        Yields merged results at regular intervals
        """
        while True:
            start_time = datetime.utcnow()
            results = []
            
            async for result in self.discover_assets(seed_targets):
                results.append(result)
            
            # Merge all results
            assets, relationships, errors, warnings = self.merge_results(results)
            
            # Update caches
            for asset in assets:
                self.asset_cache[asset.id] = asset
            
            self.relationship_cache.extend(relationships)
            
            yield (assets, relationships, errors, warnings)
            
            # Wait for next interval
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            sleep_time = max(0, interval_seconds - elapsed)
            
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)


# Factory function to create intelligence sources
def create_intelligence_source(
    config: DataSourceConfig,
    additional_config: Optional[Dict[str, Any]] = None
) -> BaseIntelligenceSource:
    """Factory function to create appropriate intelligence source"""
    source_map = {
        DataSourceType.DNS: DNSSource,
        DataSourceType.SUBDOMAIN: DNSSource,
        DataSourceType.CERTIFICATE_TRANSPARENCY: CertificateTransparencySource,
        DataSourceType.AWS: AWSCloudSource,
        DataSourceType.GITHUB: GitHubLeakSource,
        DataSourceType.PASSIVE_DNS: PassiveDNSSource,
    }
    
    source_class = source_map.get(config.source_type)
    
    if not source_class:
        raise ValueError(f"Unknown source type: {config.source_type}")
    
    if additional_config and config.source_type == DataSourceType.AWS:
        return source_class(config, additional_config)
    
    return source_class(config)


async def main():
    """Example usage of the Asset Intelligence Engine"""
    import json
    
    # Configure sources
    configs = [
        DataSourceConfig(
            name="crt_sh",
            source_type=DataSourceType.CERTIFICATE_TRANSPARENCY,
            enabled=True,
            rate_limit=60
        ),
        DataSourceConfig(
            name="github_search",
            source_type=DataSourceType.GITHUB,
            enabled=True,
            api_key=None,  # Add your GitHub token
            rate_limit=30
        ),
    ]
    
    # Create engine
    engine = AssetIntelligenceEngine()
    
    # Register sources
    for config in configs:
        source = create_intelligence_source(config)
        engine.register_source(source)
    
    # Initialize
    await engine.initialize()
    
    # Run discovery
    seed_domains = ["example.com"]
    
    print("Starting asset discovery...")
    
    async for result in engine.discover_assets(seed_domains):
        print(f"\n{'='*60}")
        print(f"Source: {result.source}")
        print(f"Status: {result.status.value}")
        print(f"Assets found: {len(result.assets)}")
        print(f"Relationships: {len(result.relationships)}")
        print(f"Duration: {result.fetch_duration_ms}ms")
        
        if result.errors:
            print(f"Errors: {result.errors}")
        
        if result.assets:
            print("\nSample assets:")
            for asset in result.assets[:5]:
                print(f"  - [{asset.asset_type.value}] {asset.value}")
    
    # Shutdown
    await engine.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
