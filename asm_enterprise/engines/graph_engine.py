"""
Enterprise ASM System - Asset Correlation & Graph Engine
Graph-based asset correlation with Neo4j integration
Enables attack path analysis and lateral movement simulation
"""
import asyncio
from datetime import datetime
from typing import List, Dict, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import logging
import hashlib

try:
    from neo4j import GraphDatabase, AsyncGraphDatabase
    from neo4j.exceptions import ServiceUnavailable, CypherSyntaxError
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    CypherSyntaxError = Exception  # Mock for when neo4j is not installed
    logger = logging.getLogger(__name__)
    logger.warning("Neo4j driver not installed. Install with: pip install neo4j")

from core.models import (
    Asset, AssetType, AssetStatus, Relationship, RelationshipType,
    Vulnerability, VulnerabilitySeverity, AttackPath, CVE
)
from config.settings import GraphDBConfig, SystemConfig, DEFAULT_CONFIG


logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the asset graph"""
    id: str
    labels: List[str]
    properties: Dict[str, Any]
    
    def to_neo4j(self) -> Tuple[str, Dict[str, Any]]:
        """Convert to Neo4j format"""
        label_str = ":".join(self.labels)
        return label_str, self.properties


@dataclass
class GraphEdge:
    """Represents an edge in the asset graph"""
    source_id: str
    target_id: str
    relationship_type: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPathResult:
    """Result of attack path analysis"""
    paths: List[AttackPath] = field(default_factory=list)
    total_paths_found: int = 0
    critical_paths: int = 0
    high_risk_paths: int = 0
    average_path_length: float = 0.0
    max_path_length: int = 0
    crown_jewels_at_risk: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)


class AssetGraphEngine:
    """
    Graph-based Asset Correlation Engine
    Uses Neo4j for storing and querying asset relationships
    Enables attack path simulation and lateral movement analysis
    """
    
    # Cypher queries for common operations
    QUERIES = {
        'create_asset': """
            MERGE (a:%s {id: $id})
            SET a += $properties
            SET a.updated_at = datetime()
            RETURN a
        """,
        
        'create_relationship': """
            MATCH (source {id: $source_id})
            MATCH (target {id: $target_id})
            MERGE (source)-[r:%s]->(target)
            SET r += $properties
            SET r.last_seen = datetime()
            RETURN r
        """,
        
        'find_asset_by_id': """
            MATCH (a {id: $id})
            RETURN a
        """,
        
        'find_connected_assets': """
            MATCH (start {id: $asset_id})-[r*1..%d]-(connected)
            RETURN start, r, connected
        """,
        
        'find_attack_paths': """
            MATCH path = (entry:Asset)-[*1..%d]->(target:Asset)
            WHERE entry.exposure_score > 0.7
            AND target.criticality > 0.8
            AND ALL(rel IN relationships(path) WHERE rel.type IN $allowed_relationships)
            RETURN path
        """,
        
        'find_lateral_movement_paths': """
            MATCH path = (start {id: $start_id})-[*1..%d]->(target {id: $target_id})
            WHERE length(path) <= $max_hops
            RETURN path
        """,
        
        'find_crown_jewels': """
            MATCH (a:Asset)
            WHERE a.criticality >= $threshold
            RETURN a ORDER BY a.criticality DESC
            LIMIT $limit
        """,
        
        'find_exposed_assets': """
            MATCH (a:Asset)
            WHERE a.is_internet_facing = true
            OR a.has_public_ip = true
            OR a.open_ports IS NOT NULL
            RETURN a
        """,
        
        'find_vulnerable_assets': """
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE v.severity IN $severities
            RETURN a, collect(v) as vulnerabilities
        """,
        
        'get_asset_neighbors': """
            MATCH (a {id: $asset_id})-[r]-(neighbor)
            RETURN neighbor, type(r) as relationship_type
        """,
        
        'delete_asset': """
            MATCH (a {id: $id})
            DETACH DELETE a
        """,
        
        'cleanup_stale': """
            MATCH (a:Asset)
            WHERE a.last_seen < datetime() - duration({days: $stale_days})
            SET a.status = 'inactive'
            RETURN count(a) as deactivated_count
        """
    }
    
    def __init__(self, config: GraphDBConfig = None):
        self.config = config or DEFAULT_CONFIG.graph_db
        self.driver = None
        self._connected = False
        
        if not NEO4J_AVAILABLE:
            logger.warning("Neo4j driver not available. Running in mock mode.")
    
    async def connect(self):
        """Establish connection to Neo4j database"""
        if not NEO4J_AVAILABLE:
            logger.info("Running in mock mode - no Neo4j connection")
            self._connected = True
            return
        
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.config.uri,
                auth=(self.config.username, self.config.password),
                max_connection_pool_size=self.config.max_pool_size,
                connection_timeout=self.config.connection_timeout
            )
            
            # Test connection
            await self.driver.verify_connectivity()
            self._connected = True
            logger.info(f"Connected to Neo4j at {self.config.uri}")
            
        except ServiceUnavailable as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to Neo4j: {e}")
            raise
    
    async def disconnect(self):
        """Close Neo4j connection"""
        if self.driver:
            await self.driver.close()
            self._connected = False
            logger.info("Disconnected from Neo4j")
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    async def insert_asset(self, asset: Asset) -> bool:
        """Insert or update an asset in the graph"""
        if not self._connected:
            return False
        
        try:
            # Determine primary label based on asset type
            primary_label = asset.asset_type.value.upper()
            labels = ['Asset', primary_label]
            
            # Prepare properties
            properties = {
                'id': asset.id,
                'value': asset.value,
                'name': asset.name or asset.value,
                'asset_type': asset.asset_type.value,
                'status': asset.status.value,
                'criticality': asset.criticality,
                'sensitivity': asset.sensitivity,
                'owner': asset.owner,
                'team': asset.team,
                'business_unit': asset.business_unit,
                'risk_score': asset.risk_score,
                'first_discovered': asset.first_discovered.isoformat(),
                'last_seen': asset.last_seen.isoformat(),
                'updated_at': asset.updated_at.isoformat(),
                'ip_addresses': asset.ip_addresses,
                'ports': asset.ports,
                'tags': list(asset.tags),
                'technologies': asset.technologies,
                'cloud_provider': asset.cloud_provider.value if asset.cloud_provider else None,
                'cloud_region': asset.cloud_region,
                'cloud_resource_id': asset.cloud_resource_id,
                'is_internet_facing': self._is_internet_facing(asset),
                'has_public_ip': self._has_public_ip(asset),
                'open_ports': asset.ports,
                'exposure_score': self._calculate_exposure_score(asset)
            }
            
            # Add cloud tags
            if asset.cloud_tags:
                properties['cloud_tags'] = asset.cloud_tags
            
            # Add DNS records
            if asset.dns_records:
                properties['dns_records'] = asset.dns_records
            
            query = self.QUERIES['create_asset'] % primary_label
            
            async with self.driver.session() as session:
                await session.run(query, {
                    'id': asset.id,
                    'properties': properties
                })
            
            return True
            
        except CypherSyntaxError as e:
            logger.error(f"Cypher syntax error inserting asset {asset.id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error inserting asset {asset.id}: {e}")
            return False
    
    async def insert_relationship(self, relationship: Relationship) -> bool:
        """Insert or update a relationship in the graph"""
        if not self._connected:
            return False
        
        try:
            rel_type = relationship.relationship_type.value.upper()
            
            properties = {
                'type': relationship.relationship_type.value,
                'confidence': relationship.confidence,
                'source': relationship.source,
                'first_discovered': relationship.first_discovered.isoformat(),
                'last_seen': relationship.last_seen.isoformat(),
                **relationship.properties
            }
            
            query = self.QUERIES['create_relationship'] % rel_type
            
            async with self.driver.session() as session:
                await session.run(query, {
                    'source_id': relationship.source_asset_id,
                    'target_id': relationship.target_asset_id,
                    'properties': properties
                })
            
            return True
            
        except Exception as e:
            logger.error(f"Error inserting relationship: {e}")
            return False
    
    async def insert_assets_batch(self, assets: List[Asset]) -> int:
        """Insert multiple assets in batch"""
        success_count = 0
        
        # Use Neo4j transactions for better performance
        if self._connected and NEO4J_AVAILABLE:
            try:
                async with self.driver.session() as session:
                    async with session.begin_transaction() as tx:
                        for asset in assets:
                            try:
                                primary_label = asset.asset_type.value.upper()
                                labels = ['Asset', primary_label]
                                
                                properties = {
                                    'id': asset.id,
                                    'value': asset.value,
                                    'name': asset.name or asset.value,
                                    'asset_type': asset.asset_type.value,
                                    'status': asset.status.value,
                                    'criticality': asset.criticality,
                                    'risk_score': asset.risk_score,
                                    'last_seen': asset.last_seen.isoformat(),
                                    'ip_addresses': asset.ip_addresses,
                                    'ports': asset.ports,
                                    'tags': list(asset.tags),
                                    'is_internet_facing': self._is_internet_facing(asset),
                                    'exposure_score': self._calculate_exposure_score(asset)
                                }
                                
                                query = self.QUERIES['create_asset'] % primary_label
                                await tx.run(query, {
                                    'id': asset.id,
                                    'properties': properties
                                })
                                success_count += 1
                                
                            except Exception as e:
                                logger.error(f"Failed to insert asset {asset.id}: {e}")
                                continue
                        
                        await tx.commit()
                        
            except Exception as e:
                logger.error(f"Batch insert failed: {e}")
        
        return success_count
    
    async def find_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Find an asset by ID"""
        if not self._connected:
            return None
        
        try:
            async with self.driver.session() as session:
                result = await session.run(
                    self.QUERIES['find_asset_by_id'],
                    {'id': asset_id}
                )
                record = await result.single()
                
                if record:
                    return dict(record['a'])
                return None
                
        except Exception as e:
            logger.error(f"Error finding asset {asset_id}: {e}")
            return None
    
    async def find_connected_assets(
        self, 
        asset_id: str, 
        max_depth: int = 3
    ) -> List[Dict[str, Any]]:
        """Find all assets connected to a given asset within max hops"""
        if not self._connected:
            return []
        
        try:
            query = self.QUERIES['find_connected_assets'] % max_depth
            
            async with self.driver.session() as session:
                result = await session.run(query, {'asset_id': asset_id})
                
                connected = []
                async for record in result:
                    connected.append({
                        'start': dict(record['start']),
                        'relationships': [dict(r) for r in record['r']] if record['r'] else [],
                        'connected': dict(record['connected'])
                    })
                
                return connected
                
        except Exception as e:
            logger.error(f"Error finding connected assets: {e}")
            return []
    
    async def find_attack_paths(
        self,
        start_asset_ids: Optional[List[str]] = None,
        target_asset_ids: Optional[List[str]] = None,
        max_hops: int = 5,
        min_severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    ) -> AttackPathResult:
        """
        Find potential attack paths through the infrastructure
        Simulates lateral movement from entry points to crown jewels
        """
        result = AttackPathResult()
        
        if not self._connected:
            # Return mock result for testing
            return self._generate_mock_attack_paths()
        
        try:
            # Find crown jewels (high criticality assets)
            crown_jewels = await self._find_crown_jewels(threshold=0.8, limit=20)
            result.crown_jewels_at_risk = [cj['id'] for cj in crown_jewels]
            
            # Find exposed entry points
            entry_points = await self._find_entry_points()
            result.entry_points = [ep['id'] for ep in entry_points]
            
            # Find attack paths
            allowed_relationships = [
                'RESOLVES_TO', 'HOSTS', 'COMMUNICATES_WITH',
                'CONNECTED_TO', 'PROXIES_TO', 'LOAD_BALANCES'
            ]
            
            query = self.QUERIES['find_attack_paths'] % max_hops
            
            async with self.driver.session() as session:
                query_result = await session.run(
                    query,
                    {
                        'allowed_relationships': allowed_relationships
                    }
                )
                
                paths_found = []
                async for record in query_result:
                    path_data = record['path']
                    
                    # Convert to AttackPath object
                    attack_path = self._convert_path_to_object(path_data)
                    
                    if attack_path:
                        paths_found.append(attack_path)
                
                result.paths = paths_found
                result.total_paths_found = len(paths_found)
                result.critical_paths = sum(
                    1 for p in paths_found if p.total_risk_score > 0.85
                )
                result.high_risk_paths = sum(
                    1 for p in paths_found if 0.65 < p.total_risk_score <= 0.85
                )
                
                if paths_found:
                    result.average_path_length = sum(
                        p.path_length for p in paths_found
                    ) / len(paths_found)
                    result.max_path_length = max(p.path_length for p in paths_found)
            
            return result
            
        except Exception as e:
            logger.error(f"Error finding attack paths: {e}")
            return result
    
    async def simulate_lateral_movement(
        self,
        start_asset_id: str,
        target_asset_id: str,
        max_hops: int = 5
    ) -> List[AttackPath]:
        """Simulate lateral movement from start to target asset"""
        if not self._connected:
            return []
        
        try:
            query = self.QUERIES['find_lateral_movement_paths'] % max_hops
            
            async with self.driver.session() as session:
                result = await session.run(
                    query,
                    {
                        'start_id': start_asset_id,
                        'target_id': target_asset_id,
                        'max_hops': max_hops
                    }
                )
                
                paths = []
                async for record in result:
                    path_data = record['path']
                    attack_path = self._convert_path_to_object(path_data)
                    
                    if attack_path:
                        paths.append(attack_path)
                
                return paths
                
        except Exception as e:
            logger.error(f"Error simulating lateral movement: {e}")
            return []
    
    async def _find_crown_jewels(
        self, 
        threshold: float = 0.8, 
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Find high-criticality assets (crown jewels)"""
        if not self._connected:
            return []
        
        try:
            async with self.driver.session() as session:
                result = await session.run(
                    self.QUERIES['find_crown_jewels'],
                    {'threshold': threshold, 'limit': limit}
                )
                
                jewels = []
                async for record in result:
                    jewels.append(dict(record['a']))
                
                return jewels
                
        except Exception as e:
            logger.error(f"Error finding crown jewels: {e}")
            return []
    
    async def _find_entry_points(self) -> List[Dict[str, Any]]:
        """Find internet-facing assets that could serve as entry points"""
        if not self._connected:
            return []
        
        try:
            async with self.driver.session() as session:
                result = await session.run(self.QUERIES['find_exposed_assets'])
                
                entry_points = []
                async for record in result:
                    entry_points.append(dict(record['a']))
                
                return entry_points
                
        except Exception as e:
            logger.error(f"Error finding entry points: {e}")
            return []
    
    def _convert_path_to_object(self, path_data: Any) -> Optional[AttackPath]:
        """Convert Neo4j path data to AttackPath object"""
        try:
            # Extract nodes and relationships from path
            nodes = path_data.nodes if hasattr(path_data, 'nodes') else []
            relationships = path_data.relationships if hasattr(path_data, 'relationships') else []
            
            if not nodes:
                return None
            
            attack_path = AttackPath(
                name=f"Attack Path {hashlib.md5(str(nodes).encode()).hexdigest()[:8]}",
                description=f"Path from {nodes[0].get('value', 'unknown')} to {nodes[-1].get('value', 'unknown')}",
                nodes=[n.get('id') for n in nodes],
                node_details=[dict(n) for n in nodes],
                edges=[dict(r) for r in relationships],
                entry_point=nodes[0].get('id') if nodes else None,
                target_asset=nodes[-1].get('id') if nodes else None,
                crown_jewel=nodes[-1].get('criticality', 0) > 0.8 if nodes else False
            )
            
            return attack_path
            
        except Exception as e:
            logger.error(f"Error converting path: {e}")
            return None
    
    def _generate_mock_attack_paths(self) -> AttackPathResult:
        """Generate mock attack paths for testing without Neo4j"""
        result = AttackPathResult()
        
        # Create sample attack path
        path = AttackPath(
            name="Sample Attack Path",
            description="Mock attack path for demonstration",
            nodes=["asset-1", "asset-2", "asset-3"],
            crown_jewel=True,
            techniques=["T1190", "T1078", "T1021"],
            is_active=True
        )
        
        result.paths = [path]
        result.total_paths_found = 1
        result.critical_paths = 1
        result.crown_jewels_at_risk = ["asset-3"]
        result.entry_points = ["asset-1"]
        
        return result
    
    def _is_internet_facing(self, asset: Asset) -> bool:
        """Determine if an asset is internet-facing"""
        # Check for public IP addresses
        if asset.ip_addresses:
            for ip in asset.ip_addresses:
                if not self._is_private_ip(ip):
                    return True
        
        # Check for web services
        if asset.services:
            for service in asset.services:
                if service.protocol in [ServiceProtocol.HTTP, ServiceProtocol.HTTPS]:
                    return True
        
        # Check cloud resource type
        if asset.cloud_resource_type in ['load_balancer', 'api_gateway', 'cloudfront']:
            return True
        
        return False
    
    def _has_public_ip(self, asset: Asset) -> bool:
        """Check if asset has public IP addresses"""
        if not asset.ip_addresses:
            return False
        
        for ip in asset.ip_addresses:
            if not self._is_private_ip(ip):
                return True
        
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            
            # 127.0.0.0/8
            if first == 127:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _calculate_exposure_score(self, asset: Asset) -> float:
        """Calculate exposure score for an asset"""
        score = 0.0
        
        # Internet facing
        if self._is_internet_facing(asset):
            score += 0.3
        
        # Has public IP
        if self._has_public_ip(asset):
            score += 0.2
        
        # Open ports
        if asset.ports:
            port_score = min(len(asset.ports) * 0.05, 0.3)
            score += port_score
            
            # High-risk ports
            high_risk_ports = {22, 23, 3389, 445, 1433, 3306, 5432}
            if any(p in high_risk_ports for p in asset.ports):
                score += 0.2
        
        # Web services
        if asset.services:
            for service in asset.services:
                if service.protocol in [ServiceProtocol.HTTP, ServiceProtocol.HTTPS]:
                    score += 0.1
                    break
        
        return min(score, 1.0)
    
    async def get_graph_statistics(self) -> Dict[str, Any]:
        """Get statistics about the graph"""
        if not self._connected:
            return {
                'total_assets': len(self.asset_cache) if hasattr(self, 'asset_cache') else 0,
                'total_relationships': 0,
                'status': 'mock_mode'
            }
        
        try:
            async with self.driver.session() as session:
                # Count assets
                asset_result = await session.run("MATCH (a:Asset) RETURN count(a) as count")
                asset_count = (await asset_result.single())['count']
                
                # Count relationships
                rel_result = await session.run("MATCH ()-[r]->() RETURN count(r) as count")
                rel_count = (await rel_result.single())['count']
                
                # Count by type
                type_result = await session.run("""
                    MATCH (a:Asset)
                    RETURN a.asset_type as type, count(a) as count
                    ORDER BY count DESC
                """)
                
                type_counts = {}
                async for record in type_result:
                    type_counts[record['type']] = record['count']
                
                return {
                    'total_assets': asset_count,
                    'total_relationships': rel_count,
                    'assets_by_type': type_counts,
                    'status': 'connected'
                }
                
        except Exception as e:
            logger.error(f"Error getting graph statistics: {e}")
            return {'error': str(e)}


async def main():
    """Example usage of the Asset Graph Engine"""
    
    # Create engine
    engine = AssetGraphEngine()
    
    # Connect
    await engine.connect()
    
    # Create sample assets
    from core.models import Asset, AssetType, AssetStatus, Relationship, RelationshipType
    
    assets = [
        Asset(
            asset_type=AssetType.DOMAIN,
            value="example.com",
            name="example.com",
            status=AssetStatus.ACTIVE,
            criticality=0.9,
            tags={"production", "critical"}
        ),
        Asset(
            asset_type=AssetType.SUBDOMAIN,
            value="api.example.com",
            name="API Server",
            status=AssetStatus.ACTIVE,
            criticality=0.8,
            ip_addresses=["203.0.113.10"],
            ports=[443, 80],
            tags={"production", "api"}
        ),
        Asset(
            asset_type=AssetType.IP_ADDRESS,
            value="203.0.113.10",
            name="Web Server",
            status=AssetStatus.ACTIVE,
            criticality=0.7,
            tags={"production"}
        )
    ]
    
    # Insert assets
    for asset in assets:
        success = await engine.insert_asset(asset)
        print(f"Inserted asset {asset.value}: {success}")
    
    # Create relationship
    relationship = Relationship(
        source_asset_id=assets[1].id,
        target_asset_id=assets[2].id,
        relationship_type=RelationshipType.RESOLVES_TO,
        confidence=0.95
    )
    
    success = await engine.insert_relationship(relationship)
    print(f"Inserted relationship: {success}")
    
    # Get statistics
    stats = await engine.get_graph_statistics()
    print(f"\nGraph Statistics: {stats}")
    
    # Find attack paths
    attack_result = await engine.find_attack_paths(max_hops=5)
    print(f"\nAttack Paths Found: {attack_result.total_paths_found}")
    print(f"Critical Paths: {attack_result.critical_paths}")
    
    # Disconnect
    await engine.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
