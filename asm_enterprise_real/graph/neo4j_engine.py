"""
Neo4j Graph Engine
Real persistent graph database for asset correlation and attack path analysis
"""
from neo4j import GraphDatabase, basic_auth
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
import logging
import asyncio

from config.settings import ASMConfig, load_config
from core.models import Asset, AssetType, Relationship, RelationshipType, AttackPath, Vulnerability, ExploitMaturity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Neo4jGraphEngine:
    """Enterprise Neo4j graph engine for ASM"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.neo4j
        self.driver = None
        self._connect()
    
    def _connect(self):
        """Establish connection to Neo4j"""
        try:
            self.driver = GraphDatabase.driver(
                self.config.uri,
                auth=basic_auth(self.config.user, self.config.password),
                max_connection_pool_size=50,
                connection_timeout=30
            )
            # Test connection
            with self.driver.session(database=self.config.database) as session:
                session.run("MATCH (n) RETURN count(n) LIMIT 1")
            logger.info(f"Connected to Neo4j at {self.config.uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
    
    def create_indexes(self):
        """Create database indexes for performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.id)",
            "CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.canonical_value)",
            "CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.asset_type)",
            "CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.source)",
            "CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.id)",
            "CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id)",
            "CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
            "CREATE INDEX IF NOT EXISTS FOR (r:Relationship) ON (r.source_id)",
            "CREATE INDEX IF NOT EXISTS FOR (r:Relationship) ON (r.target_id)",
            "CREATE INDEX IF NOT EXISTS FOR (p:AttackPath) ON (p.id)",
            "CREATE INDEX IF NOT EXISTS FOR (p:AttackPath) ON (p.total_risk_score)",
        ]
        
        with self.driver.session(database=self.config.database) as session:
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    logger.debug(f"Index creation note: {e}")
        
        logger.info("Database indexes created")
    
    def upsert_asset(self, asset: Asset) -> str:
        """Insert or update an asset in the graph"""
        query = """
        MERGE (a:Asset {id: $id})
        ON CREATE SET
            a.asset_type = $asset_type,
            a.value = $value,
            a.canonical_value = $canonical_value,
            a.first_discovered = $first_discovered,
            a.created_at = $created_at
        ON MATCH SET
            a.value = $value,
            a.canonical_value = $canonical_value,
            a.ip_addresses = $ip_addresses,
            a.ports = $ports,
            a.services = $services,
            a.cloud_provider = $cloud_provider,
            a.cloud_region = $cloud_region,
            a.resource_arn = $resource_arn,
            a.resource_tags = $resource_tags,
            a.dns_records = $dns_records,
            a.certificate_info = $certificate_info,
            a.ssl_grade = $ssl_grade,
            a.exposure_score = $exposure_score,
            a.is_internet_facing = $is_internet_facing,
            a.is_public = $is_public,
            a.open_ports_count = $open_ports_count,
            a.admin_panel_exposed = $admin_panel_exposed,
            a.api_exposed = $api_exposed,
            a.business_unit = $business_unit,
            a.owner = $owner,
            a.criticality_score = $criticality_score,
            a.is_crown_jewel = $is_crown_jewel,
            a.data_classification = $data_classification,
            a.vulnerability_count = $vulnerability_count,
            a.critical_vulns = $critical_vulns,
            a.high_vulns = $high_vulns,
            a.medium_vulns = $medium_vulns,
            a.low_vulns = $low_vulns,
            a.last_seen = $last_seen,
            a.last_scanned = $last_scanned,
            a.updated_at = $updated_at,
            a.source = $source,
            a.confidence_score = $confidence_score,
            a.tags = $tags,
            a.notes = $notes,
            a.raw_data = $raw_data
        RETURN a.id
        """
        
        params = {
            'id': asset.id,
            'asset_type': asset.asset_type.value,
            'value': asset.value,
            'canonical_value': asset.canonical_value,
            'first_discovered': asset.first_discovered.isoformat(),
            'created_at': asset.created_at.isoformat(),
            'ip_addresses': asset.ip_addresses,
            'value': asset.value,
            'canonical_value': asset.canonical_value,
            'ip_addresses': asset.ip_addresses,
            'ports': asset.ports,
            'services': asset.services,
            'cloud_provider': asset.cloud_provider,
            'cloud_region': asset.cloud_region,
            'resource_arn': asset.resource_arn,
            'resource_tags': asset.resource_tags,
            'dns_records': asset.dns_records,
            'certificate_info': asset.certificate_info,
            'ssl_grade': asset.ssl_grade,
            'exposure_score': asset.exposure_score,
            'is_internet_facing': asset.is_internet_facing,
            'is_public': asset.is_public,
            'open_ports_count': asset.open_ports_count,
            'admin_panel_exposed': asset.admin_panel_exposed,
            'api_exposed': asset.api_exposed,
            'business_unit': asset.business_unit,
            'owner': asset.owner,
            'criticality_score': asset.criticality_score,
            'is_crown_jewel': asset.is_crown_jewel,
            'data_classification': asset.data_classification,
            'vulnerability_count': asset.vulnerability_count,
            'critical_vulns': asset.critical_vulns,
            'high_vulns': asset.high_vulns,
            'medium_vulns': asset.medium_vulns,
            'low_vulns': asset.low_vulns,
            'last_seen': asset.last_seen.isoformat(),
            'last_scanned': asset.last_scanned.isoformat() if asset.last_scanned else None,
            'updated_at': asset.updated_at.isoformat(),
            'source': asset.source,
            'confidence_score': asset.confidence_score,
            'tags': asset.tags,
            'notes': asset.notes,
            'raw_data': asset.raw_data
        }
        
        with self.driver.session(database=self.config.database) as session:
            result = session.run(query, **params)
            record = result.single()
            return record['a.id'] if record else asset.id
    
    def create_relationship(self, relationship: Relationship) -> str:
        """Create a relationship between two assets"""
        rel_type = relationship.relationship_type.value.upper().replace('_', '')
        
        query = f"""
        MATCH (source:Asset {{id: $source_id}})
        MATCH (target:Asset {{id: $target_id}})
        MERGE (source)-[r:{rel_type}]->(target)
        ON CREATE SET
            r.created_at = $created_at,
            r.properties = $properties
        ON MATCH SET
            r.updated_at = $updated_at,
            r.properties = $properties
        RETURN type(r) as relationship_type
        """
        
        params = {
            'source_id': relationship.source_id,
            'target_id': relationship.target_id,
            'created_at': relationship.created_at.isoformat(),
            'updated_at': relationship.updated_at.isoformat(),
            'properties': relationship.properties
        }
        
        with self.driver.session(database=self.config.database) as session:
            result = session.run(query, **params)
            record = result.single()
            return record['relationship_type'] if record else relationship.relationship_type.value
    
    def find_attack_paths(self, entry_point_ids: List[str], target_asset_ids: List[str], 
                         max_depth: int = 5) -> List[AttackPath]:
        """Find attack paths from entry points to crown jewels"""
        attack_paths = []
        
        query = """
        UNWIND $entry_points AS entry_id
        UNWIND $targets AS target_id
        MATCH (entry:Asset {id: entry_id})
        MATCH (target:Asset {id: target_id})
        CALL apoc.path.expandConfig(entry, {
            relationshipFilter: 'RESOLVES_TO|HOSTS|COMMUNICATES_WITH|CONTAINS|DEPENDS_ON|EXPOSES|CONNECTED_TO>',
            targetNodes: [target],
            maxLevel: $max_depth,
            uniqueness: 'NODE_PATH',
            filterStartNode: true
        }) YIELD path
        WITH path, entry, target
        WHERE length(path) > 0
        RETURN 
            path,
            [node IN nodes(path) | node.id] AS node_ids,
            [rel IN relationships(path) | type(rel)] AS rel_types
        ORDER BY length(path) ASC
        LIMIT 20
        """
        
        try:
            with self.driver.session(database=self.config.database) as session:
                result = session.run(
                    query,
                    entry_points=entry_point_ids,
                    targets=target_asset_ids,
                    max_depth=max_depth
                )
                
                for record in result:
                    path_nodes = record['node_ids']
                    
                    attack_path = AttackPath(
                        name=f"Attack Path: {entry_point_ids[0][:20]}... → {target_asset_ids[0][:20]}...",
                        description=f"Attack path with {len(path_nodes)} hops",
                        entry_point_asset_id=entry_point_ids[0],
                        target_asset_id=target_asset_ids[0],
                        path_nodes=path_nodes,
                        path_length=len(path_nodes),
                        lateral_movement_hops=max(0, len(path_nodes) - 2)
                    )
                    
                    attack_path.calculate_scores()
                    attack_paths.append(attack_path)
                    
        except Exception as e:
            logger.warning(f"APOC not available or error finding paths: {e}")
            # Fallback to simple BFS without APOC
            attack_paths = self._find_paths_bfs(entry_point_ids, target_asset_ids, max_depth)
        
        return attack_paths
    
    def _find_paths_bfs(self, entry_points: List[str], targets: List[str], 
                        max_depth: int = 5) -> List[AttackPath]:
        """BFS fallback for path finding without APOC"""
        paths = []
        target_set = set(targets)
        
        query = """
        MATCH (a:Asset {id: $start_id})-[:RESOLVES_TO|:HOSTS|:COMMUNICATES_WITH|:CONTAINS|:DEPENDS_ON|:EXPOSES|:CONNECTED_TO]-(b:Asset)
        RETURN b.id AS neighbor_id
        """
        
        with self.driver.session(database=self.config.database) as session:
            # BFS
            queue = [(ep, [ep]) for ep in entry_points]
            visited_global = set()
            
            while queue:
                current_id, path = queue.pop(0)
                
                if len(path) > max_depth:
                    continue
                
                if current_id in target_set:
                    attack_path = AttackPath(
                        name=f"Attack Path: {entry_points[0][:20]}... → {current_id[:20]}...",
                        entry_point_asset_id=entry_points[0],
                        target_asset_id=current_id,
                        path_nodes=path,
                        path_length=len(path),
                        lateral_movement_hops=max(0, len(path) - 2)
                    )
                    attack_path.calculate_scores()
                    paths.append(attack_path)
                    continue
                
                if current_id in visited_global:
                    continue
                visited_global.add(current_id)
                
                result = session.run(query, start_id=current_id)
                for record in result:
                    neighbor_id = record['neighbor_id']
                    if neighbor_id not in path:
                        queue.append((neighbor_id, path + [neighbor_id]))
        
        return paths[:20]
    
    def get_entry_points(self) -> List[Dict]:
        """Find all internet-facing entry points"""
        query = """
        MATCH (a:Asset)
        WHERE a.is_internet_facing = true OR a.is_public = true
        RETURN 
            a.id AS id,
            a.value AS value,
            a.asset_type AS asset_type,
            a.exposure_score AS exposure_score,
            a.open_ports_count AS open_ports_count,
            a.admin_panel_exposed AS admin_panel_exposed,
            a.criticality_score AS criticality_score
        ORDER BY a.exposure_score DESC, a.criticality_score DESC
        LIMIT 50
        """
        
        entry_points = []
        with self.driver.session(database=self.config.database) as session:
            result = session.run(query)
            for record in result:
                entry_points.append({
                    'id': record['id'],
                    'value': record['value'],
                    'asset_type': record['asset_type'],
                    'exposure_score': record['exposure_score'],
                    'open_ports_count': record['open_ports_count'],
                    'admin_panel_exposed': record['admin_panel_exposed'],
                    'criticality_score': record['criticality_score']
                })
        
        return entry_points
    
    def get_crown_jewels(self) -> List[Dict]:
        """Identify crown jewel assets"""
        query = """
        MATCH (a:Asset)
        WHERE a.is_crown_jewel = true OR a.criticality_score >= $threshold
        RETURN 
            a.id AS id,
            a.value AS value,
            a.asset_type AS asset_type,
            a.criticality_score AS criticality_score,
            a.business_unit AS business_unit,
            a.data_classification AS data_classification,
            a.vulnerability_count AS vulnerability_count
        ORDER BY a.criticality_score DESC
        LIMIT 50
        """
        
        crown_jewels = []
        with self.driver.session(database=self.config.database) as session:
            result = session.run(query, threshold=8.0)
            for record in result:
                crown_jewels.append({
                    'id': record['id'],
                    'value': record['value'],
                    'asset_type': record['asset_type'],
                    'criticality_score': record['criticality_score'],
                    'business_unit': record['business_unit'],
                    'data_classification': record['data_classification'],
                    'vulnerability_count': record['vulnerability_count']
                })
        
        return crown_jewels
    
    def get_connected_assets(self, asset_id: str, depth: int = 2) -> List[Dict]:
        """Get all assets connected to a given asset"""
        query = """
        MATCH (start:Asset {id: $asset_id})
        OPTIONAL MATCH path = (start)-[*1..$depth]-(connected:Asset)
        WITH DISTINCT connected
        RETURN 
            connected.id AS id,
            connected.value AS value,
            connected.asset_type AS asset_type,
            connected.is_internet_facing AS is_internet_facing,
            connected.exposure_score AS exposure_score
        ORDER BY connected.exposure_score DESC
        """
        
        connected = []
        with self.driver.session(database=self.config.database) as session:
            result = session.run(query, asset_id=asset_id, depth=depth)
            for record in result:
                connected.append({
                    'id': record['id'],
                    'value': record['value'],
                    'asset_type': record['asset_type'],
                    'is_internet_facing': record['is_internet_facing'],
                    'exposure_score': record['exposure_score']
                })
        
        return connected
    
    def calculate_graph_statistics(self) -> Dict:
        """Calculate graph-wide statistics"""
        stats = {}
        
        queries = {
            'total_assets': "MATCH (a:Asset) RETURN count(a) AS count",
            'internet_facing': "MATCH (a:Asset) WHERE a.is_internet_facing = true RETURN count(a) AS count",
            'crown_jewels': "MATCH (a:Asset) WHERE a.is_crown_jewel = true OR a.criticality_score >= 8.0 RETURN count(a) AS count",
            'total_relationships': "MATCH ()-[r]->() RETURN count(r) AS count",
            'avg_exposure': "MATCH (a:Asset) RETURN avg(a.exposure_score) AS avg",
            'assets_with_vulns': "MATCH (a:Asset) WHERE a.vulnerability_count > 0 RETURN count(a) AS count",
        }
        
        with self.driver.session(database=self.config.database) as session:
            for key, query in queries.items():
                try:
                    result = session.run(query)
                    record = result.single()
                    if record:
                        value = list(record.values())[0]
                        stats[key] = float(value) if value else 0
                except Exception as e:
                    stats[key] = 0
        
        return stats
    
    def add_vulnerability_to_asset(self, asset_id: str, vulnerability: Vulnerability):
        """Link a vulnerability to an asset"""
        query = """
        MATCH (a:Asset {id: $asset_id})
        MERGE (v:Vulnerability {id: $vuln_id})
        ON CREATE SET
            v.cve_id = $cve_id,
            v.title = $title,
            v.description = $description,
            v.severity = $severity,
            v.risk_score = $risk_score,
            v.cvss_score = $cvss_score,
            v.epss_score = $epss_score,
            v.exploit_maturity = $exploit_maturity,
            v.status = $status,
            v.first_detected = $first_detected,
            v.scanner_source = $scanner_source
        ON MATCH SET
            v.last_seen = $last_seen,
            v.risk_score = $risk_score
        MERGE (a)-[:HAS_VULNERABILITY]->(v)
        ON CREATE SET
            rel.discovered_at = $discovered_at
        """
        
        params = {
            'asset_id': asset_id,
            'vuln_id': vulnerability.id,
            'cve_id': vulnerability.cve.cve_id if vulnerability.cve else None,
            'title': vulnerability.title,
            'description': vulnerability.description,
            'severity': vulnerability.severity.value,
            'risk_score': vulnerability.risk_score,
            'cvss_score': vulnerability.cvss_score,
            'epss_score': vulnerability.epss_score,
            'exploit_maturity': vulnerability.exploit_maturity.value,
            'status': vulnerability.status,
            'first_detected': vulnerability.first_detected.isoformat(),
            'last_seen': vulnerability.last_seen.isoformat(),
            'scanner_source': vulnerability.scanner_source,
            'discovered_at': datetime.utcnow().isoformat()
        }
        
        with self.driver.session(database=self.config.database) as session:
            session.run(query, **params)
        
        # Update asset vulnerability counts
        self._update_asset_vuln_counts(asset_id)
    
    def _update_asset_vuln_counts(self, asset_id: str):
        """Update vulnerability counts on an asset"""
        query = """
        MATCH (a:Asset {id: $asset_id})-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WITH a, 
             count(v) AS total,
             sum(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
             sum(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) AS high,
             sum(CASE WHEN v.severity = 'medium' THEN 1 ELSE 0 END) AS medium,
             sum(CASE WHEN v.severity = 'low' THEN 1 ELSE 0 END) AS low
        SET a.vulnerability_count = total,
            a.critical_vulns = critical,
            a.high_vulns = high,
            a.medium_vulns = medium,
            a.low_vulns = low
        """
        
        with self.driver.session(database=self.config.database) as session:
            session.run(query, asset_id=asset_id)


def demo_graph_engine():
    """Demo the graph engine"""
    config = load_config()
    
    print("=" * 60)
    print("ENTERPRISE ASM - NEO4J GRAPH ENGINE DEMO")
    print("=" * 60)
    
    try:
        graph = Neo4jGraphEngine(config)
        graph.create_indexes()
        
        # Get statistics
        stats = graph.calculate_graph_statistics()
        print(f"\n📊 Graph Statistics:")
        print(f"  Total Assets: {stats.get('total_assets', 0):.0f}")
        print(f"  Internet-Facing: {stats.get('internet_facing', 0):.0f}")
        print(f"  Crown Jewels: {stats.get('crown_jewels', 0):.0f}")
        print(f"  Relationships: {stats.get('total_relationships', 0):.0f}")
        print(f"  Avg Exposure Score: {stats.get('avg_exposure', 0):.2f}")
        
        # Get entry points
        entry_points = graph.get_entry_points()
        print(f"\n🚪 Entry Points ({len(entry_points)} found):")
        for ep in entry_points[:5]:
            print(f"  • {ep['value']} (Exposure: {ep['exposure_score']:.1f})")
        
        # Get crown jewels
        crown_jewels = graph.get_crown_jewels()
        print(f"\n💎 Crown Jewels ({len(crown_jewels)} found):")
        for cj in crown_jewels[:5]:
            print(f"  • {cj['value']} (Criticality: {cj['criticality_score']:.1f})")
        
        # Find attack paths
        if entry_points and crown_jewels:
            print(f"\n🔍 Analyzing Attack Paths...")
            paths = graph.find_attack_paths(
                [entry_points[0]['id']],
                [crown_jewels[0]['id']],
                max_depth=5
            )
            print(f"  Found {len(paths)} potential attack paths")
            for path in paths[:3]:
                print(f"    → Path length: {path.path_length}, Risk: {path.total_risk_score:.2f}")
        
        graph.close()
        print("\n✓ Graph engine demo complete!")
        
    except Exception as e:
        print(f"\n⚠️  Neo4j not available: {e}")
        print("  Install Neo4j: docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest")


if __name__ == "__main__":
    demo_graph_engine()
