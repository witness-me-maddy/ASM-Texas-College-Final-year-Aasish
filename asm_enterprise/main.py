"""
Enterprise ASM System - Main Entry Point
Orchestrates all engines and provides unified API
"""
import asyncio
import signal
from datetime import datetime
from typing import List, Dict, Optional, Any
import logging
import json

from config.settings import SystemConfig, DEFAULT_CONFIG, DataSourceConfig, DataSourceType
from core.models import Asset, Vulnerability, ScanJob, AttackPath
from engines.intelligence import AssetIntelligenceEngine, create_intelligence_source
from engines.graph_engine import AssetGraphEngine
from engines.vulnerability_intel import VulnerabilityIntelligenceEngine


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EnterpriseASM:
    """
    Enterprise Attack Surface Management System
    Main orchestrator for all ASM components
    """
    
    def __init__(self, config: SystemConfig = None):
        self.config = config or DEFAULT_CONFIG
        
        # Initialize engines
        self.intelligence_engine: Optional[AssetIntelligenceEngine] = None
        self.graph_engine: Optional[AssetGraphEngine] = None
        self.vuln_intel_engine: Optional[VulnerabilityIntelligenceEngine] = None
        
        # State
        self._running = False
        self._shutdown_event = asyncio.Event()
        
        # Statistics
        self.stats = {
            'assets_discovered': 0,
            'vulnerabilities_found': 0,
            'scans_completed': 0,
            'attack_paths_identified': 0,
            'start_time': None,
            'last_update': None
        }
        
        # Asset and vulnerability stores
        self.assets: Dict[str, Asset] = {}
        self.vulnerabilities: List[Vulnerability] = []
        self.attack_paths: List[AttackPath] = []
    
    async def initialize(self):
        """Initialize all engines"""
        logger.info("Initializing Enterprise ASM System...")
        
        # Initialize Intelligence Engine
        self.intelligence_engine = AssetIntelligenceEngine(self.config)
        
        # Register intelligence sources
        source_configs = [
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
                api_key=None,
                rate_limit=30
            ),
        ]
        
        for source_config in source_configs:
            try:
                source = create_intelligence_source(source_config)
                self.intelligence_engine.register_source(source)
            except Exception as e:
                logger.error(f"Failed to register source {source_config.name}: {e}")
        
        # Initialize Graph Engine
        self.graph_engine = AssetGraphEngine(self.config.graph_db)
        
        # Initialize Vulnerability Intelligence Engine
        self.vuln_intel_engine = VulnerabilityIntelligenceEngine(self.config.risk_model)
        
        logger.info("All engines initialized successfully")
    
    async def start(self):
        """Start the ASM system"""
        if self._running:
            logger.warning("ASM system is already running")
            return
        
        logger.info("Starting Enterprise ASM System...")
        self._running = True
        self.stats['start_time'] = datetime.utcnow()
        
        # Start all engines
        await self.intelligence_engine.initialize()
        await self.graph_engine.connect()
        await self.vuln_intel_engine.__aenter__()
        
        logger.info("Enterprise ASM System started successfully")
    
    async def stop(self):
        """Stop the ASM system"""
        if not self._running:
            return
        
        logger.info("Stopping Enterprise ASM System...")
        self._running = False
        
        # Stop all engines
        await self.intelligence_engine.shutdown()
        await self.graph_engine.disconnect()
        await self.vuln_intel_engine.__aexit__(None, None, None)
        
        self._shutdown_event.set()
        logger.info("Enterprise ASM System stopped")
    
    async def discover_assets(
        self, 
        seed_targets: List[str],
        store_in_graph: bool = True
    ) -> List[Asset]:
        """
        Discover assets from multiple intelligence sources
        """
        logger.info(f"Starting asset discovery for targets: {seed_targets}")
        
        discovered_assets = []
        
        async for result in self.intelligence_engine.discover_assets(seed_targets):
            logger.info(
                f"Intelligence result from {result.source}: "
                f"{len(result.assets)} assets, "
                f"{len(result.relationships)} relationships"
            )
            
            if result.assets:
                discovered_assets.extend(result.assets)
                
                # Store in graph
                if store_in_graph:
                    for asset in result.assets:
                        await self.graph_engine.insert_asset(asset)
                        self.assets[asset.id] = asset
                    
                    for rel in result.relationships:
                        await self.graph_engine.insert_relationship(rel)
        
        # Merge duplicates
        merged_assets = self._deduplicate_assets(discovered_assets)
        
        self.stats['assets_discovered'] += len(merged_assets)
        self.stats['last_update'] = datetime.utcnow()
        
        logger.info(f"Discovery complete: {len(merged_assets)} unique assets found")
        
        return merged_assets
    
    async def analyze_attack_paths(
        self,
        max_hops: int = 5
    ) -> List[AttackPath]:
        """
        Analyze potential attack paths through the infrastructure
        """
        logger.info("Analyzing attack paths...")
        
        result = await self.graph_engine.find_attack_paths(max_hops=max_hops)
        
        self.attack_paths = result.paths
        self.stats['attack_paths_identified'] = result.total_paths_found
        self.stats['last_update'] = datetime.utcnow()
        
        logger.info(
            f"Attack path analysis complete: "
            f"{result.total_paths_found} paths found, "
            f"{result.critical_paths} critical"
        )
        
        return result.paths
    
    async def enrich_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Enrich vulnerabilities with threat intelligence
        """
        logger.info(f"Enriching {len(vulnerabilities)} vulnerabilities...")
        
        results = await self.vuln_intel_engine.enrich_vulnerabilities_batch(
            vulnerabilities
        )
        
        enriched_vulns = []
        for result in results:
            if result.success:
                # Find corresponding vulnerability and update
                for vuln in vulnerabilities:
                    if vuln.id == result.vulnerability_id:
                        enriched_vulns.append(vuln)
                        break
        
        self.vulnerabilities.extend(enriched_vulns)
        self.stats['vulnerabilities_found'] = len(self.vulnerabilities)
        self.stats['last_update'] = datetime.utcnow()
        
        logger.info(f"Enrichment complete: {len(enriched_vulns)} vulnerabilities enriched")
        
        return enriched_vulns
    
    def _deduplicate_assets(self, assets: List[Asset]) -> List[Asset]:
        """Deduplicate assets based on type and value"""
        seen = set()
        unique = []
        
        for asset in assets:
            key = f"{asset.asset_type.value}:{asset.value.lower()}"
            if key not in seen:
                seen.add(key)
                unique.append(asset)
            else:
                # Merge with existing
                for existing in unique:
                    if f"{existing.asset_type.value}:{existing.value.lower()}" == key:
                        existing.merge(asset)
                        break
        
        return unique
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        return {
            **self.stats,
            'assets_in_cache': len(self.assets),
            'vulnerabilities_in_store': len(self.vulnerabilities),
            'attack_paths_in_store': len(self.attack_paths),
            'vuln_intel_stats': self.vuln_intel_engine.get_statistics() if self.vuln_intel_engine else {},
            'graph_stats': {'status': 'mock_mode', 'total_assets': len(self.assets)} if self.graph_engine else {}
        }
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for dashboard visualization"""
        return {
            'summary': {
                'total_assets': len(self.assets),
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical_vulnerabilities': sum(
                    1 for v in self.vulnerabilities 
                    if v.severity.value == 'critical'
                ),
                'high_vulnerabilities': sum(
                    1 for v in self.vulnerabilities 
                    if v.severity.value == 'high'
                ),
                'attack_paths': len(self.attack_paths),
                'critical_paths': sum(
                    1 for p in self.attack_paths 
                    if p.total_risk_score > 0.85
                )
            },
            'assets_by_type': self._count_by_type(),
            'risk_distribution': self._get_risk_distribution(),
            'recent_discoveries': [
                {
                    'id': a.id,
                    'type': a.asset_type.value,
                    'value': a.value,
                    'risk_score': a.risk_score,
                    'discovered_at': a.first_discovered.isoformat()
                }
                for a in sorted(
                    self.assets.values(),
                    key=lambda x: x.first_discovered,
                    reverse=True
                )[:10]
            ],
            'top_vulnerabilities': [
                {
                    'id': v.id,
                    'cve_id': v.vulnerability_id,
                    'severity': v.severity.value,
                    'risk_score': v.risk_score,
                    'tags': list(v.tags)
                }
                for v in sorted(
                    self.vulnerabilities,
                    key=lambda x: x.risk_score,
                    reverse=True
                )[:10]
            ]
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count assets by type"""
        counts = {}
        for asset in self.assets.values():
            type_name = asset.asset_type.value
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts
    
    def _get_risk_distribution(self) -> Dict[str, int]:
        """Get risk score distribution"""
        distribution = {
            'critical': 0,  # > 0.85
            'high': 0,      # 0.65 - 0.85
            'medium': 0,    # 0.40 - 0.65
            'low': 0        # < 0.40
        }
        
        for asset in self.assets.values():
            score = asset.risk_score
            if score > 0.85:
                distribution['critical'] += 1
            elif score > 0.65:
                distribution['high'] += 1
            elif score > 0.40:
                distribution['medium'] += 1
            else:
                distribution['low'] += 1
        
        return distribution


async def main():
    """Main entry point for Enterprise ASM System"""
    
    print("=" * 70)
    print("  ENTERPRISE ATTACK SURFACE MANAGEMENT SYSTEM")
    print("  Version 1.0.0")
    print("=" * 70)
    print()
    
    # Create ASM instance
    asm = EnterpriseASM()
    
    # Setup signal handlers
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        logger.info("Shutdown signal received")
        asyncio.create_task(asm.stop())
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        # Initialize
        await asm.initialize()
        
        # Start
        await asm.start()
        
        # Run asset discovery
        print("\n🔍 Running Asset Discovery...")
        seed_domains = ["example.com", "example.org"]
        assets = await asm.discover_assets(seed_domains)
        
        print(f"\n✅ Discovered {len(assets)} assets:")
        asset_types = {}
        for asset in assets:
            type_name = asset.asset_type.value
            asset_types[type_name] = asset_types.get(type_name, 0) + 1
        
        for type_name, count in sorted(asset_types.items()):
            print(f"   - {type_name}: {count}")
        
        # Analyze attack paths
        print("\n🎯 Analyzing Attack Paths...")
        attack_paths = await asm.analyze_attack_paths(max_hops=5)
        
        print(f"\n✅ Found {len(attack_paths)} attack paths")
        for i, path in enumerate(attack_paths[:3], 1):
            print(f"   Path {i}: {path.name}")
            print(f"      - Risk Score: {path.total_risk_score:.2f}")
            print(f"      - Length: {path.path_length} hops")
            print(f"      - Crown Jewel: {'Yes' if path.crown_jewel else 'No'}")
        
        # Get statistics
        print("\n📊 System Statistics:")
        stats = asm.get_statistics()
        print(f"   - Assets Discovered: {stats['assets_discovered']}")
        print(f"   - Attack Paths: {stats['attack_paths_identified']}")
        print(f"   - Uptime: {datetime.utcnow() - stats['start_time']}")
        
        # Get dashboard data
        print("\n📈 Dashboard Summary:")
        dashboard = asm.get_dashboard_data()
        summary = dashboard['summary']
        print(f"   - Total Assets: {summary['total_assets']}")
        print(f"   - Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"   - Critical Vulnerabilities: {summary['critical_vulnerabilities']}")
        print(f"   - Critical Attack Paths: {summary['critical_paths']}")
        
        print("\n" + "=" * 70)
        print("  ASM System Demo Complete!")
        print("=" * 70)
        
        # Keep running for a bit to allow cleanup
        await asyncio.sleep(2)
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error running ASM system: {e}", exc_info=True)
    finally:
        # Cleanup
        await asm.stop()
        logger.info("Cleanup complete")


if __name__ == "__main__":
    asyncio.run(main())
