"""
ELK Stack Integration for Attack Surface Management
Handles logging, indexing, and visualization of security events
"""

from elasticsearch import Elasticsearch
from datetime import datetime
import json
import time
from typing import Dict, List, Any
from dataclasses import dataclass
import hashlib


@dataclass
class SecurityEvent:
    """Represents a security event to be indexed"""
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    target: str
    description: str
    raw_data: Dict[str, Any]
    tags: List[str]


class ELKIntegration:
    """Handles integration with ELK stack for security event indexing and analysis"""
    
    def __init__(self, es_host: str = 'http://elasticsearch:9200'):
        self.es = Elasticsearch([es_host])
        self.index_pattern = "asm-security-events-*"
        
        # Wait for Elasticsearch to be ready
        while not self.es.ping():
            print("[INFO] Waiting for Elasticsearch to be ready...")
            time.sleep(2)
        
        print("[INFO] Connected to Elasticsearch")
        
        # Create index template
        self.create_index_template()
    
    def create_index_template(self):
        """Create index template for security events"""
        template_body = {
            "index_patterns": [self.index_pattern],
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s"
            },
            "mappings": {
                "properties": {
                    "timestamp": {
                        "type": "date"
                    },
                    "event_type": {
                        "type": "keyword"
                    },
                    "severity": {
                        "type": "keyword"
                    },
                    "source": {
                        "type": "keyword"
                    },
                    "target": {
                        "type": "keyword"
                    },
                    "description": {
                        "type": "text"
                    },
                    "raw_data": {
                        "type": "object",
                        "enabled": False
                    },
                    "tags": {
                        "type": "keyword"
                    }
                }
            }
        }
        
        try:
            self.es.indices.put_template(name="asm_security_events", body=template_body)
            print("[INFO] Created index template for security events")
        except Exception as e:
            print(f"[ERROR] Failed to create index template: {str(e)}")
    
    def create_daily_index(self):
        """Create daily index for security events"""
        today = datetime.now().strftime("%Y.%m.%d")
        index_name = f"asm-security-events-{today}"
        
        if not self.es.indices.exists(index=index_name):
            self.es.indices.create(index=index_name)
            print(f"[INFO] Created index: {index_name}")
        
        return index_name
    
    def index_security_event(self, event: SecurityEvent):
        """Index a security event in Elasticsearch"""
        index_name = self.create_daily_index()
        
        doc = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "severity": event.severity,
            "source": event.source,
            "target": event.target,
            "description": event.description,
            "raw_data": event.raw_data,
            "tags": event.tags
        }
        
        try:
            result = self.es.index(index=index_name, body=doc)
            print(f"[INFO] Indexed security event: {result['_id']}")
            return result
        except Exception as e:
            print(f"[ERROR] Failed to index security event: {str(e)}")
            return None
    
    def bulk_index_events(self, events: List[SecurityEvent]):
        """Bulk index multiple security events"""
        if not events:
            return
        
        index_name = self.create_daily_index()
        actions = []
        
        for event in events:
            action = {
                "_index": index_name,
                "_source": {
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "source": event.source,
                    "target": event.target,
                    "description": event.description,
                    "raw_data": event.raw_data,
                    "tags": event.tags
                }
            }
            actions.append(action)
        
        try:
            from elasticsearch.helpers import bulk
            result = bulk(self.es, actions)
            print(f"[INFO] Bulk indexed {result[0]} events")
            return result
        except Exception as e:
            print(f"[ERROR] Failed to bulk index events: {str(e)}")
            return None
    
    def search_events(self, query: Dict, size: int = 100) -> List[Dict]:
        """Search for security events"""
        try:
            result = self.es.search(
                index=self.index_pattern,
                body={
                    "query": query,
                    "size": size,
                    "sort": [{"timestamp": {"order": "desc"}}]
                }
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            print(f"[ERROR] Search failed: {str(e)}")
            return []
    
    def get_event_stats(self) -> Dict:
        """Get statistics about security events"""
        try:
            # Overall count
            total_count = self.es.count(index=self.index_pattern)["count"]
            
            # Aggregations by severity
            agg_query = {
                "aggs": {
                    "by_severity": {
                        "terms": {"field": "severity"}
                    },
                    "by_event_type": {
                        "terms": {"field": "event_type"}
                    },
                    "by_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "hour"
                        }
                    }
                }
            }
            
            result = self.es.search(index=self.index_pattern, body=agg_query)
            
            stats = {
                "total_events": total_count,
                "by_severity": {bucket["key"]: bucket["doc_count"] 
                               for bucket in result["aggregations"]["by_severity"]["buckets"]},
                "by_event_type": {bucket["key"]: bucket["doc_count"] 
                                 for bucket in result["aggregations"]["by_event_type"]["buckets"]},
                "by_time": [(bucket["key_as_string"], bucket["doc_count"]) 
                           for bucket in result["aggregations"]["by_time"]["buckets"]]
            }
            
            return stats
        except Exception as e:
            print(f"[ERROR] Failed to get event stats: {str(e)}")
            return {}
    
    def index_scan_results(self, scan_results: List[Dict]):
        """Convert and index scan results as security events"""
        events = []
        
        for result in scan_results:
            timestamp = datetime.fromisoformat(result['timestamp'])
            
            # Determine event type based on scan type
            if result['scan_type'] == 'network_discovery':
                for finding in result['findings']:
                    event = SecurityEvent(
                        timestamp=timestamp,
                        event_type="host_discovery",
                        severity="info",
                        source=result['target'],
                        target=finding.get('ip', 'unknown'),
                        description=f"Discovered host: {finding.get('hostname', 'N/A')}",
                        raw_data=finding,
                        tags=["discovery", "network"]
                    )
                    events.append(event)
            
            elif result['scan_type'] == 'vulnerability_scan':
                for finding in result['findings']:
                    severity_map = {
                        'critical': 'high',
                        'high': 'high',
                        'medium': 'medium',
                        'low': 'low'
                    }
                    
                    event = SecurityEvent(
                        timestamp=timestamp,
                        event_type="vulnerability_found",
                        severity=severity_map.get(finding.get('severity', 'medium'), 'medium'),
                        source=result['target'],
                        target=finding.get('container_id', finding.get('host', 'unknown')),
                        description=f"Vulnerability: {finding.get('vulnerability', finding.get('title', 'N/A'))}",
                        raw_data=finding,
                        tags=["vulnerability", "security"]
                    )
                    events.append(event)
            
            elif result['scan_type'] == 'web_application':
                for finding in result['findings']:
                    # Map ZAP risk to our severity
                    risk_to_severity = {
                        'High': 'high',
                        'Medium': 'medium',
                        'Low': 'low',
                        'Informational': 'info'
                    }
                    
                    event = SecurityEvent(
                        timestamp=timestamp,
                        event_type="web_vulnerability",
                        severity=risk_to_severity.get(finding.get('risk', 'Medium'), 'medium'),
                        source=result['target'],
                        target=finding.get('url', 'unknown'),
                        description=f"Web vulnerability: {finding.get('alert', 'N/A')}",
                        raw_data=finding,
                        tags=["web", "vulnerability", "application"]
                    )
                    events.append(event)
        
        # Index all events
        self.bulk_index_events(events)
        print(f"[INFO] Indexed {len(events)} events from scan results")


class KibanaVisualizer:
    """Handles creating and managing Kibana visualizations"""
    
    def __init__(self, kibana_host: str = 'http://kibana:5601'):
        self.kibana_host = kibana_host
        self.es = Elasticsearch(['http://elasticsearch:9200'])
    
    def create_dashboard(self):
        """Create a Kibana dashboard for ASM metrics"""
        # Create index pattern first
        self.create_index_pattern()
        
        # Create various visualizations
        self.create_vulnerability_trend_visualization()
        self.create_severity_distribution_visualization()
        self.create_asset_exposure_visualization()
        
        # Create dashboard
        self.create_asm_dashboard()
    
    def create_index_pattern(self):
        """Create Kibana index pattern"""
        try:
            import requests
            
            headers = {
                'Content-Type': 'application/json',
                'kbn-xsrf': 'true'
            }
            
            payload = {
                "attributes": {
                    "title": "asm-security-events-*",
                    "timeFieldName": "timestamp"
                }
            }
            
            response = requests.post(
                f"{self.kibana_host}/api/index_patterns",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                print("[INFO] Created Kibana index pattern")
            else:
                print(f"[WARNING] Failed to create index pattern: {response.text}")
                
        except Exception as e:
            print(f"[ERROR] Failed to create index pattern: {str(e)}")
    
    def create_vulnerability_trend_visualization(self):
        """Create vulnerability trend visualization"""
        try:
            import requests
            
            headers = {
                'Content-Type': 'application/json',
                'kbn-xsrf': 'true'
            }
            
            payload = {
                "attributes": {
                    "title": "ASM - Vulnerability Trend",
                    "visState": json.dumps({
                        "title": "Vulnerability Trend",
                        "type": "line",
                        "params": {
                            "type": "line",
                            "grid": {
                                "categoryLines": False,
                                "style": {"color": "#eee"}
                            },
                            "categoryAxes": [{
                                "id": "CategoryAxis-1",
                                "type": "category",
                                "position": "bottom",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear"},
                                "labels": {"show": True, "truncate": 100}
                            }],
                            "valueAxes": [{
                                "id": "ValueAxis-1",
                                "name": "LeftAxis-1",
                                "type": "value",
                                "position": "left",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear", "mode": "normal"},
                                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}
                            }],
                            "seriesParams": [{
                                "show": "true",
                                "type": "line",
                                "mode": "normal",
                                "data": {"label": "Count of event_type", "id": "1"},
                                "valueAxis": "ValueAxis-1",
                                "drawLinesBetweenPoints": True,
                                "showCircles": True
                            }],
                            "addTooltip": True,
                            "addLegend": True,
                            "legendPosition": "right",
                            "times": [],
                            "addTimeMarker": False
                        },
                        "aggs": [
                            {
                                "id": "1",
                                "enabled": True,
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2",
                                "enabled": True,
                                "type": "date_histogram",
                                "schema": "segment",
                                "params": {
                                    "field": "timestamp",
                                    "timeRange": {"from": "now-7d", "to": "now"},
                                    "useNormalizedEsInterval": True,
                                    "interval": "d",
                                    "timeZone": "UTC",
                                    "customInterval": "2h",
                                    "minDocCount": 1,
                                    "extended_bounds": {}
                                }
                            }
                        ],
                        "listeners": {}
                    }),
                    "uiStateJSON": "{}",
                    "description": "Vulnerability trend over time",
                    "version": 1,
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "asm-security-events-*",
                            "filter": [],
                            "query": {
                                "language": "kuery",
                                "query": "event_type: vulnerability_found"
                            }
                        })
                    }
                }
            }
            
            response = requests.post(
                f"{self.kibana_host}/api/saved_objects/visualization",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                print("[INFO] Created vulnerability trend visualization")
            else:
                print(f"[WARNING] Failed to create visualization: {response.text}")
                
        except Exception as e:
            print(f"[ERROR] Failed to create vulnerability trend visualization: {str(e)}")
    
    def create_severity_distribution_visualization(self):
        """Create severity distribution visualization"""
        try:
            import requests
            
            headers = {
                'Content-Type': 'application/json',
                'kbn-xsrf': 'true'
            }
            
            payload = {
                "attributes": {
                    "title": "ASM - Severity Distribution",
                    "visState": json.dumps({
                        "title": "Severity Distribution",
                        "type": "pie",
                        "params": {
                            "type": "pie",
                            "addTooltip": True,
                            "addLegend": True,
                            "legendPosition": "right",
                            "isDonut": True,
                            "labels": {
                                "show": False,
                                "values": True,
                                "last_level": True,
                                "truncate": 100
                            }
                        },
                        "aggs": [
                            {
                                "id": "1",
                                "enabled": True,
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2",
                                "enabled": True,
                                "type": "terms",
                                "schema": "segment",
                                "params": {
                                    "field": "severity",
                                    "size": 5,
                                    "order": "desc",
                                    "orderBy": "1"
                                }
                            }
                        ],
                        "listeners": {}
                    }),
                    "uiStateJSON": "{}",
                    "description": "Distribution of event severities",
                    "version": 1,
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "asm-security-events-*",
                            "filter": [],
                            "query": {"language": "kuery", "query": ""}
                        })
                    }
                }
            }
            
            response = requests.post(
                f"{self.kibana_host}/api/saved_objects/visualization",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                print("[INFO] Created severity distribution visualization")
            else:
                print(f"[WARNING] Failed to create visualization: {response.text}")
                
        except Exception as e:
            print(f"[ERROR] Failed to create severity distribution visualization: {str(e)}")
    
    def create_asset_exposure_visualization(self):
        """Create asset exposure visualization"""
        try:
            import requests
            
            headers = {
                'Content-Type': 'application/json',
                'kbn-xsrf': 'true'
            }
            
            payload = {
                "attributes": {
                    "title": "ASM - Asset Exposure Levels",
                    "visState": json.dumps({
                        "title": "Asset Exposure Levels",
                        "type": "area",
                        "params": {
                            "type": "area",
                            "grid": {
                                "categoryLines": False,
                                "style": {"color": "#eee"}
                            },
                            "categoryAxes": [{
                                "id": "CategoryAxis-1",
                                "type": "category",
                                "position": "bottom",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear"},
                                "labels": {"show": True, "truncate": 100}
                            }],
                            "valueAxes": [{
                                "id": "ValueAxis-1",
                                "name": "LeftAxis-1",
                                "type": "value",
                                "position": "left",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear", "mode": "normal"},
                                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}
                            }],
                            "seriesParams": [{
                                "show": "true",
                                "type": "area",
                                "mode": "stacked",
                                "data": {"label": "Count of source", "id": "1"},
                                "valueAxis": "ValueAxis-1",
                                "drawLinesBetweenPoints": True,
                                "showCircles": True
                            }],
                            "addTooltip": True,
                            "addLegend": True,
                            "legendPosition": "right",
                            "times": [],
                            "addTimeMarker": False
                        },
                        "aggs": [
                            {
                                "id": "1",
                                "enabled": True,
                                "type": "count",
                                "schema": "metric",
                                "params": {}
                            },
                            {
                                "id": "2",
                                "enabled": True,
                                "type": "terms",
                                "schema": "segment",
                                "params": {
                                    "field": "source",
                                    "size": 10,
                                    "order": "desc",
                                    "orderBy": "1"
                                }
                            }
                        ],
                        "listeners": {}
                    }),
                    "uiStateJSON": "{}",
                    "description": "Asset exposure levels over time",
                    "version": 1,
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": "asm-security-events-*",
                            "filter": [],
                            "query": {"language": "kuery", "query": ""}
                        })
                    }
                }
            }
            
            response = requests.post(
                f"{self.kibana_host}/api/saved_objects/visualization",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                print("[INFO] Created asset exposure visualization")
            else:
                print(f"[WARNING] Failed to create visualization: {response.text}")
                
        except Exception as e:
            print(f"[ERROR] Failed to create asset exposure visualization: {str(e)}")
    
    def create_asm_dashboard(self):
        """Create main ASM dashboard"""
        try:
            import requests
            
            headers = {
                'Content-Type': 'application/json',
                'kbn-xsrf': 'true'
            }
            
            # This would normally include references to the saved visualizations
            # For simplicity, we'll just create the dashboard shell
            payload = {
                "attributes": {
                    "title": "ASM - Enterprise Attack Surface Dashboard",
                    "hits": 0,
                    "description": "Comprehensive attack surface management dashboard",
                    "panelsJSON": "[]",
                    "optionsJSON": json.dumps({
                        "darkTheme": False,
                        "useMargins": True,
                        "hidePanelTitles": False
                    }),
                    "version": 1,
                    "timeRestore": False,
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "query": {"language": "kuery", "query": ""},
                            "filter": []
                        })
                    }
                }
            }
            
            response = requests.post(
                f"{self.kibana_host}/api/saved_objects/dashboard",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                print("[INFO] Created ASM dashboard")
            else:
                print(f"[WARNING] Failed to create dashboard: {response.text}")
                
        except Exception as e:
            print(f"[ERROR] Failed to create ASM dashboard: {str(e)}")


def example_usage():
    """Example of how to use the ELK integration"""
    elk = ELKIntegration()
    kibana_vis = KibanaVisualizer()
    
    # Create sample security events
    sample_events = [
        SecurityEvent(
            timestamp=datetime.now(),
            event_type="vulnerability_found",
            severity="high",
            source="10.0.0.1",
            target="10.0.0.10",
            description="Critical vulnerability found in SSH service",
            raw_data={"service": "ssh", "port": 22, "cve": "CVE-2023-1234"},
            tags=["ssh", "critical", "network"]
        ),
        SecurityEvent(
            timestamp=datetime.now(),
            event_type="host_discovery",
            severity="info",
            source="nmap_scanner",
            target="10.0.0.20",
            description="New host discovered on network",
            raw_data={"hostname": "webserver01", "os": "Linux"},
            tags=["discovery", "linux", "web"]
        )
    ]
    
    # Index the events
    elk.bulk_index_events(sample_events)
    
    # Get statistics
    stats = elk.get_event_stats()
    print("[STATS]", json.dumps(stats, indent=2))
    
    # Create Kibana dashboard
    kibana_vis.create_dashboard()


if __name__ == "__main__":
    example_usage()