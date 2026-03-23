"""
SOAR Integration Layer
Jira, ServiceNow ticket creation and automation
"""
import asyncio
import aiohttp
import json
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import logging

from config.settings import ASMConfig, load_config
from core.models import Vulnerability, Ticket, Severity, Alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class JiraIntegration:
    """Jira integration for auto-ticket creation"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.jira
        self.base_url = self.config.url.rstrip('/')
        self.auth = aiohttp.BasicAuth(self.config.email, self.config.api_token)
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(auth=self.auth)
        return self.session
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def create_ticket(self, vulnerability: Vulnerability, 
                           asset_info: Dict = None) -> Optional[Ticket]:
        """Create a Jira ticket for a vulnerability"""
        
        if not self.base_url or not self.config.email or not self.config.api_token:
            logger.warning("Jira credentials not configured")
            return None
        
        session = await self._get_session()
        
        # Map severity to Jira priority
        priority_map = {
            Severity.CRITICAL: 'Highest',
            Severity.HIGH: 'High',
            Severity.MEDIUM: 'Medium',
            Severity.LOW: 'Low',
            Severity.INFO: 'Lowest'
        }
        
        # Calculate SLA based on severity
        sla_days = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 3,
            Severity.MEDIUM: 7,
            Severity.LOW: 14,
            Severity.INFO: 30
        }
        
        due_date = datetime.utcnow() + timedelta(days=sla_days.get(vulnerability.severity, 30))
        
        # Build Jira issue payload
        issue_data = {
            "fields": {
                "project": {"key": self.config.project_key},
                "summary": f"[{vulnerability.severity.value.upper()}] {vulnerability.title}",
                "description": self._build_description(vulnerability, asset_info),
                "issuetype": {"name": self.config.issue_type},
                "priority": {"name": priority_map.get(vulnerability.severity, 'Medium')},
                "labels": [
                    "security",
                    "vulnerability",
                    f"severity-{vulnerability.severity.value}",
                    vulnerability.scanner_source
                ] + vulnerability.tags
            }
        }
        
        # Add custom fields if available (e.g., CVE, CVSS)
        if vulnerability.cve:
            issue_data["fields"]["labels"].append(f"cve-{vulnerability.cve.cve_id}")
        
        try:
            url = f"{self.base_url}/rest/api/3/issue"
            headers = {"Content-Type": "application/json"}
            
            async with session.post(url, json=issue_data, headers=headers) as resp:
                if resp.status == 201:
                    result = await resp.json()
                    ticket_id = result.get('key', '')
                    ticket_url = f"{self.base_url}/browse/{ticket_id}"
                    
                    logger.info(f"Created Jira ticket: {ticket_id}")
                    
                    return Ticket(
                        ticket_system='jira',
                        ticket_id=ticket_id,
                        ticket_url=ticket_url,
                        vulnerability_id=vulnerability.id,
                        asset_id=vulnerability.asset_id,
                        title=issue_data["fields"]["summary"],
                        description=issue_data["fields"]["description"],
                        severity=vulnerability.severity,
                        status='open',
                        sla_due_date=due_date,
                        raw_ticket_data=result
                    )
                else:
                    error_text = await resp.text()
                    logger.error(f"Failed to create Jira ticket: {resp.status} - {error_text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Jira integration error: {e}")
            return None
    
    def _build_description(self, vuln: Vulnerability, asset_info: Dict = None) -> str:
        """Build formatted Jira description"""
        desc = f"""
h2. Vulnerability Details

*Title:* {vuln.title}
*Severity:* {vuln.severity.value.upper()}
*Risk Score:* {vuln.risk_score}/10
*CVSS Score:* {vuln.cvss_score}
*EPSS Score:* {vuln.epss_score}
*Status:* {vuln.status}

h3. Description

{vuln.description}

"""
        
        if vuln.cve:
            desc += f"""
h3. CVE Information

*CVE ID:* {vuln.cve.cve_id}
*Published:* {vuln.cve.published_date.strftime('%Y-%m-%d') if vuln.cve.published_date else 'N/A'}
*Exploit Available:* {'Yes' if vuln.cve.exploit_available else 'No'}
*In CISA KEV:* {'Yes' if vuln.cve.is_in_kev else 'No'}

"""
        
        if asset_info:
            desc += f"""
h3. Affected Asset

*Asset:* {asset_info.get('value', 'N/A')}
*Type:* {asset_info.get('asset_type', 'N/A')}
*IP Address:* {', '.join(asset_info.get('ip_addresses', []))}
*Owner:* {asset_info.get('owner', 'Unassigned')}
*Business Unit:* {asset_info.get('business_unit', 'Unknown')}

"""
        
        if vuln.remediation:
            desc += f"""
h3. Remediation

{vuln.remediation}

"""
        
        if vuln.references:
            desc += """
h3. References

"""
            for ref in vuln.references[:5]:  # Limit to 5 references
                desc += f"* {ref}\n"
        
        desc += f"""
---
*Generated by Enterprise ASM System*
*Detected:* {vuln.first_detected.strftime('%Y-%m-%d %H:%M:%S')}
*Scanner:* {vuln.scanner_source}
"""
        
        return desc
    
    async def update_ticket(self, ticket: Ticket, status: str = None, 
                           comment: str = None) -> bool:
        """Update an existing Jira ticket"""
        
        if not ticket.ticket_id:
            return False
        
        session = await self._get_session()
        updates = {"fields": {}, "update": {}}
        
        if status:
            # Transition ticket
            transition_map = {
                'open': '1',
                'in_progress': '2',
                'resolved': '3',
                'closed': '4'
            }
            transitions_url = f"{self.base_url}/rest/api/3/issue/{ticket.ticket_id}/transitions"
            
            try:
                async with session.post(
                    transitions_url,
                    json={"transition": {"id": transition_map.get(status, '1')}}
                ) as resp:
                    if resp.status != 204:
                        logger.warning(f"Failed to transition ticket: {resp.status}")
            except Exception as e:
                logger.error(f"Ticket transition error: {e}")
        
        if comment:
            updates["update"]["comment"] = [{"add": {"body": comment}}]
        
        if updates["fields"] or updates["update"]:
            try:
                url = f"{self.base_url}/rest/api/3/issue/{ticket.ticket_id}"
                async with session.put(url, json=updates) as resp:
                    return resp.status == 204
            except Exception as e:
                logger.error(f"Ticket update error: {e}")
        
        return True


class ServiceNowIntegration:
    """ServiceNow integration for incident creation"""
    
    def __init__(self, config: ASMConfig):
        self.config = config.servicenow
        self.instance = self.config.instance
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            auth = aiohttp.BasicAuth(self.config.username, self.config.password)
            self.session = aiohttp.ClientSession(auth=auth)
        return self.session
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def create_incident(self, vulnerability: Vulnerability,
                             asset_info: Dict = None) -> Optional[Ticket]:
        """Create a ServiceNow incident"""
        
        if not self.instance:
            logger.warning("ServiceNow instance not configured")
            return None
        
        session = await self._get_session()
        
        # Map severity to ServiceNow urgency/impact
        urgency_map = {
            Severity.CRITICAL: '1',
            Severity.HIGH: '2',
            Severity.MEDIUM: '3',
            Severity.LOW: '4',
            Severity.INFO: '5'
        }
        
        incident_data = {
            "short_description": f"[SECURITY] {vulnerability.title}",
            "description": self._build_description(vulnerability, asset_info),
            "urgency": urgency_map.get(vulnerability.severity, '3'),
            "impact": urgency_map.get(vulnerability.severity, '3'),
            "category": "Security",
            "subcategory": "Vulnerability Management",
            "cmdb_ci": asset_info.get('value', '') if asset_info else '',
            "caller_id": "security-automation"
        }
        
        try:
            url = f"https://{self.instance}.service-now.com/api/now/table/{self.config.table}"
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            
            async with session.post(url, json=incident_data, headers=headers) as resp:
                if resp.status == 201:
                    result = await resp.json()
                    sys_id = result.get('result', {}).get('sys_id', '')
                    number = result.get('result', {}).get('number', '')
                    
                    ticket_url = f"https://{self.instance}.service-now.com/nav_to.do?uri={self.config.table}.do?sys_id={sys_id}"
                    
                    logger.info(f"Created ServiceNow incident: {number}")
                    
                    return Ticket(
                        ticket_system='servicenow',
                        ticket_id=number,
                        ticket_url=ticket_url,
                        vulnerability_id=vulnerability.id,
                        asset_id=vulnerability.asset_id,
                        title=incident_data["short_description"],
                        description=incident_data["description"],
                        severity=vulnerability.severity,
                        status='open',
                        raw_ticket_data=result
                    )
                else:
                    error_text = await resp.text()
                    logger.error(f"Failed to create ServiceNow incident: {resp.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"ServiceNow integration error: {e}")
            return None
    
    def _build_description(self, vuln: Vulnerability, asset_info: Dict = None) -> str:
        """Build ServiceNow description"""
        desc = f"""
VULNERABILITY DETAILS
=====================

Title: {vuln.title}
Severity: {vuln.severity.value.upper()}
Risk Score: {vuln.risk_score}/10
CVSS: {vuln.cvss_score}
EPSS: {vuln.epss_score}

Description:
{vuln.description}

"""
        
        if vuln.cve:
            desc += f"CVE: {vuln.cve.cve_id}\n"
        
        if asset_info:
            desc += f"\nAffected Asset: {asset_info.get('value', 'N/A')}\n"
        
        if vuln.remediation:
            desc += f"\nRemediation: {vuln.remediation}\n"
        
        return desc


class SOAREngine:
    """Security Orchestration, Automation and Response Engine"""
    
    def __init__(self, config: ASMConfig):
        self.config = config
        self.jira = JiraIntegration(config) if config.jira.url else None
        self.servicenow = ServiceNowIntegration(config) if config.servicenow.instance else None
        self.auto_create_tickets = os.getenv("AUTO_CREATE_TICKETS", "false").lower() == "true"
        self.auto_remediate = os.getenv("AUTO_REMEDIATE", "false").lower() == "true"
    
    async def process_vulnerability(self, vulnerability: Vulnerability,
                                   asset_info: Dict = None) -> List[Ticket]:
        """Process a vulnerability through SOAR workflows"""
        tickets = []
        
        # Auto-create tickets for medium+ severity
        if self.auto_create_tickets and vulnerability.severity in [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM
        ]:
            # Create in Jira
            if self.jira:
                ticket = await self.jira.create_ticket(vulnerability, asset_info)
                if ticket:
                    tickets.append(ticket)
            
            # Create in ServiceNow (alternative or backup)
            if self.servicenow and not tickets:
                ticket = await self.servicenow.create_incident(vulnerability, asset_info)
                if ticket:
                    tickets.append(ticket)
        
        # Auto-remediation for specific cases
        if self.auto_remediate:
            await self._attempt_auto_remediation(vulnerability, asset_info)
        
        # Send alerts for critical findings
        if vulnerability.severity == Severity.CRITICAL:
            await self._send_critical_alert(vulnerability, asset_info)
        
        return tickets
    
    async def _attempt_auto_remediation(self, vuln: Vulnerability, 
                                        asset_info: Dict = None):
        """Attempt automatic remediation for supported cases"""
        
        # Example: Auto-tag AWS resources
        if vuln.vulnerability_type == 'misconfiguration':
            if 'public' in vuln.title.lower() and asset_info:
                logger.info(f"Auto-remediation triggered for: {vuln.title}")
                # In production, this would call AWS APIs to fix the issue
                # For now, just log the action
                logger.info(f"Would remediate asset: {asset_info.get('value', 'unknown')}")
    
    async def _send_critical_alert(self, vuln: Vulnerability, 
                                   asset_info: Dict = None):
        """Send critical alert via configured channels"""
        
        alert = Alert(
            alert_type='critical_vulnerability',
            title=f"CRITICAL: {vuln.title}",
            description=vuln.description,
            severity=Severity.CRITICAL,
            vulnerability_ids=[vuln.id],
            metadata={'asset_info': asset_info}
        )
        
        # Send to configured notification channels
        # (Slack, PagerDuty, Email, etc.)
        logger.warning(f"CRITICAL ALERT: {alert.title}")
        logger.warning(f"Asset: {asset_info.get('value', 'unknown') if asset_info else 'unknown'}")
    
    async def bulk_create_tickets(self, vulnerabilities: List[Vulnerability],
                                 assets_db: Dict[str, Dict]) -> List[Ticket]:
        """Bulk create tickets for multiple vulnerabilities"""
        tickets = []
        
        # Group by severity for prioritized processing
        by_severity = {}
        for vuln in vulnerabilities:
            sev = vuln.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(vuln)
        
        # Process critical first, then high, etc.
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulns = by_severity.get(severity, [])
            for vuln in vulns:
                asset_info = assets_db.get(vuln.asset_id, {})
                ticket_results = await self.process_vulnerability(vuln, asset_info)
                tickets.extend(ticket_results)
                
                # Rate limiting
                await asyncio.sleep(0.5)
        
        return tickets
    
    async def close(self):
        """Cleanup connections"""
        if self.jira:
            await self.jira.close()
        if self.servicenow:
            await self.servicenow.close()


import os

async def demo_soar():
    """Demo SOAR integrations"""
    config = load_config()
    
    print("=" * 60)
    print("ENTERPRISE ASM - SOAR INTEGRATION DEMO")
    print("=" * 60)
    
    soar = SOAREngine(config)
    
    # Demo ticket creation
    print("\n🎫 Testing Ticket Creation:")
    
    if config.jira.url:
        print(f"  ✓ Jira configured: {config.jira.url}")
    else:
        print("  ⚠️  Jira not configured (set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN)")
    
    if config.servicenow.instance:
        print(f"  ✓ ServiceNow configured: {config.servicenow.instance}")
    else:
        print("  ⚠️  ServiceNow not configured (set SNOW_INSTANCE)")
    
    # Create sample vulnerability
    sample_vuln = Vulnerability(
        id="demo-vuln-001",
        vulnerability_type='web',
        title='SQL Injection in Login Form',
        description='Classic SQL injection vulnerability detected in login endpoint',
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        epss_score=0.95,
        asset_id='demo-asset-001',
        scanner_source='nuclei'
    )
    
    asset_info = {
        'value': 'app.example.com',
        'asset_type': 'web_application',
        'ip_addresses': ['203.0.113.10'],
        'owner': 'security-team',
        'business_unit': 'engineering'
    }
    
    print(f"\n📋 Sample Vulnerability:")
    print(f"  Title: {sample_vuln.title}")
    print(f"  Severity: {sample_vuln.severity.value}")
    print(f"  CVSS: {sample_vuln.cvss_score}")
    
    if soar.jira or soar.servicenow:
        print("\n🔄 Processing through SOAR...")
        tickets = await soar.process_vulnerability(sample_vuln, asset_info)
        if tickets:
            for ticket in tickets:
                print(f"  ✓ Created {ticket.ticket_system} ticket: {ticket.ticket_id}")
                print(f"    URL: {ticket.ticket_url}")
        else:
            print("  ℹ️  No tickets created (auto-creation disabled or API error)")
    else:
        print("\n⚠️  No ticketing systems configured")
    
    await soar.close()
    print("\n✓ SOAR demo complete!")


if __name__ == "__main__":
    asyncio.run(demo_soar())
