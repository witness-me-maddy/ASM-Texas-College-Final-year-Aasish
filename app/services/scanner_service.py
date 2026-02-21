from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

from app.connectors.tool_connectors import ToolIngestionAdapter
from app.models import Asset, Exposure, ScanReport, ScanRequest, ScanStatus, ToolFinding
from app.services.epss_service import EPSSService
from app.services.repository import InMemoryRepository


class ASMScannerService:
    """Enterprise-style URL-driven scan orchestrator (EPSS-first)."""

    def __init__(
        self,
        repository: InMemoryRepository,
        adapter: ToolIngestionAdapter,
        epss_service: EPSSService,
    ) -> None:
        self.repository = repository
        self.adapter = adapter
        self.epss_service = epss_service

    def scan_website(self, payload: ScanRequest) -> tuple[Asset, ScanReport]:
        started = datetime.now(timezone.utc)
        parsed = urlparse(str(payload.website_url))
        host = parsed.hostname or str(payload.website_url)

        findings = self._simulate_tool_findings(host)
        exposures = self.adapter.normalize(findings)

        asset = self.repository.upsert_asset(
            name=host,
            owner="Automated ASM Scanner",
            business_unit="Security Operations",
        )
        asset.type = asset.type.web_app
        created = self.repository.add_exposures(asset.id, exposures)

        max_epss = max((e.epss_score for e in exposures), default=0.0)
        max_percentile = max((e.epss_percentile for e in exposures), default=0.0)
        top_exposures = sorted(exposures, key=lambda e: e.epss_score, reverse=True)[:5]

        report = ScanReport(
            id=f"scan-{uuid4()}",
            website_url=payload.website_url,
            target_host=host,
            status=ScanStatus.completed,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            tools_executed=sorted(list({f.tool_name for f in findings})),
            assets_discovered=1,
            exposures_discovered=created,
            max_epss_score=round(max_epss, 4),
            max_epss_percentile=round(max_percentile, 4),
            top_exposures=top_exposures,
        )
        self.repository.add_report(report)
        return asset, report

    def _simulate_tool_findings(self, host: str) -> list[ToolFinding]:
        tool_cves = [
            ("Nmap", "OpenSSH outdated service fingerprint", "CVE-2024-6387", "high"),
            ("Nuclei", "Exposed admin/debug endpoint", "CVE-2023-20198", "critical"),
            ("OWASP ZAP", "Potential XSS vector in response reflection", "CVE-2023-38545", "medium"),
            ("SSLyze", "TLS misconfiguration with weak negotiation", "CVE-2023-3446", "high"),
            ("WhatWeb", "Framework version disclosure", "CVE-2021-41773", "medium"),
        ]

        seed = int(hashlib.sha256(host.encode("utf-8")).hexdigest()[:8], 16)
        offset = seed % len(tool_cves)
        selected = [tool_cves[(offset + i) % len(tool_cves)] for i in range(4)]

        findings: list[ToolFinding] = []
        for idx, (tool, title, cve, sev) in enumerate(selected, start=1):
            findings.append(
                ToolFinding(
                    tool_name=tool,
                    target=host,
                    finding_id=f"{tool.lower().replace(' ', '-')}-{idx}",
                    title=title,
                    severity_hint=sev,
                    cve=cve,
                )
            )
        return findings
