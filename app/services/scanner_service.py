from __future__ import annotations

import hashlib
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

from app.connectors.tool_connectors import ToolIngestionAdapter
from app.models import (
    Asset,
    AutomationStatus,
    GeoPosition,
    MonitoredTarget,
    MonitorRequest,
    OpenPort,
    ScanReport,
    ScanRequest,
    ScanStatus,
    ToolFinding,
)
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
        self._automation_running = False
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()

    def scan_website(self, payload: ScanRequest) -> tuple[Asset, ScanReport]:
        started = datetime.now(timezone.utc)
        parsed = urlparse(str(payload.website_url))
        host = parsed.hostname or str(payload.website_url)

        findings = self._simulate_tool_findings(host)
        exposures = self.adapter.normalize(findings)
        position = self._simulate_position(host)
        open_ports = self._simulate_open_ports(host)

        asset = self.repository.upsert_asset(
            name=host,
            owner="Automated ASM Scanner",
            business_unit="Security Operations",
        )
        asset.type = asset.type.web_app
        asset.position = position
        asset.open_ports = open_ports
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
            target_position=position,
            open_ports=open_ports,
            top_exposures=top_exposures,
        )
        self.repository.add_report(report)
        return asset, report

    def register_target(self, payload: MonitorRequest) -> MonitoredTarget:
        target = MonitoredTarget(
            id=f"target-{uuid4()}",
            website_url=payload.website_url,
            scan_interval_seconds=payload.scan_interval_seconds,
            enabled=True,
        )
        return self.repository.upsert_monitored_target(target)

    def automation_status(self) -> AutomationStatus:
        return AutomationStatus(
            running=self._automation_running,
            monitored_target_count=len(self.repository.list_monitored_targets()),
            last_cycle_at=self.repository.last_automation_cycle_at,
        )

    def start_automation(self) -> None:
        if self._automation_running:
            return
        self._automation_running = True
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._automation_loop, daemon=True)
        self._worker.start()

    def stop_automation(self) -> None:
        if not self._automation_running:
            return
        self._automation_running = False
        self._stop_event.set()
        if self._worker:
            self._worker.join(timeout=1.5)
            self._worker = None

    def _automation_loop(self) -> None:
        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            for target in self.repository.list_monitored_targets():
                if not target.enabled:
                    continue
                if target.last_scan_at and (now - target.last_scan_at).total_seconds() < target.scan_interval_seconds:
                    continue
                self.scan_website(ScanRequest(website_url=target.website_url))
                target.last_scan_at = datetime.now(timezone.utc)
                self.repository.upsert_monitored_target(target)

            self.repository.last_automation_cycle_at = datetime.now(timezone.utc)
            time.sleep(5)

    def _simulate_position(self, host: str) -> GeoPosition:
        locations = [
            ("Austin", "USA", 30.2672, -97.7431),
            ("Dallas", "USA", 32.7767, -96.7970),
            ("Frankfurt", "Germany", 50.1109, 8.6821),
            ("Singapore", "Singapore", 1.3521, 103.8198),
            ("Mumbai", "India", 19.0760, 72.8777),
        ]
        seed = int(hashlib.sha256(host.encode("utf-8")).hexdigest()[:8], 16)
        city, country, lat, lon = locations[seed % len(locations)]
        return GeoPosition(city=city, country=country, latitude=lat, longitude=lon)

    def _simulate_open_ports(self, host: str) -> list[OpenPort]:
        port_profiles = [
            OpenPort(port=443, protocol="tcp", service="https"),
            OpenPort(port=80, protocol="tcp", service="http"),
            OpenPort(port=22, protocol="tcp", service="ssh"),
            OpenPort(port=3389, protocol="tcp", service="rdp"),
            OpenPort(port=5432, protocol="tcp", service="postgresql"),
            OpenPort(port=3306, protocol="tcp", service="mysql"),
        ]
        seed = int(hashlib.sha256((host + "ports").encode("utf-8")).hexdigest()[:8], 16)
        count = 3 + (seed % 2)
        return [port_profiles[(seed + i) % len(port_profiles)] for i in range(count)]

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
