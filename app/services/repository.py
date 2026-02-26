from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List
from uuid import uuid4

from app.models import (
    Asset,
    AssetType,
    Exposure,
    ExposureStatus,
    GeoPosition,
    MonitoredTarget,
    OpenPort,
    ScanJob,
    ScanReport,
    ScanStatus,
    ScannerNode,
    Summary,
    TicketRecord,
)


class InMemoryRepository:
    def __init__(self) -> None:
        self.assets: Dict[str, Asset] = {}
        self.reports: List[ScanReport] = []
        self.monitored_targets: Dict[str, MonitoredTarget] = {}
        self.jobs: Dict[str, ScanJob] = {}
        self.nodes: Dict[str, ScannerNode] = {}
        self.tickets: Dict[str, TicketRecord] = {}
        self.last_automation_cycle_at: datetime | None = None
        self._seed()

    def _seed(self) -> None:
        now = datetime.now(timezone.utc)
        exposure = Exposure(
            id="exp-1",
            title="Outdated OpenSSL package",
            description="Detected by vulnerability scanner",
            cve="CVE-2023-0286",
            epss_score=0.62,
            epss_percentile=0.93,
            risk_score=0.76,
            source_tool="Nessus",
            discovered_at=now,
            status=ExposureStatus.open,
            fingerprint="portal.texascollege.edu|cve-2023-0286",
            sla_due_at=now + timedelta(days=14),
        )

        asset = Asset(
            id="asset-1",
            name="portal.texascollege.edu",
            type=AssetType.web_app,
            owner="IT Security",
            business_unit="Student Services",
            internet_exposed=True,
            criticality=5,
            tags=["production", "student-facing"],
            position=GeoPosition(city="Dallas", country="USA", latitude=32.7767, longitude=-96.7970),
            open_ports=[OpenPort(port=443, protocol="tcp", service="https"), OpenPort(port=22, protocol="tcp", service="ssh")],
            exposures=[exposure],
        )
        exposure.asset_id = asset.id
        self.assets = {asset.id: asset}

        self.reports = [
            ScanReport(
                id="scan-seed-1",
                website_url="https://portal.texascollege.edu",
                target_host="portal.texascollege.edu",
                status=ScanStatus.completed,
                started_at=now,
                completed_at=now,
                tools_executed=["Nmap", "Masscan", "Subfinder", "Nuclei"],
                scanned_port_range="1-65535",
                assets_discovered=5,
                exposures_discovered=1,
                max_epss_score=0.62,
                max_epss_percentile=0.93,
                target_position=asset.position,
                open_ports=asset.open_ports,
                discovered_subdomains=["www.portal.texascollege.edu", "api.portal.texascollege.edu"],
                discovered_ips=["203.0.113.10", "203.0.113.11"],
                discovered_technologies=["Nginx", "React", "FastAPI"],
                discovered_urls=["https://portal.texascollege.edu/login"],
                discovered_emails=["security@texascollege.edu"],
                discovered_cloud_assets=["aws-s3-public-bucket"],
                waf_detected="Cloudflare WAF",
                top_exposures=[exposure],
            )
        ]

    def list_assets(self) -> List[Asset]:
        return list(self.assets.values())

    def get_asset(self, asset_id: str) -> Asset | None:
        return self.assets.get(asset_id)

    def upsert_asset(self, name: str, owner: str, business_unit: str) -> Asset:
        for asset in self.assets.values():
            if asset.name == name:
                return asset

        asset = Asset(
            id=f"asset-{uuid4()}",
            name=name,
            type=AssetType.domain,
            owner=owner,
            business_unit=business_unit,
            internet_exposed=True,
            criticality=3,
            tags=["discovered"],
            exposures=[],
            open_ports=[],
        )
        self.assets[asset.id] = asset
        return asset

    def _find_duplicate(self, asset: Asset, exposure: Exposure) -> Exposure | None:
        return next((e for e in asset.exposures if e.fingerprint and e.fingerprint == exposure.fingerprint), None)

    def add_exposures(self, asset_id: str, exposures: list[Exposure]) -> tuple[int, int]:
        asset = self.assets[asset_id]
        created = 0
        deduped = 0
        for exposure in exposures:
            exposure.asset_id = asset_id
            if not exposure.fingerprint:
                exposure.fingerprint = f"{asset.name}|{(exposure.cve or exposure.title).lower()}"
            duplicate = self._find_duplicate(asset, exposure)
            if duplicate:
                deduped += 1
                exposure.duplicate_of = duplicate.id
                continue
            asset.exposures.append(exposure)
            created += 1
        return created, deduped

    def list_exposures(self) -> list[Exposure]:
        return [e for a in self.assets.values() for e in a.exposures]

    def get_exposure(self, exposure_id: str) -> Exposure | None:
        for asset in self.assets.values():
            for exposure in asset.exposures:
                if exposure.id == exposure_id:
                    return exposure
        return None

    def add_report(self, report: ScanReport) -> None:
        self.reports.insert(0, report)

    def list_reports(self) -> List[ScanReport]:
        return self.reports

    def get_report(self, report_id: str) -> ScanReport | None:
        return next((r for r in self.reports if r.id == report_id), None)

    def upsert_monitored_target(self, target: MonitoredTarget) -> MonitoredTarget:
        self.monitored_targets[target.id] = target
        return target

    def list_monitored_targets(self) -> List[MonitoredTarget]:
        return list(self.monitored_targets.values())

    def add_job(self, job: ScanJob) -> ScanJob:
        self.jobs[job.id] = job
        return job

    def update_job(self, job: ScanJob) -> None:
        self.jobs[job.id] = job

    def get_job(self, job_id: str) -> ScanJob | None:
        return self.jobs.get(job_id)

    def list_jobs(self) -> list[ScanJob]:
        return sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)

    def upsert_node(self, node: ScannerNode) -> None:
        self.nodes[node.id] = node

    def list_nodes(self) -> list[ScannerNode]:
        return list(self.nodes.values())

    def add_ticket(self, ticket: TicketRecord) -> TicketRecord:
        self.tickets[ticket.id] = ticket
        return ticket

    def summary(self) -> Summary:
        exposures = self.list_exposures()
        open_exposures = [e for e in exposures if e.status == ExposureStatus.open]
        high_risk = [e for e in open_exposures if e.epss_score >= 0.4]

        mean_epss = (
            sum(e.epss_score for e in open_exposures) / len(open_exposures)
            if open_exposures
            else 0.0
        )

        return Summary(
            asset_count=len(self.assets),
            open_exposure_count=len(open_exposures),
            high_risk_exposure_count=len(high_risk),
            internet_exposed_assets=sum(1 for a in self.assets.values() if a.internet_exposed),
            mean_epss=round(mean_epss, 4),
        )



    def reporting_snapshot(self) -> dict:
        exposures = self.list_exposures()
        open_exposures = [e for e in exposures if e.status == ExposureStatus.open]
        accepted_exposures = [e for e in exposures if e.status == ExposureStatus.accepted]
        mitigated_exposures = [e for e in exposures if e.status == ExposureStatus.mitigated]

        now = datetime.now(timezone.utc)
        sla_breaches = [e for e in open_exposures if e.sla_due_at and e.sla_due_at < now]

        risk_bands = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for exposure in exposures:
            if exposure.epss_score >= 0.7:
                risk_bands["Critical"] += 1
            elif exposure.epss_score >= 0.4:
                risk_bands["High"] += 1
            elif exposure.epss_score >= 0.2:
                risk_bands["Medium"] += 1
            else:
                risk_bands["Low"] += 1

        tool_breakdown: dict[str, int] = defaultdict(int)
        for exposure in exposures:
            tool_breakdown[exposure.source_tool] += 1

        business_unit_breakdown: dict[str, dict[str, int]] = {}
        for asset in self.assets.values():
            rows = asset.exposures
            if not rows:
                continue
            business_unit_breakdown[asset.business_unit] = {
                "total": len(rows),
                "open": len([e for e in rows if e.status == ExposureStatus.open]),
                "critical": len([e for e in rows if e.epss_score >= 0.7]),
                "high": len([e for e in rows if 0.4 <= e.epss_score < 0.7]),
            }

        reports = self.list_reports()
        recent_reports = [
            {
                "id": report.id,
                "target_host": report.target_host,
                "completed_at": report.completed_at,
                "exposures_discovered": report.exposures_discovered,
                "max_epss_score": report.max_epss_score,
            }
            for report in reports[:10]
        ]

        return {
            "kpis": {
                "assets": len(self.assets),
                "total_exposures": len(exposures),
                "open_exposures": len(open_exposures),
                "accepted_risk_exposures": len(accepted_exposures),
                "mitigated_exposures": len(mitigated_exposures),
                "sla_breaches": len(sla_breaches),
                "reports_generated": len(reports),
            },
            "risk_bands": risk_bands,
            "business_units": business_unit_breakdown,
            "source_tools": dict(sorted(tool_breakdown.items(), key=lambda x: x[1], reverse=True)),
            "recent_reports": recent_reports,
        }

    def group_by_business_unit(self) -> dict[str, int]:
        buckets = defaultdict(int)
        for asset in self.assets.values():
            buckets[asset.business_unit] += len([e for e in asset.exposures if e.status == ExposureStatus.open])
        return dict(buckets)
