from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List
from uuid import uuid4

from app.models import Asset, AssetType, Exposure, ExposureStatus, ScanReport, Summary


class InMemoryRepository:
    def __init__(self) -> None:
        self.assets: Dict[str, Asset] = {}
        self.reports: List[ScanReport] = []
        self._seed()

    def _seed(self) -> None:
        now = datetime.now(timezone.utc)
        self.assets = {
            "asset-1": Asset(
                id="asset-1",
                name="portal.texascollege.edu",
                type=AssetType.web_app,
                owner="IT Security",
                business_unit="Student Services",
                internet_exposed=True,
                criticality=5,
                tags=["production", "student-facing"],
                exposures=[
                    Exposure(
                        id="exp-1",
                        title="Outdated OpenSSL package",
                        description="Detected by vulnerability scanner",
                        cve="CVE-2023-0286",
                        epss_score=0.62,
                        epss_percentile=0.93,
                        source_tool="Nessus",
                        discovered_at=now,
                        status=ExposureStatus.open,
                    )
                ],
            ),
            "asset-2": Asset(
                id="asset-2",
                name="api.texascollege.edu",
                type=AssetType.domain,
                owner="Engineering",
                business_unit="Digital Learning",
                internet_exposed=True,
                criticality=4,
                tags=["api", "production"],
                exposures=[],
            ),
        }

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
        )
        self.assets[asset.id] = asset
        return asset

    def add_exposures(self, asset_id: str, exposures: list[Exposure]) -> int:
        asset = self.assets[asset_id]
        before = len(asset.exposures)
        asset.exposures.extend(exposures)
        return len(asset.exposures) - before

    def add_report(self, report: ScanReport) -> None:
        self.reports.insert(0, report)

    def list_reports(self) -> List[ScanReport]:
        return self.reports

    def summary(self) -> Summary:
        exposures = [e for a in self.assets.values() for e in a.exposures]
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

    def group_by_business_unit(self) -> dict[str, int]:
        buckets = defaultdict(int)
        for asset in self.assets.values():
            buckets[asset.business_unit] += len(
                [e for e in asset.exposures if e.status == ExposureStatus.open]
            )
        return dict(buckets)
