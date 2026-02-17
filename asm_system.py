from __future__ import annotations

"""Attack Surface Management (ASM) core system.

This module provides data models and orchestration logic to:
- register and update assets
- ingest service/vulnerability scan data
- calculate risk scores
- generate remediation backlog
- persist/reload ASM state as JSON
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional


class ExposureLevel(str, Enum):
    INTERNAL = "internal"
    PARTNER = "partner"
    PUBLIC = "public"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}

EXPOSURE_MULTIPLIER = {
    ExposureLevel.INTERNAL: 1.0,
    ExposureLevel.PARTNER: 1.4,
    ExposureLevel.PUBLIC: 1.8,
}


@dataclass
class Service:
    name: str
    port: int
    protocol: str = "tcp"
    internet_exposed: bool = False


@dataclass
class Vulnerability:
    title: str
    severity: Severity
    description: str
    cve: Optional[str] = None
    affected_service: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    remediated: bool = False

    def risk_points(self, exposure_level: ExposureLevel) -> float:
        return round(SEVERITY_WEIGHT[self.severity] * EXPOSURE_MULTIPLIER[exposure_level], 2)


@dataclass
class Asset:
    asset_id: str
    hostname: str
    owner: str
    business_criticality: int = 3
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    tags: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 1 <= self.business_criticality <= 5:
            raise ValueError("business_criticality must be between 1 and 5")

    def add_service(self, service: Service) -> None:
        key = (service.port, service.protocol.lower())
        if any((s.port, s.protocol.lower()) == key for s in self.services):
            raise ValueError(f"Service on port {service.port}/{service.protocol} already exists for {self.asset_id}")
        self.services.append(service)

    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        duplicate = any(
            v.title == vulnerability.title
            and v.affected_service == vulnerability.affected_service
            and not v.remediated
            for v in self.vulnerabilities
        )
        if not duplicate:
            self.vulnerabilities.append(vulnerability)

    def open_vulnerabilities(self) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if not v.remediated]

    def risk_score(self) -> float:
        vuln_score = sum(v.risk_points(self.exposure_level) for v in self.open_vulnerabilities())
        internet_surface_bonus = 2.5 * sum(1 for s in self.services if s.internet_exposed)
        criticality_multiplier = 1 + ((self.business_criticality - 1) * 0.15)
        return round((vuln_score + internet_surface_bonus) * criticality_multiplier, 2)


@dataclass
class AttackSurfaceManagementSystem:
    assets: Dict[str, Asset] = field(default_factory=dict)

    def register_asset(self, asset: Asset) -> None:
        if asset.asset_id in self.assets:
            raise ValueError(f"Asset {asset.asset_id} already registered")
        self.assets[asset.asset_id] = asset

    def delete_asset(self, asset_id: str) -> bool:
        return self.assets.pop(asset_id, None) is not None

    def get_asset(self, asset_id: str) -> Asset:
        if asset_id not in self.assets:
            raise KeyError(f"Asset {asset_id} not found")
        return self.assets[asset_id]

    def list_assets(self) -> List[Asset]:
        return sorted(self.assets.values(), key=lambda a: a.asset_id)

    def ingest_scan_result(
        self,
        asset_id: str,
        services: Optional[Iterable[Service]] = None,
        vulnerabilities: Optional[Iterable[Vulnerability]] = None,
    ) -> None:
        asset = self.get_asset(asset_id)
        for service in services or []:
            try:
                asset.add_service(service)
            except ValueError:
                pass
        for vulnerability in vulnerabilities or []:
            asset.add_vulnerability(vulnerability)

    def remediate(self, asset_id: str, vuln_title: str) -> bool:
        asset = self.get_asset(asset_id)
        for vuln in asset.vulnerabilities:
            if vuln.title == vuln_title and not vuln.remediated:
                vuln.remediated = True
                return True
        return False

    def environment_risk_score(self) -> float:
        return round(sum(asset.risk_score() for asset in self.assets.values()), 2)

    def exposure_summary(self) -> Dict[str, int]:
        summary = {level.value: 0 for level in ExposureLevel}
        for asset in self.assets.values():
            summary[asset.exposure_level.value] += 1
        return summary

    def severity_summary(self) -> Dict[str, int]:
        summary = {severity.value: 0 for severity in Severity}
        for asset in self.assets.values():
            for vuln in asset.open_vulnerabilities():
                summary[vuln.severity.value] += 1
        return summary

    def remediation_backlog(self) -> List[dict]:
        backlog = []
        for asset in self.assets.values():
            for vuln in asset.open_vulnerabilities():
                backlog.append(
                    {
                        "asset_id": asset.asset_id,
                        "hostname": asset.hostname,
                        "owner": asset.owner,
                        "vulnerability": vuln.title,
                        "severity": vuln.severity.value,
                        "risk_points": vuln.risk_points(asset.exposure_level),
                        "exposure": asset.exposure_level.value,
                        "service": vuln.affected_service,
                        "discovered_at": vuln.discovered_at,
                    }
                )
        backlog.sort(
            key=lambda item: (
                item["risk_points"],
                SEVERITY_WEIGHT[Severity(item["severity"])],
            ),
            reverse=True,
        )
        return backlog

    def dashboard(self) -> dict:
        return {
            "asset_count": len(self.assets),
            "environment_risk": self.environment_risk_score(),
            "open_vulnerabilities": sum(len(a.open_vulnerabilities()) for a in self.assets.values()),
            "exposure_summary": self.exposure_summary(),
            "severity_summary": self.severity_summary(),
            "top_risks": self.remediation_backlog()[:10],
        }

    def to_dict(self) -> dict:
        return {
            "assets": [
                {
                    **asdict(asset),
                    "exposure_level": asset.exposure_level.value,
                    "services": [asdict(service) for service in asset.services],
                    "vulnerabilities": [
                        {
                            **asdict(v),
                            "severity": v.severity.value,
                        }
                        for v in asset.vulnerabilities
                    ],
                }
                for asset in self.list_assets()
            ]
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "AttackSurfaceManagementSystem":
        asm = cls()
        for raw_asset in payload.get("assets", []):
            asset = Asset(
                asset_id=raw_asset["asset_id"],
                hostname=raw_asset["hostname"],
                owner=raw_asset["owner"],
                business_criticality=raw_asset.get("business_criticality", 3),
                exposure_level=ExposureLevel(raw_asset.get("exposure_level", "internal")),
                tags=raw_asset.get("tags", []),
                services=[Service(**service) for service in raw_asset.get("services", [])],
                vulnerabilities=[
                    Vulnerability(**{**vuln, "severity": Severity(vuln["severity"])})
                    for vuln in raw_asset.get("vulnerabilities", [])
                ],
            )
            asm.register_asset(asset)
        return asm

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "AttackSurfaceManagementSystem":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)


def seed_demo_environment() -> AttackSurfaceManagementSystem:
    asm = AttackSurfaceManagementSystem()
    asm.register_asset(
        Asset(
            asset_id="asset-001",
            hostname="portal.texascollege.edu",
            owner="IT Security",
            business_criticality=5,
            exposure_level=ExposureLevel.PUBLIC,
            tags=["student", "production", "web"],
        )
    )
    asm.register_asset(
        Asset(
            asset_id="asset-002",
            hostname="erp.internal.texascollege.edu",
            owner="Enterprise Apps",
            business_criticality=4,
            exposure_level=ExposureLevel.INTERNAL,
            tags=["erp", "finance"],
        )
    )

    asm.ingest_scan_result(
        "asset-001",
        services=[
            Service(name="https", port=443, internet_exposed=True),
            Service(name="ssh", port=22),
        ],
        vulnerabilities=[
            Vulnerability(
                title="Outdated OpenSSL",
                severity=Severity.HIGH,
                description="OpenSSL version vulnerable to RCE chain.",
                cve="CVE-2023-5678",
                affected_service="https",
            ),
            Vulnerability(
                title="Weak SSH Ciphers",
                severity=Severity.MEDIUM,
                description="Deprecated ciphers enabled.",
                affected_service="ssh",
            ),
        ],
    )

    asm.ingest_scan_result(
        "asset-002",
        services=[Service(name="mssql", port=1433)],
        vulnerabilities=[
            Vulnerability(
                title="Missing Security Patches",
                severity=Severity.CRITICAL,
                description="OS patch level behind security baseline.",
            )
        ],
    )

    return asm


if __name__ == "__main__":
    demo = seed_demo_environment()
    print(json.dumps(demo.dashboard(), indent=2))
