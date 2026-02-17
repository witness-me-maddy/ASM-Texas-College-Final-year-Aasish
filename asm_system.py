from __future__ import annotations

"""Core Attack Surface Management (ASM) system.

This module provides a lightweight yet extensible ASM implementation that can:
- register assets and exposed services
- register vulnerabilities associated with assets/services
- calculate risk scores at asset and environment levels
- produce an actionable remediation backlog
- persist and load state as JSON
"""

from dataclasses import dataclass, field, asdict
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
        base = SEVERITY_WEIGHT[self.severity]
        multiplier = EXPOSURE_MULTIPLIER[exposure_level]
        return round(base * multiplier, 2)


@dataclass
class Asset:
    asset_id: str
    hostname: str
    owner: str
    business_criticality: int = 3
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def add_service(self, service: Service) -> None:
        if any(s.port == service.port and s.protocol == service.protocol for s in self.services):
            raise ValueError(f"Service on port {service.port}/{service.protocol} already exists for {self.asset_id}")
        self.services.append(service)

    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
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

    def get_asset(self, asset_id: str) -> Asset:
        try:
            return self.assets[asset_id]
        except KeyError as exc:
            raise KeyError(f"Asset {asset_id} not found") from exc

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
                # Duplicate service, ignore as scanner can report historical entries.
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
                for asset in self.assets.values()
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
                services=[Service(**service) for service in raw_asset.get("services", [])],
                vulnerabilities=[
                    Vulnerability(
                        **{
                            **vuln,
                            "severity": Severity(vuln["severity"]),
                        }
                    )
                    for vuln in raw_asset.get("vulnerabilities", [])
                ],
            )
            asm.register_asset(asset)
        return asm

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "AttackSurfaceManagementSystem":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)


if __name__ == "__main__":
    asm = AttackSurfaceManagementSystem()
    asm.register_asset(
        Asset(
            asset_id="asset-001",
            hostname="portal.texas-college.edu",
            owner="IT Security",
            business_criticality=5,
            exposure_level=ExposureLevel.PUBLIC,
        )
    )
    asm.ingest_scan_result(
        "asset-001",
        services=[
            Service(name="https", port=443, internet_exposed=True),
            Service(name="ssh", port=22, internet_exposed=False),
        ],
        vulnerabilities=[
            Vulnerability(
                title="Outdated OpenSSL",
                severity=Severity.HIGH,
                description="OpenSSL version is vulnerable to known RCE exploit chain.",
                cve="CVE-2023-5678",
                affected_service="https",
            ),
            Vulnerability(
                title="Weak SSH Ciphers",
                severity=Severity.MEDIUM,
                description="Server supports deprecated SSH ciphers.",
                affected_service="ssh",
            ),
        ],
    )

    print("Environment risk score:", asm.environment_risk_score())
    print("Remediation backlog:")
    for item in asm.remediation_backlog():
        print(f"- [{item['severity'].upper()}] {item['asset_id']} :: {item['vulnerability']} ({item['risk_points']} pts)")
