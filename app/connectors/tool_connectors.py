from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable
from uuid import uuid4

from app.models import Exposure, ExposureStatus, ToolFinding
from app.services.epss_service import EPSSService


class ToolIngestionAdapter:
    """Normalizes findings from scanner tools into an EPSS-first exposure model."""

    def __init__(self, epss_service: EPSSService) -> None:
        self.epss_service = epss_service

    def normalize(self, findings: Iterable[ToolFinding], *, criticality: int = 3, internet_exposed: bool = True) -> list[Exposure]:
        exposures: list[Exposure] = []
        now = datetime.now(timezone.utc)

        for finding in findings:
            score, percentile = self.epss_service.score_for_cve(finding.cve)
            context_boost = 0.1 if internet_exposed else 0.0
            business_boost = (criticality / 5) * 0.15
            risk_score = min(1.0, round(score + context_boost + business_boost, 4))
            sla_days = 7 if risk_score >= 0.7 else 14 if risk_score >= 0.4 else 30

            identifier = (finding.cve or finding.title).lower().replace(" ", "-")
            exposures.append(
                Exposure(
                    id=str(uuid4()),
                    title=finding.title,
                    description=(
                        f"Imported from {finding.tool_name}. "
                        f"Severity hint: {finding.severity_hint}."
                    ),
                    cve=finding.cve,
                    epss_score=score,
                    epss_percentile=percentile,
                    risk_score=risk_score,
                    source_tool=finding.tool_name,
                    discovered_at=now,
                    status=ExposureStatus.open,
                    fingerprint=f"{finding.target}|{identifier}",
                    sla_due_at=now + timedelta(days=sla_days),
                )
            )

        return exposures
