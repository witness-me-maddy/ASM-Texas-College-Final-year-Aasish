from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

from app.models import Exposure, ExposureStatus, ToolFinding
from app.services.epss_service import EPSSService


class ToolIngestionAdapter:
    """Normalizes findings from scanner tools into an EPSS-first exposure model."""

    def __init__(self, epss_service: EPSSService) -> None:
        self.epss_service = epss_service

    def normalize(self, findings: Iterable[ToolFinding]) -> list[Exposure]:
        exposures: list[Exposure] = []
        now = datetime.now(timezone.utc)

        for finding in findings:
            score, percentile = self.epss_service.score_for_cve(finding.cve)
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
                    source_tool=finding.tool_name,
                    discovered_at=now,
                    status=ExposureStatus.open,
                )
            )

        return exposures
