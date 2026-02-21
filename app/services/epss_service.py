from __future__ import annotations

import hashlib
from typing import Dict


class EPSSService:
    """Deterministic EPSS estimator + optional live API adapter hook.

    This class defaults to deterministic scores to keep local/offline development predictable.
    In production, replace `score_for_cve` with API-backed retrieval and caching.
    """

    def __init__(self) -> None:
        self._cache: Dict[str, tuple[float, float]] = {}

    def score_for_cve(self, cve: str | None) -> tuple[float, float]:
        if not cve:
            return 0.05, 0.20

        if cve in self._cache:
            return self._cache[cve]

        digest = hashlib.sha256(cve.encode("utf-8")).hexdigest()
        n = int(digest[:8], 16)

        # Produce deterministic values with realistic skew to lower probabilities.
        score = ((n % 1000) / 1000) ** 2
        percentile = min(0.99, max(score, ((n // 1000) % 1000) / 1000))

        result = round(score, 4), round(percentile, 4)
        self._cache[cve] = result
        return result

    @staticmethod
    def risk_band(epss_score: float) -> str:
        if epss_score >= 0.7:
            return "Critical"
        if epss_score >= 0.4:
            return "High"
        if epss_score >= 0.2:
            return "Medium"
        return "Low"
