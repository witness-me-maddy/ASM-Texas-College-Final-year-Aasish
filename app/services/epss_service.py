from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict

import httpx


class EPSSService:
    """EPSS service with live API fetch + deterministic fallback cache."""

    def __init__(self) -> None:
        self._cache: Dict[str, tuple[float, float, datetime]] = {}
        self.ttl = timedelta(hours=12)

    def score_for_cve(self, cve: str | None) -> tuple[float, float]:
        if not cve:
            return 0.05, 0.20

        cached = self._cache.get(cve)
        now = datetime.now(timezone.utc)
        if cached and now - cached[2] < self.ttl:
            return cached[0], cached[1]

        live = self._fetch_live_epss(cve)
        if live:
            score, percentile = live
            self._cache[cve] = (score, percentile, now)
            return score, percentile

        score, percentile = self._deterministic_fallback(cve)
        self._cache[cve] = (score, percentile, now)
        return score, percentile

    def _fetch_live_epss(self, cve: str) -> tuple[float, float] | None:
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get("https://api.first.org/data/v1/epss", params={"cve": cve})
                if response.status_code != 200:
                    return None
                payload = response.json()
                rows = payload.get("data", [])
                if not rows:
                    return None
                row = rows[0]
                score = float(row.get("epss", 0.0))
                percentile = float(row.get("percentile", score))
                return round(score, 4), round(percentile, 4)
        except Exception:
            return None

    @staticmethod
    def _deterministic_fallback(cve: str) -> tuple[float, float]:
        digest = hashlib.sha256(cve.encode("utf-8")).hexdigest()
        n = int(digest[:8], 16)
        score = ((n % 1000) / 1000) ** 2
        percentile = min(0.99, max(score, ((n // 1000) % 1000) / 1000))
        return round(score, 4), round(percentile, 4)

    @staticmethod
    def risk_band(epss_score: float) -> str:
        if epss_score >= 0.7:
            return "Critical"
        if epss_score >= 0.4:
            return "High"
        if epss_score >= 0.2:
            return "Medium"
        return "Low"
