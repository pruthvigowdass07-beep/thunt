"""Cisco Talos reputation - no free API, so scraped best-effort with Playwright.

Only runs when scraping is enabled (--scrape) because Talos is behind reCAPTCHA and
scraping is inherently fragile.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source


class Talos(Source):
    name = "talos"
    supports = (IndicatorType.IPV4,)
    needs_scrape = True

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        from .. import scrape

        try:
            data = await scrape.talos_reputation(value, timeout_ms=int(cfg.timeout * 1000))
        except scrape.ScrapeUnavailable as exc:
            return self.error(str(exc))
        except Exception as exc:
            return self.error(f"scrape failed: {exc.__class__.__name__}")

        if not data:
            return self.skip("no reputation shown (reCAPTCHA?)")

        rep = (data.get("Web reputation") or data.get("Email reputation") or "").lower()
        if "poor" in rep or "malicious" in rep:
            verdict = Verdict.MALICIOUS
        elif "neutral" in rep or "questionable" in rep:
            verdict = Verdict.SUSPICIOUS
        elif "good" in rep or "favorable" in rep:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN

        summary = data.get("Web reputation") or data.get("Email reputation") or "looked up"
        return self.result(
            verdict=verdict, summary=summary, fields=data,
            link=f"https://talosintelligence.com/reputation_center/lookup?search={value}",
        )
