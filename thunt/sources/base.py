"""Source plugin contract and shared helpers.

A Source declares which indicator types it supports and whether it needs an API key.
Each source implements `fetch()` and returns a SourceResult. The registry filters
sources by indicator type and key availability, then runs the applicable ones
concurrently.
"""

from __future__ import annotations

import abc
from typing import Optional

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict


class Source(abc.ABC):
    #: Display name shown in the panel header.
    name: str = "source"
    #: Indicator types this source can enrich.
    supports: tuple[IndicatorType, ...] = ()
    #: Config field name of a required key, or None if the source needs no key.
    requires_key: Optional[str] = None
    #: If True, the source is only useful when scraping is enabled (no free API path).
    needs_scrape: bool = False

    def applicable(self, itype: IndicatorType, cfg: Config) -> bool:
        if itype not in self.supports:
            return False
        if self.requires_key and not cfg.has(self.requires_key):
            return False
        if self.needs_scrape and not cfg.allow_scrape:
            return False
        return True

    @abc.abstractmethod
    async def fetch(
        self,
        client: httpx.AsyncClient,
        itype: IndicatorType,
        value: str,
        cfg: Config,
    ) -> SourceResult:
        ...

    # --- convenience result builders -------------------------------------------------

    def result(self, **kwargs) -> SourceResult:
        return SourceResult(source=self.name, **kwargs)

    def error(self, message: str) -> SourceResult:
        return SourceResult(source=self.name, verdict=Verdict.ERROR, error=message)

    def skip(self, reason: str = "no data") -> SourceResult:
        return SourceResult(
            source=self.name, verdict=Verdict.UNKNOWN, summary=reason, skipped=True
        )


async def get_json(
    client: httpx.AsyncClient, url: str, **kwargs
) -> tuple[Optional[dict], Optional[str]]:
    """GET a URL and parse JSON. Returns (data, error_message)."""
    try:
        resp = await client.get(url, **kwargs)
    except httpx.HTTPError as exc:
        return None, f"request failed: {exc.__class__.__name__}"
    if resp.status_code == 404:
        return None, "404"
    if resp.status_code in (401, 403):
        return None, "401"
    if resp.status_code == 429:
        return None, "rate limited (429)"
    if resp.status_code >= 400:
        return None, f"HTTP {resp.status_code}"
    try:
        return resp.json(), None
    except ValueError:
        return None, "invalid JSON response"


async def post_json(
    client: httpx.AsyncClient, url: str, **kwargs
) -> tuple[Optional[dict], Optional[str]]:
    try:
        resp = await client.post(url, **kwargs)
    except httpx.HTTPError as exc:
        return None, f"request failed: {exc.__class__.__name__}"
    if resp.status_code in (401, 403):
        return None, "401"
    if resp.status_code == 429:
        return None, "rate limited (429)"
    if resp.status_code >= 400:
        return None, f"HTTP {resp.status_code}"
    try:
        return resp.json(), None
    except ValueError:
        return None, "invalid JSON response"
