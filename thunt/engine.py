"""Query orchestration: run all applicable sources concurrently and aggregate."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from . import sources as sources_mod
from .config import Config
from .models import IndicatorType, SourceResult, Verdict

_USER_AGENT = "thunt/0.1 (+https://github.com/yourname/thunt)"


@dataclass
class Report:
    indicator: str
    itype: IndicatorType
    results: list[SourceResult] = field(default_factory=list)
    gated: list[tuple[str, str]] = field(default_factory=list)  # (source_name, reason)

    @property
    def overall(self) -> Verdict:
        """The most severe verdict from sources that actually returned data."""
        worst = Verdict.UNKNOWN
        seen_clean = False
        for r in self.results:
            if not r.ok:
                continue
            if r.verdict == Verdict.CLEAN:
                seen_clean = True
            if r.verdict.value > worst.value and r.verdict != Verdict.ERROR:
                worst = r.verdict
        if worst == Verdict.UNKNOWN and seen_clean:
            return Verdict.CLEAN
        return worst

    @property
    def malicious_sources(self) -> list[str]:
        return [r.source for r in self.results if r.ok and r.verdict == Verdict.MALICIOUS]

    @property
    def suspicious_sources(self) -> list[str]:
        return [r.source for r in self.results if r.ok and r.verdict == Verdict.SUSPICIOUS]


async def _run_one(source, client, itype, value, cfg) -> SourceResult:
    try:
        return await asyncio.wait_for(
            source.fetch(client, itype, value, cfg), timeout=cfg.timeout + 5
        )
    except asyncio.TimeoutError:
        return source.error("timed out")
    except Exception as exc:  # never let one source break the run
        return source.error(f"{exc.__class__.__name__}: {exc}")


async def investigate(
    itype: IndicatorType, value: str, cfg: Config, only: set[str] | None = None
) -> Report:
    active = sources_mod.applicable(itype, cfg, only)
    report = Report(indicator=value, itype=itype)
    report.gated = [(s.name, why) for s, why in sources_mod.gated(itype, cfg)]

    limits = httpx.Limits(max_connections=12)
    timeout = httpx.Timeout(cfg.timeout)
    async with httpx.AsyncClient(
        headers={"User-Agent": _USER_AGENT}, timeout=timeout, limits=limits,
        follow_redirects=True,
    ) as client:
        tasks = [_run_one(s, client, itype, value, cfg) for s in active]
        results = await asyncio.gather(*tasks)

    # Preserve registry order for stable rendering.
    order = {s.name: i for i, s in enumerate(sources_mod.ALL_SOURCES)}
    report.results = sorted(results, key=lambda r: order.get(r.source, 99))
    return report
