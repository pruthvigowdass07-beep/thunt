import asyncio
import json

import httpx
import pytest

from thunt.config import Config
from thunt.engine import Report, investigate
from thunt.models import IndicatorType, SourceResult, Verdict
from thunt.render import to_json
from thunt.sources.base import Source


def _report(*results: SourceResult) -> Report:
    r = Report(indicator="1.2.3.4", itype=IndicatorType.IPV4)
    r.results = list(results)
    return r


def test_overall_takes_most_severe():
    rep = _report(
        SourceResult("a", verdict=Verdict.CLEAN),
        SourceResult("b", verdict=Verdict.MALICIOUS),
        SourceResult("c", verdict=Verdict.SUSPICIOUS),
    )
    assert rep.overall == Verdict.MALICIOUS
    assert rep.malicious_sources == ["b"]
    assert rep.suspicious_sources == ["c"]


def test_overall_clean_when_only_clean_and_unknown():
    rep = _report(
        SourceResult("a", verdict=Verdict.CLEAN),
        SourceResult("b", verdict=Verdict.UNKNOWN),
    )
    assert rep.overall == Verdict.CLEAN


def test_errors_and_skips_excluded():
    rep = _report(
        SourceResult("a", verdict=Verdict.ERROR, error="boom"),
        SourceResult("b", verdict=Verdict.UNKNOWN, skipped=True),
    )
    assert rep.overall == Verdict.UNKNOWN
    assert rep.malicious_sources == []


def test_to_json_shape():
    rep = _report(SourceResult("a", verdict=Verdict.MALICIOUS, summary="bad"))
    payload = json.loads(to_json(rep))
    assert payload["indicator"] == "1.2.3.4"
    assert payload["verdict"] == "Malicious"
    assert payload["sources"][0]["verdict"] == "Malicious"


class _FakeSource(Source):
    name = "fake"
    supports = (IndicatorType.IPV4,)

    async def fetch(self, client, itype, value, cfg):
        return self.result(verdict=Verdict.MALICIOUS, summary="fake hit")


def test_investigate_runs_only_filtered(monkeypatch):
    import thunt.sources as sources_mod

    fake = _FakeSource()
    monkeypatch.setattr(sources_mod, "ALL_SOURCES", [fake])

    rep = asyncio.run(
        investigate(IndicatorType.IPV4, "1.2.3.4", Config(), only={"fake"})
    )
    assert rep.overall == Verdict.MALICIOUS
    assert rep.results[0].source == "fake"


def test_source_exception_becomes_error(monkeypatch):
    import thunt.sources as sources_mod

    class Boom(Source):
        name = "boom"
        supports = (IndicatorType.IPV4,)

        async def fetch(self, client, itype, value, cfg):
            raise RuntimeError("kaboom")

    monkeypatch.setattr(sources_mod, "ALL_SOURCES", [Boom()])
    rep = asyncio.run(investigate(IndicatorType.IPV4, "1.2.3.4", Config()))
    assert rep.results[0].error is not None
    assert rep.overall == Verdict.UNKNOWN
