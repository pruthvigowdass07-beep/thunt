"""GreyNoise Community API - no-key (rate-limited) internet-scanner classification.

Tells you whether an IP is mass-scanning the internet ("noise"), a known benign
service ("RIOT"), and GreyNoise's malicious/benign classification. An optional free
API key raises the rate limit.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json


class GreyNoise(Source):
    name = "greynoise"
    supports = (IndicatorType.IPV4,)

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        headers = {}
        if cfg.greynoise_key:
            headers["key"] = cfg.greynoise_key
        url = f"https://api.greynoise.io/v3/community/{value}"
        data, err = await get_json(client, url, headers=headers)
        if err == "404":
            return self.skip("not observed scanning")
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        classification = (data.get("classification") or "unknown").lower()
        verdict = {
            "malicious": Verdict.MALICIOUS,
            "benign": Verdict.CLEAN,
        }.get(classification, Verdict.UNKNOWN)
        if data.get("riot") and verdict == Verdict.UNKNOWN:
            verdict = Verdict.CLEAN  # known benign business service

        fields: dict[str, str] = {"Classification": classification}
        if data.get("name") and data["name"] != "unknown":
            fields["Actor"] = data["name"]
        if data.get("noise") is not None:
            fields["Internet noise"] = "yes" if data["noise"] else "no"
        if data.get("riot") is not None:
            fields["RIOT (benign svc)"] = "yes" if data["riot"] else "no"
        if data.get("last_seen"):
            fields["Last seen"] = data["last_seen"]

        summary = classification
        if data.get("noise"):
            summary += " · mass-scanner"
        return self.result(
            verdict=verdict, summary=summary, fields=fields,
            link=data.get("link") or f"https://viz.greynoise.io/ip/{value}",
        )
