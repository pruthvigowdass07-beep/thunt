"""AlienVault OTX - community threat "pulses". Needs a free API key."""

from __future__ import annotations

import httpx

from ..config import Config
from ..indicators import host_of
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json


def _section(itype: IndicatorType) -> str:
    if itype == IndicatorType.IPV4:
        return "IPv4"
    if itype == IndicatorType.IPV6:
        return "IPv6"
    if itype.is_hash:
        return "file"
    return "domain"


class Otx(Source):
    name = "otx"
    supports = (
        IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN,
        IndicatorType.URL, IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256,
    )
    requires_key = "otx_key"

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        section = _section(itype)
        ident = value if itype.is_hash else host_of(itype, value)
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ident}/general"
        data, err = await get_json(client, url, headers={"X-OTX-API-KEY": cfg.otx_key})
        if err == "404":
            return self.skip("not in OTX")
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        pulses = (data.get("pulse_info") or {}).get("pulses") or []
        count = (data.get("pulse_info") or {}).get("count", len(pulses))
        fields: dict[str, str] = {"Threat pulses": str(count)}

        names = [p.get("name", "").strip() for p in pulses if p.get("name")]
        if names:
            fields["Reports"] = "; ".join(names[:4])[:200]
        # Aggregate malware families / adversaries mentioned across pulses.
        families = sorted({m for p in pulses for m in (p.get("malware_families") or [])
                           if isinstance(m, str)})
        if families:
            fields["Families"] = ", ".join(families[:6])

        if count >= 3:
            verdict = Verdict.MALICIOUS
        elif count:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN
        summary = f"{count} community threat report(s)"
        return self.result(
            verdict=verdict, summary=summary, fields=fields,
            link=f"https://otx.alienvault.com/indicator/{section.lower()}/{ident}",
        )
