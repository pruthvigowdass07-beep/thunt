"""Shodan InternetDB - free, no-key exposure data (open ports, CVEs, tags)."""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json

_BAD_TAGS = {"malware", "compromised", "c2", "botnet", "honeypot", "self-signed"}


class ShodanInternetDB(Source):
    name = "shodan-internetdb"
    supports = (IndicatorType.IPV4, IndicatorType.IPV6)

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        data, err = await get_json(client, f"https://internetdb.shodan.io/{value}")
        if err == "404":
            return self.skip("no exposure data")
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        tags = data.get("tags") or []
        hostnames = data.get("hostnames") or []

        fields: dict[str, str] = {}
        if ports:
            fields["Open ports"] = ", ".join(str(p) for p in ports[:20])
        if hostnames:
            fields["Hostnames"] = ", ".join(hostnames[:5])
        if tags:
            fields["Tags"] = ", ".join(tags)
        if vulns:
            fields["CVEs"] = f"{len(vulns)} known ({', '.join(vulns[:6])}{'…' if len(vulns) > 6 else ''})"

        bad = _BAD_TAGS.intersection({t.lower() for t in tags})
        if bad:
            verdict = Verdict.MALICIOUS
            summary = f"flagged: {', '.join(sorted(bad))}"
        elif vulns:
            verdict = Verdict.SUSPICIOUS
            summary = f"{len(ports)} ports, {len(vulns)} CVEs exposed"
        elif ports:
            verdict = Verdict.UNKNOWN
            summary = f"{len(ports)} ports exposed"
        else:
            return self.skip("no exposure data")

        return self.result(
            verdict=verdict, summary=summary, fields=fields,
            link=f"https://www.shodan.io/host/{value}",
        )
