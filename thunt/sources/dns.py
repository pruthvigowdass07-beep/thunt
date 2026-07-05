"""DNS resolution via Cloudflare DNS-over-HTTPS - free, no-key.

Resolves a domain to its A/AAAA records and shows NS/MX so you can pivot to the
hosting IPs and mail infrastructure.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..indicators import host_of
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json

_DOH = "https://cloudflare-dns.com/dns-query"


class Dns(Source):
    name = "dns"
    supports = (IndicatorType.DOMAIN, IndicatorType.URL)

    async def _query(self, client, host, rtype):
        data, err = await get_json(
            client, _DOH, params={"name": host, "type": rtype},
            headers={"accept": "application/dns-json"},
        )
        if err or not data:
            return []
        answers = data.get("Answer") or []
        return [a.get("data", "").rstrip(".") for a in answers if a.get("data")]

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        host = host_of(itype, value)
        a = await self._query(client, host, "A")
        aaaa = await self._query(client, host, "AAAA")
        ns = await self._query(client, host, "NS")
        mx = await self._query(client, host, "MX")

        if not any((a, aaaa, ns, mx)):
            return self.skip("no DNS records / NXDOMAIN")

        fields: dict[str, str] = {}
        if a:
            fields["A"] = ", ".join(a[:8])
        if aaaa:
            fields["AAAA"] = ", ".join(aaaa[:4])
        if ns:
            fields["NS"] = ", ".join(sorted(ns)[:5])
        if mx:
            fields["MX"] = ", ".join(m.split(" ")[-1] for m in mx[:5])

        return self.result(
            verdict=Verdict.UNKNOWN,
            summary=f"resolves to {len(a) + len(aaaa)} IP(s)" if (a or aaaa) else "has DNS records",
            fields=fields,
        )
