"""ip-api.com - free, no-key IP geolocation + hosting/proxy flags."""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json

_FIELDS = (
    "status,message,country,countryCode,regionName,city,isp,org,as,asname,"
    "reverse,mobile,proxy,hosting,query"
)


class IpApi(Source):
    name = "ip-api"
    supports = (IndicatorType.IPV4, IndicatorType.IPV6)

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        # Free tier is HTTP-only; HTTPS requires a paid key.
        url = f"http://ip-api.com/json/{value}?fields={_FIELDS}"
        data, err = await get_json(client, url)
        if err:
            return self.error(err)
        if not data or data.get("status") != "success":
            return self.skip(data.get("message", "no data") if data else "no data")

        fields: dict[str, str] = {}
        loc = ", ".join(x for x in (data.get("city"), data.get("regionName"), data.get("country")) if x)
        if loc:
            fields["Location"] = loc
        if data.get("isp"):
            fields["ISP"] = data["isp"]
        if data.get("org") and data.get("org") != data.get("isp"):
            fields["Org"] = data["org"]
        if data.get("as"):
            fields["ASN"] = data["as"]
        if data.get("reverse"):
            fields["rDNS"] = data["reverse"]

        flags = []
        if data.get("proxy"):
            flags.append("proxy/VPN")
        if data.get("hosting"):
            flags.append("hosting/datacenter")
        if data.get("mobile"):
            flags.append("mobile")
        if flags:
            fields["Flags"] = ", ".join(flags)

        # ip-api is informational, not a reputation source: it never asserts malicious.
        verdict = Verdict.SUSPICIOUS if data.get("proxy") else Verdict.CLEAN
        summary = loc or "located"
        if data.get("proxy"):
            summary += " (proxy/anonymizer)"
        return self.result(verdict=verdict, summary=summary, fields=fields)
