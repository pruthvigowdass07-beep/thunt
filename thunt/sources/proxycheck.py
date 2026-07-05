"""proxycheck.io - VPN / proxy / Tor detection with provider attribution.

Answers "is this a VPN or Tor node, and if so whose?". The free tier works without a
key (~100 queries/day); an optional free API key (proxycheck_key) raises it to
1000/day and enables provider names on every lookup.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json

# proxycheck's `type` values we treat as anonymizing infrastructure.
_ANON_TYPES = {"VPN", "TOR", "PUB", "WEB", "SES", "COM"}


class ProxyCheck(Source):
    name = "proxycheck"
    supports = (IndicatorType.IPV4, IndicatorType.IPV6)

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        params = {"vpn": "1", "asn": "1", "risk": "1"}
        if cfg.proxycheck_key:
            params["key"] = cfg.proxycheck_key
        data, err = await get_json(
            client, f"https://proxycheck.io/v2/{value}", params=params
        )
        if err:
            return self.error(err)
        if not data:
            return self.skip()
        if data.get("status") == "denied":
            return self.error(data.get("message", "daily free limit reached; add proxycheck_key"))
        if data.get("status") not in ("ok", "warning", None):
            return self.skip(data.get("message", "no data"))

        rec = data.get(value) or {}
        if not rec:
            return self.skip("no data")

        is_proxy = str(rec.get("proxy", "no")).lower() == "yes"
        ptype = (rec.get("type") or "").upper()
        provider = rec.get("provider") or rec.get("organisation")
        risk = rec.get("risk")

        fields: dict[str, str] = {}
        fields["Proxy/VPN"] = "yes" if is_proxy else "no"
        if ptype:
            fields["Type"] = ptype
        if provider:
            fields["Provider"] = str(provider)
        if rec.get("operator", {}).get("name"):
            fields["Operator"] = str(rec["operator"]["name"])
        if risk is not None:
            fields["Risk score"] = f"{risk}/100"
        if rec.get("asn"):
            fields["ASN"] = str(rec["asn"])

        is_tor = ptype == "TOR"
        if is_tor:
            verdict = Verdict.SUSPICIOUS
            summary = f"TOR exit node ({provider})" if provider else "TOR exit node"
        elif is_proxy and ptype in _ANON_TYPES:
            verdict = Verdict.SUSPICIOUS
            label = "VPN" if ptype == "VPN" else "proxy"
            summary = f"{label}: {provider}" if provider else f"{label} detected"
        elif is_proxy:
            verdict = Verdict.SUSPICIOUS
            summary = f"anonymizer ({ptype or 'proxy'})"
        else:
            verdict = Verdict.CLEAN
            summary = "not a proxy/VPN/Tor"

        try:
            if risk is not None and int(risk) >= 66:
                verdict = Verdict.MALICIOUS
        except (TypeError, ValueError):
            pass

        return self.result(verdict=verdict, summary=summary, fields=fields)
