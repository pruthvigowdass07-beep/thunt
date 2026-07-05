"""ThreatFox (abuse.ch) - IOC-to-malware mapping (C2s, payloads, etc.).

Uses the free abuse.ch Auth-Key when configured. A match means the indicator is a
known IOC tied to a malware family, with a confidence level.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..indicators import host_of
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, post_json

_API = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox(Source):
    name = "threatfox"
    supports = (
        IndicatorType.IPV4, IndicatorType.DOMAIN, IndicatorType.URL,
        IndicatorType.MD5, IndicatorType.SHA256,
    )

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        headers = {}
        if cfg.abusech_key:
            headers["Auth-Key"] = cfg.abusech_key
        search = value if itype.is_hash else host_of(itype, value)
        data, err = await post_json(
            client, _API,
            json={"query": "search_ioc", "search_term": search},
            headers=headers,
        )
        if err == "401":
            return self.error("needs free abuse.ch Auth-Key (thunt config set abusech_key)")
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        status = data.get("query_status")
        if status in ("no_result", "illegal_search_term"):
            return self.skip("not a known IOC")
        if status in ("unauthorized", "unauthenticated", "no_auth_key"):
            return self.error("needs free abuse.ch Auth-Key (thunt config set abusech_key)")
        if status != "ok":
            return self.skip(status or "no data")

        items = data.get("data") or []
        if not items:
            return self.skip("not a known IOC")
        first = items[0]

        fields: dict[str, str] = {}
        if first.get("malware_printable"):
            fields["Malware"] = str(first["malware_printable"])
        if first.get("threat_type"):
            fields["Threat type"] = str(first["threat_type"])
        if first.get("confidence_level") is not None:
            fields["Confidence"] = f"{first['confidence_level']}%"
        if first.get("first_seen"):
            fields["First seen"] = str(first["first_seen"])
        tags = first.get("tags") or []
        if tags:
            fields["Tags"] = ", ".join(tags[:6])
        fields["IOC entries"] = str(len(items))

        conf = first.get("confidence_level") or 0
        verdict = Verdict.MALICIOUS if conf >= 50 else Verdict.SUSPICIOUS
        return self.result(
            verdict=verdict,
            summary=f"KNOWN IOC · {first.get('malware_printable', 'malware')}",
            fields=fields,
            link=f"https://threatfox.abuse.ch/ioc/",
        )
