"""URLhaus (abuse.ch) - malicious URL / host / payload database.

Uses the free abuse.ch Auth-Key when configured. For a host or IP it reports how many
malware-distribution URLs abuse.ch has seen there; for a hash it reports the payload.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..indicators import host_of
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, post_json

_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
_PAYLOAD = "https://urlhaus-api.abuse.ch/v1/payload/"


class UrlHaus(Source):
    name = "urlhaus"
    supports = (
        IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.IPV4,
        IndicatorType.MD5, IndicatorType.SHA256,
    )

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        headers = {}
        if cfg.abusech_key:
            headers["Auth-Key"] = cfg.abusech_key

        if itype.is_hash:
            key = "sha256_hash" if itype == IndicatorType.SHA256 else "md5_hash"
            data, err = await post_json(client, _PAYLOAD, data={key: value}, headers=headers)
        else:
            host = host_of(itype, value)
            data, err = await post_json(client, _HOST, data={"host": host}, headers=headers)

        if err == "401":
            return self.error("needs free abuse.ch Auth-Key (thunt config set abusech_key)")
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        status = data.get("query_status")
        if status in ("no_results", "not_found"):
            return self.skip("not in URLhaus")
        if status in ("unauthorized", "unauthenticated", "no_auth_key"):
            return self.error("needs free abuse.ch Auth-Key (thunt config set abusech_key)")
        if status != "ok":
            return self.skip(status or "no data")

        fields: dict[str, str] = {}
        if itype.is_hash:
            if data.get("signature"):
                fields["Signature"] = str(data["signature"])
            if data.get("file_type"):
                fields["File type"] = str(data["file_type"])
            if data.get("firstseen"):
                fields["First seen"] = str(data["firstseen"])
            urls = data.get("urls") or []
            fields["Distributing URLs"] = str(len(urls))
            summary = f"malware payload · {data.get('signature') or 'unknown family'}"
        else:
            urls = data.get("urls") or []
            online = [u for u in urls if u.get("url_status") == "online"]
            if data.get("firstseen"):
                fields["First seen"] = str(data["firstseen"])
            fields["Malicious URLs"] = f"{len(urls)} ({len(online)} online)"
            threats = sorted({u.get("threat", "") for u in urls if u.get("threat")})
            if threats:
                fields["Threats"] = ", ".join(threats[:5])
            summary = f"{len(urls)} malicious URLs hosted here"

        return self.result(
            verdict=Verdict.MALICIOUS, summary=summary, fields=fields,
            link=data.get("urlhaus_reference"),
        )
