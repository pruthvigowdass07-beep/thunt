"""crt.sh - free, no-key certificate transparency lookup.

Gives an earliest-certificate date (a useful proxy for how long a domain has been
active/observed) and discovered subdomains.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import get_json
from .base import Source
from ..indicators import host_of


class CrtSh(Source):
    name = "crt.sh"
    supports = (IndicatorType.DOMAIN, IndicatorType.URL)

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        host = host_of(itype, value)
        url = f"https://crt.sh/?q={host}&output=json"
        data, err = await get_json(client, url)
        if err:
            return self.error(err)
        if not data:
            return self.skip("no certificates")

        # data is a list of cert entries.
        entries = data if isinstance(data, list) else []
        if not entries:
            return self.skip("no certificates")

        earliest = None
        subdomains: set[str] = set()
        for e in entries:
            nb = e.get("not_before")
            if nb and (earliest is None or nb < earliest):
                earliest = nb
            for name in (e.get("name_value") or "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name and name.endswith(host):
                    subdomains.add(name)

        fields: dict[str, str] = {"Certificates": str(len(entries))}
        if earliest:
            fields["Earliest cert"] = earliest.split("T")[0]
        extra = sorted(s for s in subdomains if s != host)
        if extra:
            shown = ", ".join(extra[:8])
            if len(extra) > 8:
                shown += f" (+{len(extra) - 8} more)"
            fields["Subdomains"] = shown

        return self.result(
            verdict=Verdict.UNKNOWN,
            summary=f"{len(entries)} certs, {len(extra)} subdomains",
            fields=fields,
            link=f"https://crt.sh/?q={host}",
        )
