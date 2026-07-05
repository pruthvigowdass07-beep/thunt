"""Tor network detection via the Tor Project's onionoo API - free, no key.

Authoritatively answers whether an IP is a Tor relay or exit node, and if so gives
the relay nickname and when it was first seen on the network.
"""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json


class Tor(Source):
    name = "tor"
    supports = (IndicatorType.IPV4, IndicatorType.IPV6)

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        data, err = await get_json(
            client,
            "https://onionoo.torproject.org/details",
            params={
                "search": value,
                "fields": "nickname,or_addresses,exit_addresses,flags,first_seen,running",
            },
        )
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        relays = data.get("relays") or []
        # onionoo `search` can match loosely; confirm the IP really is a relay address.
        def _has_ip(relay) -> bool:
            addrs = [a.split(":")[0] for a in relay.get("or_addresses", [])]
            addrs += relay.get("exit_addresses", [])
            return value in addrs

        matches = [r for r in relays if _has_ip(r)] or relays
        if not matches:
            return self.skip("not a Tor node")

        relay = matches[0]
        flags = relay.get("flags", []) or []
        is_exit = "Exit" in flags or bool(relay.get("exit_addresses"))

        fields: dict[str, str] = {}
        if relay.get("nickname"):
            fields["Nickname"] = str(relay["nickname"])
        fields["Role"] = "exit node" if is_exit else "relay/guard"
        if flags:
            fields["Flags"] = ", ".join(flags[:6])
        if relay.get("first_seen"):
            fields["First seen"] = str(relay["first_seen"]).split(" ")[0]
        fields["Running"] = "yes" if relay.get("running") else "no"
        if len(matches) > 1:
            fields["Relays at IP"] = str(len(matches))

        # An exit node touching your environment is more notable than a middle relay.
        verdict = Verdict.SUSPICIOUS if is_exit else Verdict.UNKNOWN
        summary = "TOR EXIT NODE" if is_exit else "Tor relay"
        return self.result(
            verdict=verdict, summary=summary, fields=fields,
            link=f"https://metrics.torproject.org/rs.html#search/{value}",
        )
