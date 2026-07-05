"""RDAP (whois successor) - free, no-key registration data.

For a domain this answers "when was it created" (registration event) plus registrar
and status. For an IP it gives the network allocation and owner.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from ..config import Config
from ..indicators import host_of
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json


def _event(events, action: str):
    for e in events or []:
        if e.get("eventAction") == action:
            return e.get("eventDate")
    return None


def _age_days(iso: str):
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


class Rdap(Source):
    name = "rdap/whois"
    supports = (IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.IPV4, IndicatorType.IPV6)

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        if itype.is_ip:
            return await self._ip(client, value)
        return await self._domain(client, host_of(itype, value))

    async def _domain(self, client, domain):
        data, err = await get_json(client, f"https://rdap.org/domain/{domain}")
        if err == "404":
            return self.skip("domain not registered / no RDAP")
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        events = data.get("events")
        created = _event(events, "registration")
        expires = _event(events, "expiration")
        updated = _event(events, "last changed")

        registrar = None
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for item in vcard[1]:
                        if isinstance(item, list) and item and item[0] == "fn":
                            registrar = item[3]
                            break

        fields: dict[str, str] = {}
        verdict = Verdict.UNKNOWN
        summary = "registered"
        if created:
            day = created.split("T")[0]
            age = _age_days(created)
            if age is not None:
                fields["Created"] = f"{day} ({age} days ago)"
                # Freshly-registered domains are a classic phishing/malware signal.
                if age < 30:
                    verdict = Verdict.SUSPICIOUS
                    summary = f"NEWLY REGISTERED {age}d ago"
                else:
                    summary = f"registered {day}"
            else:
                fields["Created"] = day
        if updated:
            fields["Updated"] = updated.split("T")[0]
        if expires:
            fields["Expires"] = expires.split("T")[0]
        if registrar:
            fields["Registrar"] = registrar
        statuses = data.get("status") or []
        if statuses:
            fields["Status"] = ", ".join(statuses[:4])

        return self.result(verdict=verdict, summary=summary, fields=fields)

    async def _ip(self, client, ip):
        data, err = await get_json(client, f"https://rdap.org/ip/{ip}")
        if err == "404":
            return self.skip("no allocation data")
        if err:
            return self.error(err)
        if not data:
            return self.skip()

        fields: dict[str, str] = {}
        if data.get("name"):
            fields["Network"] = str(data["name"])
        if data.get("handle"):
            fields["Handle"] = str(data["handle"])
        if data.get("startAddress") and data.get("endAddress"):
            fields["Range"] = f"{data['startAddress']} - {data['endAddress']}"
        if data.get("country"):
            fields["Country"] = str(data["country"])
        registered = _event(data.get("events"), "registration")
        if registered:
            fields["Allocated"] = registered.split("T")[0]
        org = None
        for ent in data.get("entities", []):
            if "registrant" in ent.get("roles", []) or "administrative" in ent.get("roles", []):
                vcard = ent.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for item in vcard[1]:
                        if isinstance(item, list) and item and item[0] == "fn":
                            org = item[3]
                            break
            if org:
                break
        if org:
            fields["Owner"] = org

        return self.result(
            verdict=Verdict.UNKNOWN,
            summary=fields.get("Network", "allocated"),
            fields=fields,
        )
