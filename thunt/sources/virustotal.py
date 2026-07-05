"""VirusTotal v3 - detection stats + community comments.

Needs a free-tier API key (4 lookups/min). Fetches the analysis stats (how many AV
engines flag it), reputation, creation/first-seen dates, AND the community comments
that the user specifically asked for (a second /comments call).
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from ..config import Config
from ..indicators import host_of
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json


def _collection(itype: IndicatorType) -> str:
    if itype.is_ip:
        return "ip_addresses"
    if itype.is_hash:
        return "files"
    return "domains"


def _fmt_ts(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return str(ts)


class VirusTotal(Source):
    name = "virustotal"
    supports = (
        IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN,
        IndicatorType.URL, IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256,
    )
    requires_key = "virustotal_key"

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        collection = _collection(itype)
        ident = value if itype.is_hash else host_of(itype, value)
        headers = {"x-apikey": cfg.virustotal_key}
        base = f"https://www.virustotal.com/api/v3/{collection}/{ident}"

        data, err = await get_json(client, base, headers=headers)
        if err == "404":
            return self.skip("not seen by VirusTotal")
        if err:
            return self.error(err)
        if not data or "data" not in data:
            return self.skip()
        attr = data["data"].get("attributes", {})

        stats = attr.get("last_analysis_stats", {}) or {}
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = mal + susp + harmless + undetected

        fields: dict[str, str] = {}
        if total:
            fields["Detections"] = f"{mal + susp}/{total} engines flag it"
        if attr.get("reputation") is not None:
            fields["Reputation"] = str(attr["reputation"])
        # "When was it created / first seen"
        for key, label in (
            ("creation_date", "Created"),
            ("first_submission_date", "First seen"),
            ("last_analysis_date", "Last analysed"),
        ):
            if attr.get(key):
                fields[label] = _fmt_ts(attr[key])
        if attr.get("meaningful_name"):
            fields["Name"] = str(attr["meaningful_name"])
        if attr.get("type_description"):
            fields["File type"] = str(attr["type_description"])
        popular = attr.get("popular_threat_classification", {})
        if popular.get("suggested_threat_label"):
            fields["Threat label"] = str(popular["suggested_threat_label"])

        if mal >= 3:
            verdict = Verdict.MALICIOUS
        elif mal or susp:
            verdict = Verdict.SUSPICIOUS
        elif total:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN
        summary = f"{mal + susp}/{total} engines flag it" if total else "no analysis"

        # Second call: community comments (what the user explicitly asked for).
        notes: list[str] = []
        cdata, cerr = await get_json(
            client, f"{base}/comments", headers=headers, params={"limit": 10}
        )
        if not cerr and cdata:
            for c in cdata.get("data", []):
                text = (c.get("attributes", {}).get("text") or "").strip().replace("\n", " ")
                votes = c.get("attributes", {}).get("votes", {})
                if text:
                    tag = ""
                    if votes.get("negative"):
                        tag = f"[-{votes['negative']}] "
                    notes.append((tag + text)[:280])

        gui_kind = {"files": "file", "ip_addresses": "ip-address", "domains": "domain"}[collection]
        link = f"https://www.virustotal.com/gui/{gui_kind}/{ident}"
        return self.result(verdict=verdict, summary=summary, fields=fields, notes=notes, link=link)
