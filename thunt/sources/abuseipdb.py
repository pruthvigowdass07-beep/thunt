"""AbuseIPDB - IP abuse reports. Needs a free-tier API key (1000 checks/day)."""

from __future__ import annotations

import httpx

from ..config import Config
from ..models import IndicatorType, SourceResult, Verdict
from .base import Source, get_json


class AbuseIPDB(Source):
    name = "abuseipdb"
    supports = (IndicatorType.IPV4, IndicatorType.IPV6)
    requires_key = "abuseipdb_key"

    async def fetch(
        self, client: httpx.AsyncClient, itype: IndicatorType, value: str, cfg: Config
    ) -> SourceResult:
        data, err = await get_json(
            client,
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": cfg.abuseipdb_key, "Accept": "application/json"},
        )
        if err:
            return self.error(err)
        if not data or "data" not in data:
            return self.skip()
        d = data["data"]

        score = int(d.get("abuseConfidenceScore", 0))
        reports = d.get("totalReports", 0)
        fields: dict[str, str] = {"Abuse score": f"{score}%", "Reports": str(reports)}
        if d.get("countryCode"):
            fields["Country"] = str(d["countryCode"])
        if d.get("isp"):
            fields["ISP"] = str(d["isp"])
        if d.get("usageType"):
            fields["Usage"] = str(d["usageType"])
        if d.get("domain"):
            fields["Domain"] = str(d["domain"])
        if d.get("isTor"):
            fields["Tor exit"] = "yes"
        if d.get("lastReportedAt"):
            fields["Last report"] = str(d["lastReportedAt"]).split("T")[0]

        if score >= 50:
            verdict = Verdict.MALICIOUS
        elif score >= 15 or reports:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN
        return self.result(
            verdict=verdict,
            summary=f"abuse score {score}% ({reports} reports)",
            fields=fields,
            link=f"https://www.abuseipdb.com/check/{value}",
        )
