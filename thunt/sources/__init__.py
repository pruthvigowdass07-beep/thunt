"""Source registry: instantiate every source and expose the applicable subset."""

from __future__ import annotations

from ..config import Config
from ..models import IndicatorType
from .abuseipdb import AbuseIPDB
from .base import Source
from .crtsh import CrtSh
from .dns import Dns
from .greynoise import GreyNoise
from .ipapi import IpApi
from .malwarebazaar import MalwareBazaar
from .otx import Otx
from .proxycheck import ProxyCheck
from .rdap import Rdap
from .shodan_internetdb import ShodanInternetDB
from .talos import Talos
from .threatfox import ThreatFox
from .tor import Tor
from .urlhaus import UrlHaus
from .virustotal import VirusTotal

# Order here is the default render order (roughly: identity/context first, then reputation).
ALL_SOURCES: list[Source] = [
    Rdap(),
    Dns(),
    IpApi(),
    ShodanInternetDB(),
    CrtSh(),
    ProxyCheck(),
    Tor(),
    GreyNoise(),
    AbuseIPDB(),
    Talos(),
    VirusTotal(),
    Otx(),
    MalwareBazaar(),
    UrlHaus(),
    ThreatFox(),
]


def by_name() -> dict[str, Source]:
    return {s.name: s for s in ALL_SOURCES}


def applicable(itype: IndicatorType, cfg: Config, only: set[str] | None = None) -> list[Source]:
    out = []
    for s in ALL_SOURCES:
        if only is not None and s.name not in only:
            continue
        if s.applicable(itype, cfg):
            out.append(s)
    return out


def gated(itype: IndicatorType, cfg: Config) -> list[tuple[Source, str]]:
    """Sources that could apply to this indicator type but are gated off, with reason.

    Used to hint the user about free keys / scraping they could enable.
    """
    hints = []
    for s in ALL_SOURCES:
        if itype not in s.supports:
            continue
        if s.applicable(itype, cfg):
            continue
        if s.requires_key and not cfg.has(s.requires_key):
            hints.append((s, f"needs {s.requires_key}"))
        elif s.needs_scrape and not cfg.allow_scrape:
            hints.append((s, "needs --scrape"))
    return hints
