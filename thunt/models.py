"""Core data types shared across the tool: indicator kinds, verdicts, and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"

    @property
    def is_ip(self) -> bool:
        return self in (IndicatorType.IPV4, IndicatorType.IPV6)

    @property
    def is_hash(self) -> bool:
        return self in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256)

    @property
    def is_host(self) -> bool:
        """Domain or URL - things that resolve to a name/host."""
        return self in (IndicatorType.DOMAIN, IndicatorType.URL)


class Verdict(Enum):
    """Normalized verdict for a single source, ordered by severity."""

    MALICIOUS = 4
    SUSPICIOUS = 3
    UNKNOWN = 2
    CLEAN = 1
    ERROR = 0

    @property
    def color(self) -> str:
        return {
            Verdict.MALICIOUS: "bold red",
            Verdict.SUSPICIOUS: "yellow",
            Verdict.UNKNOWN: "grey62",
            Verdict.CLEAN: "green",
            Verdict.ERROR: "grey37",
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Verdict.MALICIOUS: "🔴",
            Verdict.SUSPICIOUS: "🟡",
            Verdict.UNKNOWN: "⚪",
            Verdict.CLEAN: "🟢",
            Verdict.ERROR: "✖",
        }[self]

    @property
    def marker(self) -> str:
        """ASCII fallback for consoles that can't render emoji."""
        return {
            Verdict.MALICIOUS: "[MAL]",
            Verdict.SUSPICIOUS: "[SUS]",
            Verdict.UNKNOWN: "[ ? ]",
            Verdict.CLEAN: "[OK ]",
            Verdict.ERROR: "[ x ]",
        }[self]

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class SourceResult:
    """What a single intel source reports about one indicator."""

    source: str
    verdict: Verdict = Verdict.UNKNOWN
    summary: str = ""
    # Ordered key -> value details rendered as a small table in the source panel.
    fields: dict[str, str] = field(default_factory=dict)
    # Free-text notes (e.g. VirusTotal community comments, sandbox tags).
    notes: list[str] = field(default_factory=list)
    # A pivot URL a human can open to dig deeper.
    link: Optional[str] = None
    error: Optional[str] = None
    # True when the source has no data / was not applicable (rendered muted).
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and not self.skipped
