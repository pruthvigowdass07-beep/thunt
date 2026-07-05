"""Detect what kind of indicator a raw string is (IP / domain / URL / hash)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .models import IndicatorType

_HASH_RE = {
    IndicatorType.MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IndicatorType.SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IndicatorType.SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
}

# Deliberately permissive: labels of 1-63 chars, at least one dot, a TLD of >=2 letters.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


def _defang(value: str) -> str:
    """Undo common IOC defanging so pasted indicators just work."""
    value = value.strip().strip("\"'<>()[] \t\r\n")
    replacements = {
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[dot]": ".",
        "(dot)": ".",
        " dot ": ".",
        "[:]": ":",
        "hxxps://": "https://",
        "hxxp://": "http://",
        "hxxps:\\\\": "https://",
        "hxxp:\\\\": "http://",
        "[//]": "//",
    }
    lower_map = {k.lower(): v for k, v in replacements.items()}
    # Replace case-insensitively for the schema tokens, literally for the rest.
    for token, repl in replacements.items():
        value = value.replace(token, repl)
    for token, repl in lower_map.items():
        value = re.sub(re.escape(token), repl, value, flags=re.IGNORECASE)
    return value.strip()


def detect(raw: str) -> tuple[IndicatorType, str]:
    """Return (type, normalized_value) for a raw indicator string.

    normalized_value is lowercased for hosts/hashes and stripped of defanging.
    """
    value = _defang(raw)

    # Hash first - unambiguous by length + charset.
    for kind, pattern in _HASH_RE.items():
        if pattern.match(value):
            return kind, value.lower()

    # URL - has a scheme.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        host = urlparse(value).hostname or ""
        # A URL whose host is a bare IP still reads as a URL for querying purposes.
        if host:
            return IndicatorType.URL, value
        return IndicatorType.UNKNOWN, value

    # IP address.
    try:
        ip = ipaddress.ip_address(value)
        return (
            IndicatorType.IPV4 if ip.version == 4 else IndicatorType.IPV6,
            str(ip),
        )
    except ValueError:
        pass

    # Domain.
    if _DOMAIN_RE.match(value):
        return IndicatorType.DOMAIN, value.lower()

    return IndicatorType.UNKNOWN, value


def host_of(itype: IndicatorType, value: str) -> str:
    """Extract the hostname/domain from a URL, or return the value unchanged."""
    if itype == IndicatorType.URL:
        return (urlparse(value).hostname or value).lower()
    return value
