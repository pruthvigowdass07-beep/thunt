"""Configuration: optional free-tier API keys loaded from a config file or env vars.

Every key is optional. thunt works with zero keys using no-key sources; keys simply
unlock more sources and make Cloudflare/reCAPTCHA-guarded ones reliable.

Precedence (highest first): environment variable, then config file value.
Config file: ~/.config/thunt/config.toml (or %APPDATA%\\thunt\\config.toml on Windows).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Optional

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - 3.9/3.10 fallback
    tomllib = None  # type: ignore


# Maps config field -> environment variable name.
_ENV = {
    "virustotal_key": "VT_API_KEY",
    "abuseipdb_key": "ABUSEIPDB_API_KEY",
    "otx_key": "OTX_API_KEY",
    "abusech_key": "ABUSECH_API_KEY",  # MalwareBazaar / URLhaus / ThreatFox auth key
    "greynoise_key": "GREYNOISE_API_KEY",
    "shodan_key": "SHODAN_API_KEY",
    "proxycheck_key": "PROXYCHECK_API_KEY",  # optional; keyless free tier also works
}


@dataclass
class Config:
    virustotal_key: Optional[str] = None
    abuseipdb_key: Optional[str] = None
    otx_key: Optional[str] = None
    abusech_key: Optional[str] = None
    greynoise_key: Optional[str] = None
    shodan_key: Optional[str] = None
    proxycheck_key: Optional[str] = None
    # Runtime toggles (not persisted) set by the CLI.
    allow_scrape: bool = False
    timeout: float = 20.0

    def has(self, field_name: str) -> bool:
        return bool(getattr(self, field_name, None))


def config_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "thunt"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "thunt"


def config_path() -> Path:
    return config_dir() / "config.toml"


def _read_file() -> dict:
    path = config_path()
    if not path.exists() or tomllib is None:
        return {}
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return {}
    # Accept either a flat table or a [keys] table.
    return {**data, **data.get("keys", {})}


def load() -> Config:
    file_data = _read_file()
    cfg = Config()
    for f in fields(Config):
        if f.name not in _ENV:
            continue
        env_name = _ENV[f.name]
        value = os.environ.get(env_name) or file_data.get(f.name)
        if value:
            setattr(cfg, f.name, str(value).strip())
    return cfg


def save_key(field_name: str, value: str) -> Path:
    """Persist a single key to the config file, preserving other keys."""
    if field_name not in _ENV:
        raise KeyError(f"unknown key '{field_name}'")
    existing = _read_file()
    keys = existing.get("keys", {}) if "keys" in existing else existing
    keys = {k: v for k, v in keys.items() if k in _ENV}
    keys[field_name] = value.strip()
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# thunt config - free-tier API keys (all optional)", "[keys]"]
    for k, v in keys.items():
        lines.append(f'{k} = "{v}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def key_field_names() -> list[str]:
    return list(_ENV.keys())


def env_name_for(field_name: str) -> str:
    return _ENV[field_name]
