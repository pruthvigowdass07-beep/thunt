"""thunt command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.table import Table

from . import __version__, config, render
from .engine import investigate
from .indicators import detect
from .models import IndicatorType


def _setup_encoding() -> bool:
    """Make stdout UTF-8 where possible and report whether emoji are safe to print.

    Windows legacy consoles use cp1252 and cannot encode emoji; reconfiguring to
    UTF-8 fixes modern terminals, and the return value drives an ASCII fallback for
    the rest.
    """
    ok = True
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            ok = False
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    if "utf" not in enc:
        ok = False
    if ok:
        try:
            "🟢".encode(sys.stdout.encoding)
        except Exception:
            ok = False
    return ok


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="thunt",
        description="Unified terminal threat-hunting tool - enrich an IP, domain, "
        "URL, or file hash from many free intel sources at once.",
        epilog="Examples:\n"
        "  thunt 8.8.8.8\n"
        "  thunt evil-domain.com\n"
        "  thunt 44d88612fea8a8f36de82e1278abb02f\n"
        "  thunt 1.2.3.4 --scrape --json\n"
        "  thunt config set virustotal_key <KEY>\n"
        "  thunt config show",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("indicator", nargs="?", help="IP, domain, URL, or file hash (MD5/SHA1/SHA256)")
    p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    p.add_argument("--scrape", action="store_true",
                   help="enable best-effort Playwright scraping (Talos); needs 'thunt[scrape]'")
    p.add_argument("--only", metavar="A,B", help="query only these sources (comma-separated)")
    p.add_argument("--timeout", type=float, default=20.0, help="per-source timeout seconds (default 20)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"thunt {__version__}")
    p.add_argument("--list-sources", action="store_true", help="list all sources and exit")
    return p


def _cmd_config(argv: list[str], console: Console) -> int:
    """`thunt config [show|set <key> <value>|path]`."""
    action = argv[0] if argv else "show"
    if action in ("show", "list"):
        cfg = config.load()
        table = Table(title="thunt config (free-tier keys, all optional)")
        table.add_column("key", style="cyan")
        table.add_column("env var", style="grey62")
        table.add_column("status")
        for name in config.key_field_names():
            has = bool(getattr(cfg, name, None))
            table.add_row(
                name, config.env_name_for(name),
                "[green]set[/green]" if has else "[grey50]not set[/grey50]",
            )
        console.print(table)
        console.print(f"\nConfig file: [blue]{config.config_path()}[/blue]")
        console.print(
            "Get free keys: VirusTotal virustotal.com/gui/join-us · "
            "AbuseIPDB abuseipdb.com/register · OTX otx.alienvault.com · "
            "abuse.ch auth.abuse.ch"
        )
        return 0
    if action == "path":
        console.print(str(config.config_path()))
        return 0
    if action == "set":
        if len(argv) < 3:
            console.print("[red]usage:[/red] thunt config set <key> <value>")
            console.print("keys: " + ", ".join(config.key_field_names()))
            return 2
        key, value = argv[1], argv[2]
        try:
            path = config.save_key(key, value)
        except KeyError:
            console.print(f"[red]unknown key '{key}'.[/red] valid: " + ", ".join(config.key_field_names()))
            return 2
        console.print(f"[green]saved[/green] {key} -> {path}")
        return 0
    console.print(f"[red]unknown config command '{action}'.[/red] try: show | set | path")
    return 2


async def _run(args, console: Console) -> int:
    itype, value = detect(args.indicator)
    if itype == IndicatorType.UNKNOWN:
        console.print(f"[red]Could not classify indicator:[/red] {args.indicator!r}")
        console.print("Expected an IP, domain, URL, or MD5/SHA1/SHA256 hash.")
        return 2

    cfg = config.load()
    cfg.allow_scrape = args.scrape
    cfg.timeout = args.timeout
    only = {s.strip() for s in args.only.split(",")} if args.only else None

    if not args.json:
        console.print(f"[grey62]Investigating[/grey62] [bold]{value}[/bold] "
                      f"[grey62]as {itype.value}…[/grey62]")

    report = await investigate(itype, value, cfg, only)

    if args.json:
        print(render.to_json(report))
    else:
        render.render(report, console)
    # Exit code reflects severity for scripting: 0 clean/unknown, 1 suspicious, 2 malicious.
    from .models import Verdict
    return {Verdict.MALICIOUS: 2, Verdict.SUSPICIOUS: 1}.get(report.overall, 0)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    use_emoji = _setup_encoding()
    render.USE_EMOJI = use_emoji

    # Subcommand: config (handled before argparse so it can take its own args).
    if argv and argv[0] == "config":
        return _cmd_config(argv[1:], Console(emoji=False))

    parser = _build_parser()
    args = parser.parse_args(argv)
    console = Console(no_color=args.no_color, highlight=False, emoji=False)

    if args.list_sources:
        from . import sources as sources_mod
        table = Table(title="thunt sources")
        table.add_column("source", style="cyan")
        table.add_column("indicator types")
        table.add_column("requirement", style="grey62")
        for s in sources_mod.ALL_SOURCES:
            types = ", ".join(t.value for t in s.supports)
            req = "free" if not s.requires_key and not s.needs_scrape else (
                f"key: {s.requires_key}" if s.requires_key else "scrape")
            table.add_row(s.name, types, req)
        console.print(table)
        return 0

    if not args.indicator:
        parser.print_help()
        return 0

    try:
        return asyncio.run(_run(args, console))
    except KeyboardInterrupt:
        console.print("\n[grey62]interrupted[/grey62]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
