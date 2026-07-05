"""Rich rendering: color-coded verdict banner + per-source panels + JSON output."""

from __future__ import annotations

import json as _json
from dataclasses import asdict

from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .engine import Report
from .models import SourceResult, Verdict

# Set by the CLI once it knows whether the output stream can encode emoji.
USE_EMOJI = True


def _sym(v: Verdict) -> str:
    return v.emoji if USE_EMOJI else v.marker


def _note_icon() -> str:
    return "💬 " if USE_EMOJI else "* "


def _fields_table(fields: dict[str, str]) -> Table:
    t = Table(show_header=False, box=None, pad_edge=False, expand=True)
    t.add_column("k", style="bold cyan", no_wrap=True, ratio=1)
    t.add_column("v", style="white", ratio=3, overflow="fold")
    for k, v in fields.items():
        t.add_row(k, str(v))
    return t


def _source_panel(r: SourceResult) -> Panel:
    if r.error:
        title = Text.assemble((f"{r.source}", "bold"), ("  ✖", "grey37"))
        body = Text(r.error, style="grey37")
        return Panel(body, title=title, title_align="left", border_style="grey37")
    if r.skipped:
        title = Text.assemble((f"{r.source}", "bold grey50"))
        body = Text(r.summary or "no data", style="grey37")
        return Panel(body, title=title, title_align="left", border_style="grey30")

    v = r.verdict
    title = Text.assemble(
        (f"{_sym(v)} {r.source}", f"bold {v.color}"),
        ("  ", ""),
        (v.label.upper(), v.color),
    )
    parts = []
    if r.summary:
        parts.append(Text(r.summary, style=v.color))
    if r.fields:
        parts.append(_fields_table(r.fields))
    if r.notes:
        notes_tbl = Table(show_header=True, box=None, pad_edge=False, expand=True)
        notes_tbl.add_column(f"{_note_icon()}community / intel notes", style="italic grey74", overflow="fold")
        for n in r.notes:
            notes_tbl.add_row(n)
        parts.append(notes_tbl)
    if r.link:
        parts.append(Text(r.link, style="blue underline"))
    return Panel(Group(*parts), title=title, title_align="left", border_style=v.color)


def _banner(report: Report) -> Panel:
    v = report.overall
    headline = Text()
    headline.append(f"{_sym(v)}  ", style="bold")
    headline.append(report.indicator, style="bold white")
    headline.append(f"   [{report.itype.value}]", style="grey62")
    headline.append("\n")
    headline.append(f"{v.label.upper()}", style=f"bold {v.color}")

    mal = report.malicious_sources
    susp = report.suspicious_sources
    detail = Text()
    if mal:
        detail.append("\nMalicious per: ", style="grey74")
        detail.append(", ".join(mal), style="bold red")
    if susp:
        detail.append("\nSuspicious per: ", style="grey74")
        detail.append(", ".join(susp), style="yellow")
    if not mal and not susp:
        detail.append("\nNo source flagged this indicator.", style="green")

    return Panel(
        Group(headline, detail),
        border_style=v.color,
        title="thunt · threat verdict",
        title_align="left",
    )


def render(report: Report, console: Console) -> None:
    console.print(_banner(report))

    panels = [_source_panel(r) for r in report.results]
    if panels:
        console.print(Columns(panels, equal=False, expand=True, column_first=True))
    else:
        console.print(Text("No sources returned data for this indicator.", style="grey62"))

    if report.gated:
        hint = Text("\nEnable more sources: ", style="grey62")
        hint.append(
            ", ".join(f"{name} ({why})" for name, why in report.gated), style="grey50"
        )
        hint.append("\nRun `thunt config` to add free keys, or `--scrape` for Talos.", style="grey50")
        console.print(hint)


def to_json(report: Report) -> str:
    payload = {
        "indicator": report.indicator,
        "type": report.itype.value,
        "verdict": report.overall.label,
        "malicious_sources": report.malicious_sources,
        "suspicious_sources": report.suspicious_sources,
        "sources": [],
    }
    for r in report.results:
        d = asdict(r)
        d["verdict"] = r.verdict.label
        d.pop("skipped", None)
        payload["sources"].append(d)
    payload["gated"] = [{"source": n, "reason": w} for n, w in report.gated]
    return _json.dumps(payload, indent=2)
