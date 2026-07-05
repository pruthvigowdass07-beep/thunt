"""Rich rendering: color-coded verdict banner + per-source panels + JSON output."""

from __future__ import annotations

import json as _json
import re
from dataclasses import asdict

from rich import box
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
    return "💬 " if USE_EMOJI else ""


def _fields_table(fields: dict[str, str]) -> Table:
    # A grid sizes the label column to its content, so values sit right beside the
    # keys instead of across a wide gap.
    t = Table.grid(padding=(0, 2))
    t.add_column(style="cyan", no_wrap=True, justify="left")
    t.add_column(style="white", overflow="fold")
    for k, v in fields.items():
        t.add_row(k, str(v))
    return t


_URL_RE = re.compile(r"https?://\S+")


def _note_body(text: str, accent: str) -> Text:
    """Render one comment in full, tinting any URLs so links stand out."""
    clean = re.sub(r"\s+", " ", str(text)).strip()
    body = Text(overflow="fold")
    pos = 0
    for m in _URL_RE.finditer(clean):
        if m.start() > pos:
            body.append(clean[pos:m.start()], style="grey82")
        body.append(m.group(0), style="blue underline")
        pos = m.end()
    if pos < len(clean):
        body.append(clean[pos:], style="grey82")
    return body


def _notes_group(notes: list[str], accent: str) -> Group:
    header = Text(f"{_note_icon()}community / intel notes ({len(notes)})", style="bold grey74")
    # One row per comment with horizontal rules between them: full text, clearly
    # separated, nothing hidden behind a link.
    tbl = Table(box=box.HORIZONTALS, show_header=False, expand=True, padding=(0, 1),
                border_style="grey30", show_edge=False, show_lines=True)
    tbl.add_column("n", style=f"bold {accent}", no_wrap=True, justify="right", width=2)
    tbl.add_column("body", overflow="fold")
    for i, n in enumerate(notes, 1):
        tbl.add_row(str(i), _note_body(n, accent))
    return Group(Text(""), header, tbl)


def _source_panel(r: SourceResult) -> Panel:
    if r.error:
        title = Text.assemble((f"{r.source}", "bold grey58"), ("  ✖", "grey37"))
        body = Text(r.error, style="grey37")
        return Panel(body, title=title, title_align="left", border_style="grey37",
                     padding=(0, 1))
    if r.skipped:
        title = Text.assemble((f"{r.source}", "bold grey50"), ("  —", "grey37"))
        body = Text(r.summary or "no data", style="grey37")
        return Panel(body, title=title, title_align="left", border_style="grey30",
                     padding=(0, 1))

    v = r.verdict
    title = Text.assemble(
        (f"{_sym(v)} {r.source} ", f"bold {v.color}"),
        (f" {v.label.upper()} ", f"reverse {v.color}"),
    )
    parts: list = []
    if r.summary:
        parts.append(Text(r.summary, style=f"bold {v.color}"))
    if r.fields:
        parts.append(_fields_table(r.fields))
    if r.notes:
        parts.append(_notes_group(r.notes, v.color))
    if r.link:
        parts.append(Text(""))
        parts.append(Text.assemble(("↗ ", "grey50"), (r.link, "blue underline")))
    return Panel(Group(*parts), title=title, title_align="left", border_style=v.color,
                 padding=(0, 1))


def _banner(report: Report) -> Panel:
    v = report.overall
    headline = Text(overflow="fold")
    headline.append(f" {_sym(v)} {v.label.upper()} ", style=f"reverse bold {v.color}")
    headline.append("  ")
    headline.append(report.indicator, style="bold white")
    headline.append(f"  ({report.itype.value})", style="grey62")

    mal = report.malicious_sources
    susp = report.suspicious_sources
    detail = Text()
    if mal:
        detail.append("\nflagged malicious by  ", style="grey74")
        detail.append(", ".join(mal), style="bold red")
    if susp:
        detail.append("\nflagged suspicious by ", style="grey74")
        detail.append(", ".join(susp), style="yellow")
    if not mal and not susp:
        detail.append("\nno source flagged this indicator", style="green")

    return Panel(
        Group(headline, detail),
        border_style=v.color,
        title="thunt · threat verdict",
        title_align="left",
        padding=(0, 1),
    )


def render(report: Report, console: Console) -> None:
    console.print(_banner(report))

    # Order panels so the sources that actually flagged something come first, then
    # informational, then errors/skips - most useful at the top.
    def _rank(r: SourceResult) -> int:
        if r.error:
            return 3
        if r.skipped:
            return 2
        if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            return 0
        return 1

    ordered = sorted(report.results, key=_rank)
    if ordered:
        for r in ordered:
            console.print(_source_panel(r))
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
