"""Best-effort Playwright scraping for sources with no free API (Cisco Talos).

Kept isolated so the core tool has zero heavy dependencies. Everything here degrades
gracefully: if Playwright (or its browser) is not installed, callers get a clear
message telling them how to enable it, never a crash.
"""

from __future__ import annotations

import asyncio
from typing import Optional


class ScrapeUnavailable(RuntimeError):
    """Raised when Playwright or its browser binary is not installed."""


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def _render_text(url: str, wait_selector: Optional[str], timeout_ms: int) -> str:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover
        raise ScrapeUnavailable(
            "playwright not installed - run: pipx install 'thunt[scrape]' && playwright install chromium"
        ) from exc

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True)
        except Exception as exc:  # browser binary missing
            raise ScrapeUnavailable(
                "chromium not installed - run: playwright install chromium"
            ) from exc
        try:
            page = await browser.new_page(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
                )
            )
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            if wait_selector:
                try:
                    await page.wait_for_selector(wait_selector, timeout=timeout_ms // 2)
                except Exception:
                    pass
            else:
                await asyncio.sleep(2.0)
            return await page.inner_text("body")
        finally:
            await browser.close()


async def talos_reputation(ip: str, timeout_ms: int = 25000) -> dict:
    """Scrape the Talos reputation center for an IP.

    Returns a dict with any of: email_reputation, web_reputation, owner, network,
    added. Raises ScrapeUnavailable if Playwright isn't set up.
    """
    url = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
    text = await _render_text(url, wait_selector="text=Reputation", timeout_ms=timeout_ms)

    out: dict[str, str] = {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    # Talos renders label/value pairs on adjacent lines; pick out the ones we care about.
    wanted = {
        "email reputation": "Email reputation",
        "web reputation": "Web reputation",
        "owner": "Owner",
        "network owner": "Owner",
        "added to corpus": "Added",
    }
    for i, ln in enumerate(lines):
        low = ln.lower().rstrip(":")
        if low in wanted and i + 1 < len(lines):
            out.setdefault(wanted[low], lines[i + 1])
    return out
