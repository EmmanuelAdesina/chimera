"""
Headless browser execution layer.

This layer is intended for authorized dynamic application observation:
- navigation
- DOM/title/status capture
- optional scoped host enforcement

It deliberately avoids anti-detection bypass behavior.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


class BrowserLayer:
    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        headless: bool = True,
        timeout_ms: int = 30000,
    ) -> None:
        self.allowed_hosts = set(allowed_hosts or [])
        self.headless = headless
        self.timeout_ms = timeout_ms
        self._playwright = None
        self._browser = None

    async def initialize(self) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium") from exc

        if self._playwright is None:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self.headless)

    async def cleanup(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def execute_navigation(self, payload: Dict[str, Any]) -> Evidence:
        url = payload.get("url")
        if not url:
            raise ValueError("browser.navigate requires payload['url']")

        self._enforce_scope(url, payload.get("_scope", {}))
        await self.initialize()

        context = await self._browser.new_context()
        page = await context.new_page()

        try:
            response = await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
            title = await page.title()
            html = await page.content()
            status = response.status if response else 0

            return self._evidence(url, title, status, len(html))
        finally:
            await context.close()

    def _enforce_scope(self, url: str, runtime_scope: Dict[str, Any]) -> None:
        host = urlparse(url).hostname or ""
        allowed = set(self.allowed_hosts)
        allowed.update(runtime_scope.get("allowed_hosts", []) or [])

        if allowed and host not in allowed:
            raise PermissionError(f"Host is outside authorized browser scope: {host}")

    def _evidence(self, url: str, title: str, status: int, html_length: int) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="BrowserLayer",
            action="navigate",
            input_ref=url,
            output_ref=ev_id,
            parameters={"status": status},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.HTTP_RESPONSE,
            data={
                "request": {"method": "GET", "url": url},
                "response": {
                    "status": status,
                    "title": title,
                    "html_length": html_length,
                },
            },
            chain_of_custody=chain,
            confidence=1.0 if status else 0.5,
            description=f"Browser observed {url} with status {status}",
            metadata={"layer": "browser"},
        )
