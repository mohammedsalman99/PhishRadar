from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from collections import deque
from pathlib import Path
from typing import Any

import httpx

from app.integrations.errors import connection_failure, response_failure


class URLhausClient:
    """Opt-in URLhaus URL lookups with a persistent 24-hour cache."""

    def __init__(self, enabled: bool | None = None, cache_path: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None,
                 request_interval: float | None = None) -> None:
        self.enabled = enabled if enabled is not None else os.getenv("URLHAUS_ENABLED", "").lower() == "true"
        self.cache_path = Path(cache_path or os.getenv("PHISHRADAR_CACHE_DB", "data/reputation-cache.sqlite3"))
        self.transport = transport
        self.request_interval = request_interval if request_interval is not None else float(
            os.getenv("URLHAUS_REQUEST_INTERVAL", "1")
        )
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    def _cached(self, url: str) -> dict[str, Any] | None:
        if not self.cache_path.exists():
            return None
        try:
            with sqlite3.connect(self.cache_path) as connection:
                row = connection.execute(
                    "SELECT result, cached_at FROM urlhaus_cache WHERE url = ?", (url,)
                ).fetchone()
            if row and time.time() - row[1] < 86400:
                return json.loads(row[0])
        except (sqlite3.Error, ValueError, TypeError):
            return None
        return None

    def _store(self, url: str, result: dict[str, Any]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.cache_path) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS urlhaus_cache "
                    "(url TEXT PRIMARY KEY, result TEXT NOT NULL, cached_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT OR REPLACE INTO urlhaus_cache VALUES (?, ?, ?)",
                    (url, json.dumps(result), time.time()),
                )
        except (OSError, sqlite3.Error):
            return

    async def _request_slot(self) -> None:
        async with self._lock:
            if self._timestamps:
                elapsed = time.monotonic() - self._timestamps[-1]
                if elapsed < self.request_interval:
                    await asyncio.sleep(self.request_interval - elapsed)
            self._timestamps.append(time.monotonic())

    async def lookup(self, url: str) -> dict[str, Any] | None:
        if not self.enabled:
            return {"status": "disabled"}
        cached = self._cached(url)
        if cached is not None:
            return cached

        await self._request_slot()
        try:
            async with httpx.AsyncClient(timeout=8, transport=self.transport) as client:
                response = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": url},
                    headers={"Accept": "application/json"},
                )
            response.raise_for_status()
            payload = response.json()
            query_status = payload.get("query_status")
            result = {
                "status": "found" if query_status == "ok" else "not_found",
                "query_status": query_status,
                "url_status": payload.get("url_status"),
                "threat": payload.get("threat"),
                "tags": payload.get("tags") or [],
                "urlhaus_link": payload.get("urlhaus_reference") or payload.get("urlhaus_link"),
            }
            self._store(url, result)
            return result
        except httpx.HTTPStatusError as exc:
            return {"status": "unavailable", "error_code": f"http_{exc.response.status_code}",
                    "error_message": f"URLhaus returned HTTP {exc.response.status_code}. No reputation verdict was received."}
        except (httpx.TimeoutException, httpx.RequestError, OSError):
            return connection_failure("URLhaus")
        except (ValueError, TypeError, AttributeError):
            return response_failure("URLhaus")