from __future__ import annotations

import asyncio
import base64
import os
import sqlite3
import time
from collections import deque
from pathlib import Path
from typing import Any

import httpx

from app.integrations.errors import api_failure, connection_failure, response_failure


class VirusTotalClient:
    """VirusTotal v3 lookups with a persistent TTL cache and a 4/minute limit."""

    def __init__(self, api_key: str | None = None, cache_path: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")
        self.cache_path = Path(cache_path or os.getenv("PHISHRADAR_CACHE_DB", "data/reputation-cache.sqlite3"))
        self.transport = transport
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    def _cached(self, indicator: str) -> dict[str, Any] | None:
        if not self.cache_path.exists():
            return None
        try:
            with sqlite3.connect(self.cache_path) as connection:
                row = connection.execute("SELECT result, cached_at FROM reputation WHERE indicator = ?", (indicator,)).fetchone()
            if row and time.time() - row[1] < 86400:
                import json
                return json.loads(row[0])
        except sqlite3.Error:
            return None
        return None

    def _store(self, indicator: str, result: dict[str, Any]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.cache_path) as connection:
                connection.execute("CREATE TABLE IF NOT EXISTS reputation (indicator TEXT PRIMARY KEY, result TEXT NOT NULL, cached_at REAL NOT NULL)")
                import json
                connection.execute("INSERT OR REPLACE INTO reputation VALUES (?, ?, ?)", (indicator, json.dumps(result), time.time()))
        except (OSError, sqlite3.Error):
            return

    async def lookup(self, kind: str, value: str) -> dict[str, Any] | None:
        if not self.api_key:
            return None
        cache_key = f"{kind}:{value}"
        cached = self._cached(cache_key)
        if cached is not None:
            return cached
        if kind == "url":
            encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            endpoint = f"urls/{encoded}"
        elif kind == "ip":
            endpoint = f"ip_addresses/{value}"
        elif kind == "file":
            endpoint = f"files/{value}"
        else:
            return None
        try:
            async with self._lock:
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] >= 60:
                    self._timestamps.popleft()
                if len(self._timestamps) >= 4:
                    await asyncio.sleep(max(0.0, 60 - (now - self._timestamps[0])))
                    now = time.monotonic()
                    while self._timestamps and now - self._timestamps[0] >= 60:
                        self._timestamps.popleft()
                self._timestamps.append(time.monotonic())
            async with httpx.AsyncClient(timeout=8, transport=self.transport) as client:
                response = await client.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.api_key})
            if response.status_code == 404:
                result = {"status": "not_found", "malicious": 0, "suspicious": 0}
            else:
                response.raise_for_status()
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result = {"status": "found", "malicious": stats.get("malicious", 0),
                          "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0)}
            self._store(cache_key, result)
            return result
        except httpx.HTTPStatusError as exc:
            return {**api_failure("VirusTotal", "VIRUSTOTAL_API_KEY", exc.response.status_code),
                    "malicious": 0, "suspicious": 0}
        except (httpx.TimeoutException, httpx.RequestError, OSError):
            return {**connection_failure("VirusTotal"), "malicious": 0, "suspicious": 0}
        except ValueError:
            return {**response_failure("VirusTotal"), "malicious": 0, "suspicious": 0}