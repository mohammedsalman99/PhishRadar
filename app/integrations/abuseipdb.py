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

from app.integrations.errors import api_failure, connection_failure, response_failure


class AbuseIPDBClient:
    """AbuseIPDB IP checks with a persistent 24-hour cache."""

    def __init__(self, api_key: str | None = None, cache_path: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None,
                 request_interval: float | None = None) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")
        self.cache_path = Path(cache_path or os.getenv("PHISHRADAR_CACHE_DB", "data/reputation-cache.sqlite3"))
        self.transport = transport
        self.request_interval = request_interval if request_interval is not None else float(
            os.getenv("ABUSEIPDB_REQUEST_INTERVAL", "1")
        )
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    def _cached(self, ip_address: str) -> dict[str, Any] | None:
        if not self.cache_path.exists():
            return None
        try:
            with sqlite3.connect(self.cache_path) as connection:
                row = connection.execute(
                    "SELECT result, cached_at FROM abuseipdb_cache WHERE ip_address = ?", (ip_address,)
                ).fetchone()
            if row and time.time() - row[1] < 86400:
                return json.loads(row[0])
        except (sqlite3.Error, ValueError, TypeError):
            return None
        return None

    def _store(self, ip_address: str, result: dict[str, Any]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.cache_path) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS abuseipdb_cache "
                    "(ip_address TEXT PRIMARY KEY, result TEXT NOT NULL, cached_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT OR REPLACE INTO abuseipdb_cache VALUES (?, ?, ?)",
                    (ip_address, json.dumps(result), time.time()),
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

    async def lookup(self, ip_address: str | None) -> dict[str, Any] | None:
        if not self.api_key or not ip_address:
            return None
        cached = self._cached(ip_address)
        if cached is not None:
            return cached

        await self._request_slot()
        try:
            async with httpx.AsyncClient(timeout=8, transport=self.transport) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    headers={"Key": self.api_key, "Accept": "application/json"},
                )
            response.raise_for_status()
            data = response.json()["data"]
            result = {
                "status": "found",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": bool(data.get("isWhitelisted", False)),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "last_reported_at": data.get("lastReportedAt"),
            }
            self._store(ip_address, result)
            return result
        except httpx.HTTPStatusError as exc:
            return {**api_failure("AbuseIPDB", "ABUSEIPDB_API_KEY", exc.response.status_code)}
        except (httpx.TimeoutException, httpx.RequestError, OSError):
            return connection_failure("AbuseIPDB")
        except (KeyError, ValueError, TypeError, AttributeError):
            return response_failure("AbuseIPDB")