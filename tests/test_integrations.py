import asyncio

import httpx

from app.integrations.abuseipdb import AbuseIPDBClient
from app.integrations.virustotal import VirusTotalClient
from app.integrations.urlhaus import URLhausClient


def test_abuseipdb_lookup_and_cache(tmp_path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.path.endswith("/api/v2/check")
        assert request.url.params["ipAddress"] == "203.0.113.10"
        assert request.headers["Key"] == "test-key"
        return httpx.Response(200, json={
            "data": {"abuseConfidenceScore": 85, "totalReports": 12, "isWhitelisted": False,
                     "countryCode": "US", "isp": "Example ISP", "lastReportedAt": None},
        }, request=request)

    client = AbuseIPDBClient(
        api_key="test-key",
        cache_path=str(tmp_path / "cache.sqlite3"),
        transport=httpx.MockTransport(handler),
        request_interval=0,
    )
    first = asyncio.run(client.lookup("203.0.113.10"))
    second = asyncio.run(client.lookup("203.0.113.10"))

    assert first["status"] == "found"
    assert first["abuse_confidence_score"] == 85
    assert first["total_reports"] == 12
    assert second == first
    assert len(requests) == 1


def test_abuseipdb_rate_limit_is_unavailable(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"errors": [{"detail": "daily limit"}]}, request=request)

    client = AbuseIPDBClient(
        api_key="test-key",
        cache_path=str(tmp_path / "cache.sqlite3"),
        transport=httpx.MockTransport(handler),
        request_interval=0,
    )
    result = asyncio.run(client.lookup("203.0.113.10"))

    assert result["status"] == "unavailable"
    assert result["error_code"] == "rate_limited"


def test_virustotal_rate_limit_returns_actionable_message(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "quota exceeded"}, request=request)

    client = VirusTotalClient(
        api_key="test-key",
        cache_path=str(tmp_path / "cache.sqlite3"),
        transport=httpx.MockTransport(handler),
    )
    result = asyncio.run(client.lookup("url", "https://example.test"))

    assert result["status"] == "unavailable"
    assert result["error_code"] == "rate_limited"
    assert "rate limit" in result["error_message"].lower()


def test_urlhaus_lookup_and_cache(tmp_path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.path.endswith("/v1/url/")
        assert request.read() == b"url=https%3A%2F%2Fbad.example%2Flogin"
        return httpx.Response(200, json={
            "query_status": "ok", "url_status": "online", "threat": "malware",
            "tags": ["malware"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
        }, request=request)

    client = URLhausClient(
        enabled=True,
        cache_path=str(tmp_path / "cache.sqlite3"),
        transport=httpx.MockTransport(handler),
        request_interval=0,
    )
    first = asyncio.run(client.lookup("https://bad.example/login"))
    second = asyncio.run(client.lookup("https://bad.example/login"))

    assert first["status"] == "found"
    assert first["threat"] == "malware"
    assert second == first
    assert len(requests) == 1


def test_urlhaus_disabled_does_not_query() -> None:
    client = URLhausClient(enabled=False)
    result = asyncio.run(client.lookup("https://example.test"))
    assert result == {"status": "disabled"}


def test_virustotal_lookup_and_cache(tmp_path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["x-apikey"] == "test-key"
        return httpx.Response(200, json={
            "data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 10}}},
        }, request=request)

    client = VirusTotalClient(
        api_key="test-key",
        cache_path=str(tmp_path / "cache.sqlite3"),
        transport=httpx.MockTransport(handler),
    )
    first = asyncio.run(client.lookup("url", "https://example.test"))
    second = asyncio.run(client.lookup("url", "https://example.test"))

    assert first == {"status": "found", "malicious": 3, "suspicious": 1, "harmless": 10}
    assert second == first
    assert len(requests) == 1