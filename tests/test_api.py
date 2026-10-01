from fastapi.testclient import TestClient
import pytest

import app.main as main
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_dns_auth(monkeypatch) -> None:
    monkeypatch.setattr(main, "analyze_dns_auth", lambda message, headers: ({
        "spf": {"status": "no_record"}, "dmarc": {"status": "no_record"},
    }, []))
    monkeypatch.setattr(main, "verify_dkim", lambda raw_email, headers: ({
        "status": "absent", "signing_domain": None, "aligned": False,
    }, []))


def test_analyze_endpoint_accepts_pasted_email() -> None:
    response = client.post("/api/analyze", data={"raw_email": "From: person@example.test\nSubject: Hello\n\nHi there"})
    assert response.status_code == 200
    report = response.json()
    assert report["verdict"] == "Safe"
    assert report["enrichment"]["providers"]["abuseipdb"]["status"] == "not_configured"


def test_analyze_endpoint_rejects_empty_input() -> None:
    response = client.post("/api/analyze", data={"raw_email": ""})
    assert response.status_code == 400


def test_dashboard_is_served() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "PhishRadar" in response.text


def test_configured_reputation_verdicts_are_in_report(monkeypatch) -> None:
    class FakeVirusTotal:
        api_key = "test-key"

        async def lookup(self, kind: str, value: str) -> dict[str, int | str]:
            return {"status": "found", "malicious": 2, "suspicious": 0}

    monkeypatch.setattr(main, "vt_client", FakeVirusTotal())
    response = client.post("/api/analyze", data={
        "raw_email": "From: sender@example.test\n\nVisit https://bad.example.test/login"
    })

    assert response.status_code == 200
    report = response.json()
    assert report["enrichment"]["providers"]["virustotal"]["lookups"][0]["malicious"] == 2
    assert "virustotal-malicious" in {item["rule"] for item in report["findings"]}


def test_abuseipdb_verdict_is_in_report(monkeypatch) -> None:
    class FakeAbuseIPDB:
        api_key = "test-key"

        async def lookup(self, ip_address: str) -> dict[str, object]:
            return {"status": "found", "abuse_confidence_score": 85, "total_reports": 12}

    monkeypatch.setattr(main, "abuseipdb_client", FakeAbuseIPDB())
    response = client.post("/api/analyze", data={
        "raw_email": "From: sender@example.test\nReceived: from host (host [8.8.8.8])\n\nHello"
    })

    assert response.status_code == 200
    report = response.json()
    assert report["enrichment"]["providers"]["abuseipdb"]["lookups"][0]["abuse_confidence_score"] == 85
    assert report["enrichment"]["providers"]["abuseipdb"]["status"] == "checked"
    assert report["verdict"] == "Malicious"


def test_urlhaus_verdict_is_in_report(monkeypatch) -> None:
    class FakeURLhaus:
        enabled = True

        async def lookup(self, url: str) -> dict[str, object]:
            return {"status": "found", "query_status": "ok", "threat": "malware", "tags": ["malware"]}

    monkeypatch.setattr(main, "urlhaus_client", FakeURLhaus())
    response = client.post("/api/analyze", data={
        "raw_email": "From: sender@example.test\n\nVisit https://bad.example/login"
    })

    assert response.status_code == 200
    report = response.json()
    assert report["enrichment"]["providers"]["urlhaus"]["lookups"][0]["threat"] == "malware"
    assert report["enrichment"]["providers"]["urlhaus"]["status"] == "checked"
    assert "urlhaus-malicious" in {item["rule"] for item in report["findings"]}


def test_provider_api_errors_are_explained_in_report(monkeypatch) -> None:
    class FailedVirusTotal:
        api_key = "test-key"

        async def lookup(self, kind: str, value: str) -> dict[str, int | str]:
            return {"status": "unavailable", "error_code": "rate_limited",
                    "error_message": "VirusTotal rate limit reached. Wait before trying again.",
                    "malicious": 0, "suspicious": 0}

    monkeypatch.setattr(main, "vt_client", FailedVirusTotal())
    response = client.post("/api/analyze", data={
        "raw_email": "From: sender@example.test\n\nVisit https://example.test/login"
    })

    assert response.status_code == 200
    report = response.json()
    assert report["enrichment"]["status"] == "unavailable"
    assert report["enrichment"]["providers"]["virustotal"]["status"] == "unavailable"
    assert "rate limit" in report["enrichment"]["providers"]["virustotal"]["lookups"][0]["error_message"].lower()
