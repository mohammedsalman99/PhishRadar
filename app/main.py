from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from dotenv import load_dotenv

from app.analyzers.attachments import analyze_attachments
from app.analyzers.content import analyze_content
from app.analyzers.dns_auth import analyze_dns_auth, verify_dkim
from app.analyzers.email_parser import parse_email
from app.analyzers.headers import analyze_headers
from app.analyzers.urls import analyze_urls
from app.integrations.abuseipdb import AbuseIPDBClient
from app.integrations.virustotal import VirusTotalClient
from app.integrations.urlhaus import URLhausClient
from app.scoring.engine import build_report

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("phishradar")
app = FastAPI(title="PhishRadar", description="Explainable phishing email triage API", version="1.0.0")
vt_client = VirusTotalClient()
abuseipdb_client = AbuseIPDBClient()
urlhaus_client = URLhausClient()
STATIC_DIR = Path(__file__).parent / "static"
MAX_EMAIL_BYTES = 5 * 1024 * 1024


def _lookup_status(results: list[dict[str, Any] | None]) -> str:
    statuses = [result.get("status") for result in results if result]
    if not statuses:
        return "no_indicators"
    failures = statuses.count("unavailable")
    if failures == len(statuses):
        return "unavailable"
    if failures:
        return "partial"
    return "checked"


async def analyze_message(raw_email: bytes) -> dict[str, Any]:
    parsed = parse_email(raw_email)
    headers, header_findings = analyze_headers(parsed["headers"])
    dns_auth, dns_findings = await asyncio.to_thread(analyze_dns_auth, parsed["headers"], headers)
    dkim_auth, dkim_findings = await asyncio.to_thread(verify_dkim, raw_email, headers)
    headers["dns_authentication"] = dns_auth
    headers["dkim_verification"] = dkim_auth
    urls, url_findings = analyze_urls(parsed["text"], parsed["html"])
    content_findings = analyze_content(parsed["text"], parsed["html"])
    attachment_findings = analyze_attachments(parsed["attachments"])
    findings = header_findings + dns_findings + dkim_findings + url_findings + content_findings + attachment_findings
    providers: dict[str, dict[str, Any]] = {
        "virustotal": {"status": "not_configured", "lookups": []},
        "abuseipdb": {"status": "not_configured", "lookups": []},
        "urlhaus": {"status": "not_configured", "lookups": []},
    }
    enrichment: dict[str, Any] = {"status": "not_configured", "providers": providers}
    if vt_client.api_key:
        indicators = [("url", item["url"]) for item in urls[:10]]
        indicators += [("file", item["sha256"]) for item in parsed["attachments"][:10]]
        if headers.get("sending_ip"):
            indicators.append(("ip", headers["sending_ip"]))
        results = await asyncio.gather(*(vt_client.lookup(kind, value) for kind, value in indicators))
        providers["virustotal"]["status"] = _lookup_status(results)
        for (kind, value), result in zip(indicators, results):
            if result is None:
                continue
            providers["virustotal"]["lookups"].append({"type": kind, "indicator": value, **result})
            if result["malicious"]:
                findings.append({"category": "Reputation", "rule": "virustotal-malicious", "points": 40,
                                 "severity": "critical", "detail": f"VirusTotal flagged this {kind} as malicious.",
                                 "evidence": value})
            elif result["suspicious"]:
                findings.append({"category": "Reputation", "rule": "virustotal-suspicious", "points": 18,
                                 "severity": "high", "detail": f"VirusTotal reported suspicious detections for this {kind}.",
                                 "evidence": value})
    if urlhaus_client.enabled:
        url_results = await asyncio.gather(*(urlhaus_client.lookup(item["url"]) for item in urls[:10]))
        providers["urlhaus"]["status"] = _lookup_status(url_results)
        for item, result in zip(urls[:10], url_results):
            if result is None:
                continue
            providers["urlhaus"]["lookups"].append({"type": "url", "indicator": item["url"], **result})
            if result.get("status") == "found":
                findings.append({"category": "Reputation", "rule": "urlhaus-malicious", "points": 35,
                                 "severity": "critical", "detail": "URLhaus lists this URL as malicious.",
                                 "evidence": item["url"]})
    if abuseipdb_client.api_key:
        result = await abuseipdb_client.lookup(headers.get("sending_ip"))
        if result is not None:
            indicator = headers.get("sending_ip", "")
            providers["abuseipdb"]["lookups"] = [{"type": "ip", "indicator": indicator, **result}]
            providers["abuseipdb"]["status"] = _lookup_status([result])
            confidence = result.get("abuse_confidence_score", 0)
            if result.get("status") == "found" and confidence >= 75:
                findings.append({"category": "Reputation", "rule": "abuseipdb-high-confidence", "points": 35,
                                 "severity": "critical", "detail": "AbuseIPDB reports high-confidence abuse for this IP address.",
                                 "evidence": f"{indicator}; abuse_confidence_score={confidence}"})
            elif result.get("status") == "found" and confidence >= 25:
                findings.append({"category": "Reputation", "rule": "abuseipdb-suspicious", "points": 18,
                                 "severity": "high", "detail": "AbuseIPDB reports suspicious abuse activity for this IP address.",
                                 "evidence": f"{indicator}; abuse_confidence_score={confidence}"})
    active_statuses = [provider["status"] for provider in providers.values() if provider["status"] != "not_configured"]
    if "unavailable" in active_statuses:
        enrichment["status"] = "unavailable" if active_statuses.count("unavailable") == len(active_statuses) else "partial"
    elif "partial" in active_statuses:
        enrichment["status"] = "partial"
    elif "checked" in active_statuses:
        enrichment["status"] = "checked"
    elif "no_indicators" in active_statuses:
        enrichment["status"] = "no_indicators"
    elif active_statuses:
        enrichment["status"] = active_statuses[0]
    report = build_report(findings, headers, urls, parsed["attachments"], enrichment)
    logger.info("analysis_complete score=%d verdict=%s urls=%d attachments=%d", report["score"], report["verdict"], len(urls), len(parsed["attachments"]))
    return report


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/analyze")
async def analyze(raw_email: str = Form(default=""), file: UploadFile | None = File(default=None)) -> dict[str, Any]:
    if file is not None:
        if file.filename and not file.filename.lower().endswith(".eml"):
            raise HTTPException(status_code=415, detail="Only .eml files are supported; paste raw email for other formats.")
        payload = await file.read(MAX_EMAIL_BYTES + 1)
    else:
        payload = raw_email.encode("utf-8")
    if not payload.strip():
        raise HTTPException(status_code=400, detail="Upload an .eml file or paste raw email headers and body.")
    if len(payload) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="Email exceeds the 5 MB analysis limit.")
    try:
        return await analyze_message(payload)
    except Exception as exc:
        logger.exception("analysis_failed")
        raise HTTPException(status_code=422, detail="The email could not be analyzed.") from exc