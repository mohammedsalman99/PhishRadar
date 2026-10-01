from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from typing import Any


BRANDS = {
    "amazon": "amazon.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "paypal": "paypal.com",
}


def _parse_address(value: str) -> tuple[str, str]:
    bracketed = re.search(r"<\s*([^<>\s@]+@[^<>\s@]+)\s*>", value)
    if bracketed:
        return value[:bracketed.start()].strip(" ,"), bracketed.group(1)
    return parseaddr(value)


def domain_of(address: str) -> str:
    _, parsed = _parse_address(address)
    return parsed.rsplit("@", 1)[-1].strip(" >.").lower() if "@" in parsed else ""


def _public_ips(received_headers: list[str]) -> list[str]:
    found: list[str] = []
    for header in received_headers:
        for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,}\b", header):
            try:
                address = ipaddress.ip_address(candidate.strip("[]"))
            except ValueError:
                continue
            if address.is_global and str(address) not in found:
                found.append(str(address))
    return found


def analyze_headers(message: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from_value = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))
    from_domain = domain_of(from_value)
    reply_domain = domain_of(reply_to)
    return_domain = domain_of(return_path)
    received = [str(value) for value in message.get_all("Received", [])]
    auth_results = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    details = {
        "from": from_value,
        "from_domain": from_domain,
        "from_domain_parse_failed": bool(from_value.strip()) and not from_domain,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": str(message.get("Message-ID", "")),
        "received_count": len(received),
        "sending_ip": (_public_ips(received) or [None])[-1],
        "authentication_results": auth_results,
    }
    findings: list[dict[str, Any]] = []

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({"category": "Headers", "rule": "reply-to-mismatch", "points": 18,
                         "severity": "high", "detail": "Reply-To uses a different domain from the visible sender.",
                         "evidence": f"From: {from_domain}; Reply-To: {reply_domain}"})
    if return_domain and from_domain and return_domain != from_domain:
        findings.append({"category": "Headers", "rule": "return-path-mismatch", "points": 10,
                         "severity": "medium", "detail": "Return-Path uses a different domain from the visible sender.",
                         "evidence": f"From: {from_domain}; Return-Path: {return_domain}"})

    display_name, _ = _parse_address(from_value)
    brand = next((name for name in BRANDS if name in display_name.lower()), None)
    if brand and from_domain and not (from_domain == BRANDS[brand] or from_domain.endswith("." + BRANDS[brand])):
        findings.append({"category": "Headers", "rule": "brand-display-name", "points": 24,
                         "severity": "high", "detail": "The sender display name references a brand not represented by its domain.",
                         "evidence": f"Display name: {display_name}; domain: {from_domain}"})

    if auth_results:
        failures = re.findall(r"\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|permerror|temperror|none)\b", auth_results, re.I)
        for method, result in failures:
            findings.append({"category": "Authentication", "rule": f"{method.lower()}-{result.lower()}",
                             "points": 12 if result.lower() == "fail" else 7,
                             "severity": "high" if result.lower() == "fail" else "medium",
                             "detail": f"{method.upper()} authentication reported {result.lower()}.",
                             "evidence": f"source=header; {auth_results[:220]}"})

    return details, findings