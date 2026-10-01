import hashlib
from pathlib import Path

import pytest

import app.analyzers.dns_auth as dns_auth
from app.analyzers.email_parser import parse_email
from app.analyzers.headers import analyze_headers
from app.analyzers.urls import analyze_urls
from app.scoring.engine import build_report


def test_multipart_email_extracts_attachments_and_explainable_risk() -> None:
    raw = b"""From: PayPal Support <alerts@random-mail.test>
Reply-To: collect@elsewhere.test
Return-Path: <bounce@random-mail.test>
Authentication-Results: mx.test; spf=fail; dkim=pass; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=part

--part
Content-Type: text/plain; charset=utf-8

Urgent: verify your account at http://paypa1.com/login immediately.
--part
Content-Type: application/octet-stream; name=invoice.js
Content-Disposition: attachment; filename=invoice.js
Content-Transfer-Encoding: base64

YWxlcnQoMSk=
--part--
"""
    parsed = parse_email(raw)
    headers, header_findings = analyze_headers(parsed["headers"])
    urls, url_findings = analyze_urls(parsed["text"], parsed["html"])
    assert headers["from_domain"] == "random-mail.test"
    assert {finding["rule"] for finding in header_findings} >= {"reply-to-mismatch", "spf-fail", "brand-display-name"}
    assert urls[0]["host"] == "paypa1.com"
    assert any(finding["rule"] == "brand-lookalike" for finding in url_findings)
    assert parsed["attachments"][0]["sha256"] == hashlib.sha256(b"alert(1)").hexdigest()
    report = build_report(header_findings + url_findings, headers, urls, parsed["attachments"])
    assert report["score"] > 0
    assert report["findings"]


def test_malformed_from_display_name_keeps_sender_domain_checks() -> None:
    raw = b'''From: "Microsoft account team", _ <no-reply@access-accsecurity.com>
Reply-To: sotrecognizd@gmail.com
Return-Path: <bounce@thcultarfdes.co.uk>

Account notice.
'''
    parsed = parse_email(raw)
    headers, findings = analyze_headers(parsed["headers"])

    assert headers["from_domain"] == "access-accsecurity.com"
    assert headers["from_domain_parse_failed"] is False
    assert {finding["rule"] for finding in findings} >= {
        "reply-to-mismatch", "return-path-mismatch", "brand-display-name",
    }


def test_link_text_mismatch_is_reported() -> None:
    urls, findings = analyze_urls("", '<a href="https://bad.test/login">https://example.com</a>')
    assert urls[0]["host"] == "bad.test"
    assert any(item["rule"] == "link-text-mismatch" for item in findings)


def test_high_severity_finding_cannot_be_labeled_safe() -> None:
    report = build_report(
        [{"category": "Reputation", "rule": "provider-suspicious", "points": 18, "severity": "high"}],
        {}, [], [],
    )
    assert report["score"] == 18
    assert report["verdict"] == "Suspicious"

    critical_report = build_report(
        [{"category": "Reputation", "rule": "provider-malicious", "points": 40, "severity": "critical"}],
        {}, [], [],
    )
    assert critical_report["verdict"] == "Malicious"


def test_report_adds_contextual_attack_mappings_without_changing_score() -> None:
    findings = [
        {"category": "URLs", "rule": "brand-lookalike", "points": 24, "severity": "high"},
        {"category": "Authentication", "rule": "spf-fail", "points": 12, "severity": "high"},
        {"category": "Attachments", "rule": "dangerous-extension", "points": 22, "severity": "high"},
        {"category": "Content", "rule": "embedded-login-form", "points": 28, "severity": "high"},
    ]

    report = build_report(findings, {}, [], [])

    assert report["score"] == 86
    mappings = {item["rule"]: item.get("attack") for item in report["findings"]}
    assert mappings["brand-lookalike"]["technique_id"] == "T1566.002"
    assert mappings["dangerous-extension"]["technique_id"] == "T1566.001"
    assert mappings["embedded-login-form"]["technique_id"] == "T1056.003"
    assert mappings["spf-fail"] is None
    assert "does not confirm" in mappings["brand-lookalike"]["interpretation"]


def test_dns_spf_pass_and_fail_are_independently_evaluated(monkeypatch) -> None:
    class TxtRecord:
        def __init__(self, value: bytes) -> None:
            self.strings = (value,)

    def resolve(name: str, record_type: str):
        if record_type == "TXT" and name == "example.test":
            return [TxtRecord(b"v=spf1 ip4:203.0.113.10 -all")]
        if record_type == "TXT" and name == "_dmarc.example.test":
            return [TxtRecord(b"v=DMARC1; p=reject")]
        if record_type in {"A", "AAAA"}:
            raise dns_auth.dns.resolver.NoAnswer
        raise dns_auth.dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_auth.dns.resolver, "resolve", resolve)
    details = {
        "from_domain": "example.test", "sending_ip": "203.0.113.11",
        "authentication_results": "mx; spf=pass smtp.mailfrom=example.test",
    }
    verification, findings = dns_auth.analyze_dns_auth(None, details)

    assert verification["spf"]["result"] == "fail"
    assert verification["dmarc"]["policy"] == "reject"
    assert any(item["rule"] == "spf-fail" and "dns_verified" in item["evidence"] for item in findings)
    assert any(item["rule"] == "auth-mismatch" and "header_spf=pass" in item["evidence"] for item in findings)


@pytest.mark.parametrize(
    ("header_state", "expects_mismatch"),
    [("none", False), ("temperror", True), ("permerror", True)],
)
def test_dns_header_state_equivalence_against_no_record(monkeypatch, header_state: str, expects_mismatch: bool) -> None:
    def resolve(name: str, record_type: str):
        raise dns_auth.dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_auth.dns.resolver, "resolve", resolve)
    verification, findings = dns_auth.analyze_dns_auth(None, {
        "from_domain": "missing.example", "sending_ip": "203.0.113.11",
        "authentication_results": f"mx; spf={header_state}; dmarc={header_state}",
    })

    assert verification["spf"]["status"] == "no_record"
    assert verification["dmarc"]["status"] == "no_record"
    mismatches = [item for item in findings if item["rule"] == "auth-mismatch"]
    assert bool(mismatches) is expects_mismatch
    if expects_mismatch:
        assert len(mismatches) == 2
        assert any(f"header_spf={header_state}" in item["evidence"] and "dns_spf=no_record" in item["evidence"]
                   for item in mismatches)
        assert any(f"header_dmarc={header_state}" in item["evidence"] and "dns_dmarc=no_record" in item["evidence"]
                   for item in mismatches)


def test_dns_spf_supports_pass_and_softfail(monkeypatch) -> None:
    class TxtRecord:
        def __init__(self, value: bytes) -> None:
            self.strings = (value,)

    def resolve(name: str, record_type: str):
        if record_type == "TXT" and name == "pass.example":
            return [TxtRecord(b"v=spf1 ip4:203.0.113.11 -all")]
        if record_type == "TXT" and name == "soft.example":
            return [TxtRecord(b"v=spf1 ~all")]
        if record_type == "TXT" and name.startswith("_dmarc."):
            return [TxtRecord(b"v=DMARC1; p=none")]
        raise dns_auth.dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_auth.dns.resolver, "resolve", resolve)
    passed, pass_findings = dns_auth.analyze_dns_auth(None, {
        "from_domain": "pass.example", "sending_ip": "203.0.113.11", "authentication_results": "",
    })
    softfailed, softfail_findings = dns_auth.analyze_dns_auth(None, {
        "from_domain": "soft.example", "sending_ip": "203.0.113.11", "authentication_results": "",
    })

    assert passed["spf"]["result"] == "pass"
    assert pass_findings == []
    assert softfailed["spf"]["result"] == "softfail"
    assert softfail_findings[0]["rule"] == "spf-softfail"


def test_dns_no_record_is_not_treated_as_authentication_pass(monkeypatch) -> None:
    def resolve(name: str, record_type: str):
        raise dns_auth.dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_auth.dns.resolver, "resolve", resolve)
    verification, findings = dns_auth.analyze_dns_auth(None, {
        "from_domain": "missing.example", "sending_ip": "203.0.113.11", "authentication_results": "",
    })

    assert verification["spf"]["status"] == "no_record"
    assert verification["dmarc"]["status"] == "no_record"
    assert findings == []


def test_dkim_fixture_failure_is_distinct_from_absence(monkeypatch) -> None:
    invalid = Path(__file__).parent / "fixtures" / "dkim-invalid.eml"
    valid = Path(__file__).parent / "fixtures" / "dkim-valid.eml"
    details = {"from_domain": "example.test"}

    failed, findings = dns_auth.verify_dkim(invalid.read_bytes(), details)
    assert failed["status"] == "unavailable" or failed["status"] == "failed"
    if failed["status"] == "unavailable":
        monkeypatch.setattr(dns_auth.dkim.DKIM, "verify", lambda self, dnsfunc: False)
        failed, findings = dns_auth.verify_dkim(invalid.read_bytes(), details)
    assert failed["status"] == "failed"
    assert findings[0]["rule"] == "dkim-cryptographic-fail"

    monkeypatch.setattr(dns_auth.dkim.DKIM, "verify", lambda self, dnsfunc: True)
    verified, findings = dns_auth.verify_dkim(valid.read_bytes(), details)
    assert verified["status"] == "verified"
    assert findings == []

    absent, findings = dns_auth.verify_dkim(b"From: sender@example.test\n\nNo signature\n", details)
    assert absent["status"] == "absent"
    assert findings == []