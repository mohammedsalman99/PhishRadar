from __future__ import annotations

from html.parser import HTMLParser
from typing import Any


URGENCY_TERMS = ("urgent", "immediately", "suspended", "verify your account", "act now", "within 24 hours")
CREDENTIAL_TERMS = ("password", "sign in", "login", "social security", "credit card", "bank details")


class FormInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.password_inputs = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag.lower() == "form":
            self.forms += 1
        if tag.lower() == "input" and attributes.get("type", "").lower() == "password":
            self.password_inputs += 1


def analyze_content(text: str, html: str) -> list[dict[str, Any]]:
    normalized = f"{text}\n{html}".lower()
    findings: list[dict[str, Any]] = []
    urgent = [term for term in URGENCY_TERMS if term in normalized]
    credentials = [term for term in CREDENTIAL_TERMS if term in normalized]
    if urgent:
        findings.append({"category": "Content", "rule": "urgency-language", "points": min(15, 5 * len(urgent)),
                         "severity": "medium", "detail": "The message uses urgency or account-pressure language.",
                         "evidence": ", ".join(urgent)})
    if credentials:
        findings.append({"category": "Content", "rule": "credential-request", "points": min(12, 4 * len(credentials)),
                         "severity": "medium", "detail": "The message references credentials or sensitive personal data.",
                         "evidence": ", ".join(credentials)})
    inspector = FormInspector()
    inspector.feed(html)
    if inspector.forms or inspector.password_inputs:
        findings.append({"category": "Content", "rule": "embedded-login-form", "points": 28,
                         "severity": "high", "detail": "The email HTML contains a form or password field.",
                         "evidence": f"Forms: {inspector.forms}; password fields: {inspector.password_inputs}"})
    return findings