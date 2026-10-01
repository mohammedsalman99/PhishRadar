from __future__ import annotations

from typing import Any


DANGEROUS_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".iso", ".img", ".docm", ".xlsm", ".html", ".hta"}


def analyze_attachments(attachments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for attachment in attachments:
        extension = "." + attachment["filename"].rsplit(".", 1)[-1].lower() if "." in attachment["filename"] else ""
        if extension in DANGEROUS_EXTENSIONS:
            findings.append({"category": "Attachments", "rule": "dangerous-extension", "points": 22,
                             "severity": "high", "detail": "The attachment uses a file type commonly abused for malware or credential theft.",
                             "evidence": attachment["filename"]})
    return findings