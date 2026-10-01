from __future__ import annotations

from typing import Any


ATTACK_MAPPINGS = {
    "dangerous-extension": {
        "technique_id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
    },
    "brand-lookalike": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
    },
    "link-text-mismatch": {
        "technique_id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
    },
    "embedded-login-form": {
        "technique_id": "T1056.003",
        "name": "Web Portal Capture",
        "tactic": "Credential Access",
    },
}


def _with_attack_mapping(finding: dict[str, Any]) -> dict[str, Any]:
    mapping = ATTACK_MAPPINGS.get(finding.get("rule"))
    if mapping is None:
        return finding
    return {
        **finding,
        "attack": {
            **mapping,
            "url": f"https://attack.mitre.org/techniques/{mapping['technique_id']}/",
            "interpretation": "This signal is consistent with the technique; it does not confirm adversary behavior or attribution.",
        },
    }


def build_report(findings: list[dict[str, Any]], headers: dict[str, Any], urls: list[dict[str, Any]],
                 attachments: list[dict[str, Any]], enrichment: dict[str, Any] | None = None) -> dict[str, Any]:
    score = min(100, sum(finding["points"] for finding in findings))
    severities = {finding.get("severity") for finding in findings}
    if score >= 65 or "critical" in severities:
        verdict = "Malicious"
    elif score >= 30 or "high" in severities:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
    return {
        "score": score,
        "verdict": verdict,
        "summary": f"{len(findings)} explainable indicator(s) found.",
        "findings": [_with_attack_mapping(finding) for finding in findings],
        "headers": headers,
        "urls": urls,
        "attachments": attachments,
        "iocs": {
            "urls": [item["url"] for item in urls],
            "ips": [headers["sending_ip"]] if headers.get("sending_ip") else [],
            "sha256": [item["sha256"] for item in attachments],
        },
        "enrichment": enrichment or {"provider": "VirusTotal", "status": "not_configured"},
    }