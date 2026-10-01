from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.main as main


ROOT = Path(__file__).parent


def _disable_external_enrichment() -> None:
    main.vt_client.api_key = ""
    main.abuseipdb_client.api_key = ""
    main.analyze_dns_auth = lambda message, headers: ({
        "spf": {"status": "not_configured"}, "dmarc": {"status": "not_configured"},
    }, [])
    main.verify_dkim = lambda raw_email, headers: ({
        "status": "not_configured", "signing_domain": None, "aligned": False,
    }, [])


def main_eval() -> int:
    labels: dict[str, str] = json.loads((ROOT / "labels.json").read_text(encoding="utf-8"))
    _disable_external_enrichment()
    confusion: Counter[tuple[str, str]] = Counter()
    correct = 0
    for filename, expected in labels.items():
        report = asyncio.run(main.analyze_message((ROOT / "samples" / filename).read_bytes()))
        actual = report["verdict"]
        correct += actual == expected
        confusion[(expected, actual)] += 1
        print(f"{filename}: expected={expected} actual={actual} {'PASS' if actual == expected else 'FAIL'}")

    print(f"Accuracy: {correct}/{len(labels)} ({correct / len(labels):.0%})")
    print("Confusion matrix (expected, predicted):")
    for expected in ("Safe", "Suspicious", "Malicious"):
        print(expected, [confusion[(expected, actual)] for actual in ("Safe", "Suspicious", "Malicious")])
    return 0 if correct == len(labels) else 1


if __name__ == "__main__":
    raise SystemExit(main_eval())