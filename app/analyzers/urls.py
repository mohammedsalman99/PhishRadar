from __future__ import annotations

import re
from difflib import SequenceMatcher
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from app.analyzers.headers import BRANDS

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rb.gy"}


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text_content: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        self.text_content.append(data)
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _brand_lookalike(host: str) -> str | None:
    candidate = host.split(":", 1)[0].removeprefix("www.")
    for brand, canonical in BRANDS.items():
        expected = canonical.split(".")[0]
        label = candidate.split(".")[0]
        if label != expected and SequenceMatcher(None, label, expected).ratio() >= 0.78:
            return brand
    return None


def analyze_urls(text: str, html: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    parser = LinkParser()
    parser.feed(html)
    links = parser.links
    candidates = links + [(url, "") for url in URL_PATTERN.findall(text + "\n" + " ".join(parser.text_content))]
    urls: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for raw_url, label in candidates:
        url = raw_url.rstrip(".,);]}")
        if not url.lower().startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        host = _host(url)
        item = {"url": url, "host": host, "display_text": label}
        urls.append(item)
        if host in SHORTENERS:
            findings.append({"category": "URLs", "rule": "url-shortener", "points": 10,
                             "severity": "medium", "detail": "A shortened link hides its final destination.", "evidence": url})
        if url.lower().startswith("http://"):
            findings.append({"category": "URLs", "rule": "unencrypted-link", "points": 5,
                             "severity": "low", "detail": "The link does not use HTTPS.", "evidence": url})
        lookalike = _brand_lookalike(host)
        if lookalike:
            findings.append({"category": "URLs", "rule": "brand-lookalike", "points": 24,
                             "severity": "high", "detail": f"The hostname resembles {lookalike} but is not its known domain.",
                             "evidence": host})
        if label.startswith(("http://", "https://")) and _host(label) and _host(label) != host:
            findings.append({"category": "URLs", "rule": "link-text-mismatch", "points": 20,
                             "severity": "high", "detail": "The displayed URL hostname differs from the actual link destination.",
                             "evidence": f"Displayed: {_host(label)}; actual: {host}"})
    return urls, findings