from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
from typing import Any


def parse_email(raw_email: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            attachments.append({
                "filename": filename or "unnamed-attachment",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest(),
                "sha1": hashlib.sha1(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, AttributeError):
            content = payload.decode("utf-8", errors="replace")
        if isinstance(content, str):
            (html_parts if part.get_content_type() == "text/html" else text_parts).append(content)

    return {
        "headers": message,
        "text": "\n".join(text_parts),
        "html": "\n".join(html_parts),
        "attachments": attachments,
    }