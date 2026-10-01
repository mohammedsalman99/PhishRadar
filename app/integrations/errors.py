from __future__ import annotations

from typing import Any


def api_failure(provider: str, key_name: str, status_code: int) -> dict[str, Any]:
    if status_code in {401, 403}:
        code = "unauthorized"
        message = f"{provider} rejected the API key. Check {key_name} in your .env file."
    elif status_code == 429:
        code = "rate_limited"
        message = f"{provider} rate limit reached. Wait before trying again."
    elif status_code == 400:
        code = "request_rejected"
        message = f"{provider} rejected this request. Check the indicator format and provider requirements."
    elif status_code >= 500:
        code = "provider_error"
        message = f"{provider} is temporarily unavailable. Try again later."
    else:
        code = "http_error"
        message = f"{provider} returned HTTP {status_code}. No reputation verdict was received."
    return {"status": "unavailable", "error_code": code, "error_message": message}


def connection_failure(provider: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "error_code": "connection_error",
        "error_message": f"Could not connect to {provider}. Check your network and try again.",
    }


def response_failure(provider: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "error_code": "invalid_response",
        "error_message": f"{provider} returned an unreadable response. No reputation verdict was received.",
    }