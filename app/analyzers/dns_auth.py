from __future__ import annotations

import ipaddress
import re
from email.message import Message
from typing import Any

import dkim
import dns.exception
import dns.resolver


SUPPORTED_SPF_MECHANISMS = {"include", "a", "mx", "ip4", "ip6", "all"}
RESULT_POINTS = {"fail": (12, "high"), "softfail": (7, "medium")}
AUTH_STATES = {"pass", "fail", "softfail", "no_record", "temperror", "permerror", "none"}
AUTH_STATE_EQUIVALENTS = {"none": "no_record"}


def _txt_value(record: Any) -> str:
    strings = getattr(record, "strings", None)
    if strings is not None:
        return b"".join(value if isinstance(value, bytes) else str(value).encode() for value in strings).decode(
            "utf-8", errors="replace"
        )
    return str(record).strip('"')


def _query(name: str, record_type: str) -> tuple[str, list[Any]]:
    try:
        return "ok", list(dns.resolver.resolve(name, record_type))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "no_record", []
    except (dns.resolver.NoNameservers, dns.exception.Timeout, OSError):
        return "unavailable", []


def _txt_records(name: str) -> tuple[str, list[str]]:
    status, records = _query(name, "TXT")
    return status, [_txt_value(record) for record in records]


def _addresses(name: str) -> tuple[str, list[str]]:
    addresses: list[str] = []
    statuses: list[str] = []
    for record_type in ("A", "AAAA"):
        status, records = _query(name, record_type)
        statuses.append(status)
        addresses.extend(str(record) for record in records)
    if addresses:
        return "ok", addresses
    if "unavailable" in statuses:
        return "unavailable", []
    return "no_record", []


def _matches_ip(network: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def _qualifier(token: str) -> tuple[str, str]:
    return (token[0], token[1:]) if token[:1] in "+-~?" else ("+", token)


def _spf_record(domain: str) -> tuple[str, str | None]:
    status, records = _txt_records(domain)
    if status != "ok":
        return status, None
    record = next((item for item in records if item.lower().startswith("v=spf1")), None)
    return ("ok", record) if record else ("no_record", None)


def _evaluate_spf(domain: str, sending_ip: str, depth: int = 0, seen: set[str] | None = None) -> dict[str, Any]:
    if depth > 10 or domain in (seen or set()):
        return {"status": "unavailable", "reason": "spf_include_loop"}
    seen = set(seen or ())
    seen.add(domain)
    status, record = _spf_record(domain)
    if status != "ok" or record is None:
        return {"status": status}

    for token in record.split()[1:]:
        if "=" in token and not token.startswith(("ip4:", "ip6:")):
            modifier = token.split("=", 1)[0].lower()
            if modifier in {"redirect", "exp"}:
                return {"status": "unavailable", "reason": f"unsupported_modifier:{modifier}"}
            continue
        qualifier, mechanism = _qualifier(token)
        name, _, value = mechanism.partition(":")
        if name not in SUPPORTED_SPF_MECHANISMS:
            return {"status": "unavailable", "reason": f"unsupported_mechanism:{name}"}
        matched = False
        if name == "all":
            matched = True
        elif name in {"ip4", "ip6"}:
            address, _, prefix = value.partition("/")
            cidr = prefix or ("32" if name == "ip4" else "128")
            try:
                matched = _matches_ip(f"{address}/{cidr}", sending_ip)
            except (IndexError, ValueError):
                matched = False
        elif name == "include":
            if not value:
                continue
            included = _evaluate_spf(value, sending_ip, depth + 1, seen)
            if included.get("status") == "unavailable":
                return included
            matched = included.get("result") == "pass"
        else:
            target = value or domain
            if name == "a":
                address_status, addresses = _addresses(target)
                if address_status == "unavailable":
                    return {"status": "unavailable", "reason": "dns_lookup_failed"}
                matched = sending_ip in addresses
            elif name == "mx":
                mx_status, mx_records = _query(target, "MX")
                if mx_status == "unavailable":
                    return {"status": "unavailable", "reason": "dns_lookup_failed"}
                for mx in mx_records:
                    address_status, addresses = _addresses(str(mx.exchange).rstrip("."))
                    if address_status == "unavailable":
                        return {"status": "unavailable", "reason": "dns_lookup_failed"}
                    matched = matched or sending_ip in addresses
        if matched:
            result = {"pass": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(qualifier, "pass")
            return {"status": "ok", "result": result, "record": record}
    return {"status": "ok", "result": "neutral", "record": record}


def _auth_result(auth_results: str, method: str) -> str | None:
    match = re.search(rf"\b{method}\s*=\s*([a-z]+)", auth_results, re.I)
    return match.group(1).lower() if match else None


def _normalized_auth_state(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.lower()
    normalized = AUTH_STATE_EQUIVALENTS.get(normalized, normalized)
    return normalized if normalized in AUTH_STATES else None


def _add_auth_mismatch(findings: list[dict[str, Any]], method: str,
                       header_state: str | None, dns_state: str | None) -> None:
    normalized_header = _normalized_auth_state(header_state)
    normalized_dns = _normalized_auth_state(dns_state)
    if normalized_header is None or normalized_dns is None or normalized_header == normalized_dns:
        return
    findings.append({"category": "Authentication", "rule": "auth-mismatch", "points": 18,
                     "severity": "high", "detail": f"Authentication-Results {method.upper()} disagrees with DNS verification.",
                     "evidence": f"source=header,dns_verified; header_{method}={header_state}; dns_{method}={dns_state}"})


def _auth_domain(auth_results: str, method: str) -> str | None:
    parameter = "smtp.mailfrom" if method == "spf" else "header.d"
    match = re.search(rf"\b{re.escape(parameter)}\s*=\s*([^\s;]+)", auth_results, re.I)
    return match.group(1).strip("<>").lower() if match else None


def _aligned(domain: str | None, from_domain: str) -> bool:
    return bool(domain and (domain == from_domain or domain.endswith("." + from_domain)))


def _result_finding(method: str, result: str, evidence: str) -> dict[str, Any] | None:
    points_severity = RESULT_POINTS.get(result)
    if points_severity is None:
        return None
    points, severity = points_severity
    return {
        "category": "Authentication",
        "rule": f"{method}-{result}",
        "points": points,
        "severity": severity,
        "detail": f"DNS verification found {method.upper()} {result}.",
        "evidence": evidence,
    }


def analyze_dns_auth(message: Message, header_details: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from_domain = header_details.get("from_domain", "")
    auth_results = header_details.get("authentication_results", "")
    verification: dict[str, Any] = {"spf": {"status": "no_record"}, "dmarc": {"status": "no_record"}}
    findings: list[dict[str, Any]] = []

    sending_ip = header_details.get("sending_ip")
    if from_domain and sending_ip:
        spf = _evaluate_spf(from_domain, sending_ip)
        verification["spf"] = spf
        result = spf.get("result")
        if result:
            finding = _result_finding("spf", result, f"source=dns_verified; domain={from_domain}; result={result}")
            if finding:
                findings.append(finding)
        _add_auth_mismatch(findings, "spf", _auth_result(auth_results, "spf"), result or spf.get("status"))

    if from_domain:
        dmarc_status, dmarc_records = _txt_records(f"_dmarc.{from_domain}")
        policy = None
        for record in dmarc_records:
            if record.lower().startswith("v=dmarc1"):
                match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)", record, re.I)
                policy = match.group(1).lower() if match else None
                break
        verification["dmarc"] = {"status": dmarc_status, "policy": policy}
        if policy is None and dmarc_status == "ok":
            verification["dmarc"]["status"] = "no_record"
        _add_auth_mismatch(findings, "dmarc", _auth_result(auth_results, "dmarc"), verification["dmarc"]["status"])
        spf_domain = _auth_domain(auth_results, "spf")
        dkim_domain = _auth_domain(auth_results, "dkim")
        spf_aligned = _aligned(spf_domain, from_domain) and verification.get("spf", {}).get("result") == "pass"
        dkim_aligned = _aligned(dkim_domain, from_domain) and _auth_result(auth_results, "dkim") == "pass"
        verification["dmarc"]["alignment"] = {"spf": spf_aligned, "dkim": dkim_aligned}
        if policy in {"quarantine", "reject"} and not (spf_aligned or dkim_aligned):
            findings.append({"category": "Authentication", "rule": "dmarc-alignment-fail", "points": 12,
                             "severity": "high", "detail": "DMARC policy is protective, but SPF and DKIM are not aligned with the From domain.",
                             "evidence": f"source=dns_verified; policy={policy}; spf_aligned={spf_aligned}; dkim_aligned={dkim_aligned}"})

    return verification, findings


def _dkim_dnsfunc(name: bytes, timeout: int = 5) -> bytes:
    del timeout
    status, records = _txt_records(name.decode().rstrip("."))
    if status != "ok" or not records:
        raise dkim.DKIMException("DKIM key unavailable")
    return records[0].encode()


def verify_dkim(raw_email: bytes, header_details: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    message = dkim.DKIM(raw_email)
    signature = next((value for name, value in message.headers if name.lower() == b"dkim-signature"), None)
    if not signature:
        return {"status": "absent", "signing_domain": None, "aligned": False}, []
    header = signature.decode("utf-8", errors="replace")
    domain_match = re.search(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", header, re.I)
    signing_domain = domain_match.group(1).lower() if domain_match else None
    aligned = _aligned(signing_domain, header_details.get("from_domain", ""))
    try:
        verified = message.verify(dnsfunc=_dkim_dnsfunc)
    except (dkim.DKIMException, dns.exception.DNSException, OSError):
        return {"status": "unavailable", "signing_domain": signing_domain, "aligned": aligned}, []
    if verified:
        return {"status": "verified", "signing_domain": signing_domain, "aligned": aligned}, []
    finding = {"category": "Authentication", "rule": "dkim-cryptographic-fail", "points": 12,
               "severity": "high", "detail": "DKIM signature verification failed.",
               "evidence": f"source=dkim_verified; signing_domain={signing_domain or 'unknown'}; aligned={aligned}"}
    return {"status": "failed", "signing_domain": signing_domain, "aligned": aligned}, [finding]