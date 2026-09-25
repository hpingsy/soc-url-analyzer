"""Validate URLs and report deterministic, advisory threat indicators."""

import ipaddress
import re
from typing import TypedDict
from urllib.parse import unquote, urlsplit


class Finding(TypedDict):
    code: str
    message: str


class AnalysisResult(TypedDict):
    url: str | None
    valid: bool
    scheme: str | None
    hostname: str | None
    suspicious: bool
    findings: list[Finding]
    errors: list[str]


def _hostname(value: str) -> tuple[str, bool]:
    """Return a normalized ASCII hostname and whether it is an IP literal."""
    if "%" in value:
        raise ValueError("Encoded hostnames and IPv6 zone identifiers are not supported.")
    try:
        return str(ipaddress.ip_address(value)), True
    except ValueError:
        pass
    host = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")
    ):
        raise ValueError("Hostname is invalid.")
    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError("IPv4 address is invalid or ambiguous.")
    return host, False


def analyze_url(url: object) -> AnalysisResult:
    """Analyze an absolute HTTP(S) URL locally; findings do not prove maliciousness.

    Invalid input returns errors rather than raising. Hostnames use lowercase IDNA
    ASCII form; IP literals use canonical form. No network access is performed.
    """
    result: AnalysisResult = {
        "url": url if isinstance(url, str) else None,
        "valid": False,
        "scheme": None,
        "hostname": None,
        "suspicious": False,
        "findings": [],
        "errors": [],
    }
    try:
        if not isinstance(url, str) or not url:
            raise ValueError("URL must be a non-empty string.")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
            raise ValueError("URL must not contain whitespace or control characters.")
        if "\\" in url:
            raise ValueError("URL must not contain backslashes.")
        if re.search(r"%(?![0-9a-fA-F]{2})", url):
            raise ValueError("URL contains an invalid percent escape.")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            raise ValueError("URL scheme must be HTTP or HTTPS.")
        if not parts.netloc or not parts.hostname:
            raise ValueError("URL must include a hostname.")
        authority = parts.netloc.rsplit("@", 1)[-1]
        if parts.netloc.count("@") > 1 or authority.endswith(":"):
            raise ValueError("URL authority is malformed.")
        port = parts.port  # Validates numeric syntax and the port range.
        if port == 0:
            raise ValueError("URL port must be between 1 and 65535.")
        host, is_ip = _hostname(parts.hostname)
        if authority.startswith("["):
            if (
                not is_ip
                or ":" not in host
                or not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", authority)
            ):
                raise ValueError("Bracketed authority must contain an IPv6 address.")
    except (ValueError, UnicodeError) as exc:
        result["errors"].append(str(exc))
        return result

    result.update(valid=True, scheme=parts.scheme, hostname=host)
    checks = [
        (parts.scheme == "http", "unencrypted_http", "URL uses unencrypted HTTP."),
        (parts.username is not None, "embedded_credentials", "URL contains user information."),
        (is_ip, "ip_literal", "Hostname is an IP address."),
        (
            any(s.startswith("xn--") for s in host.split(".")),
            "idn_hostname",
            "Internationalized hostname may require visual inspection.",
        ),
        (
            len(host.split(".")) > 4 and not is_ip,
            "many_labels",
            "Hostname has more than four labels.",
        ),
        (len(url) > 2048, "long_url", "URL exceeds 2048 characters."),
        (
            port is not None and port != {"http": 80, "https": 443}[parts.scheme],
            "unusual_port",
            "URL uses a non-default port.",
        ),
        (
            bool(re.search(r"\.(?:exe|scr|bat|cmd|ps1|msi|vbs|js)$", unquote(parts.path), re.I)),
            "executable_path",
            "Decoded path ends with an executable or script extension.",
        ),
    ]
    result["findings"] = [
        {"code": code, "message": message} for matched, code, message in checks if matched
    ]
    result["suspicious"] = bool(result["findings"])
    return result
