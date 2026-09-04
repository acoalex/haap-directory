# -*- coding: utf-8 -*-
"""L2 domain verification checks (SPEC §3.3) — server-side only.

The directory NEVER trusts the agent's claim of success: both methods are
executed by the directory itself.

* ``check_dns_txt``  — resolve TXT ``_haap.<domain>`` via ``dig``; the token
  must appear verbatim in a record (or as ``haap-verify=<token>``). An
  off-registrable-domain CNAME in the answer is treated as failure.
* ``check_https_well_known`` — fetch
  ``https://<domain>/.well-known/haap-verify.txt`` (falling back to
  ``.json``) over TLS; body must be exactly the token (trimmed) or, for
  JSON, the field ``haap_verify_token``. Redirects are followed only within
  the same registrable domain; response capped at 4 KiB; timeout 10 s.

Both raise ``DirectoryError`` with the stable §4.10 codes on failure.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .errors import DirectoryError

_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_DNS_TIMEOUT_S = 10
_HTTPS_TIMEOUT_S = 10
_MAX_WELL_KNOWN_BYTES = 4 * 1024
_TOKEN_PREFIX = "haap-verify="


def validate_domain(domain: object) -> str:
    """Validate a claimed domain (SPEC §3.3 normative rules)."""
    if not isinstance(domain, str) or not domain:
        raise DirectoryError("DOMAIN_INVALID", "domain is required")
    domain = domain.strip().lower()
    if len(domain) > 253:
        raise DirectoryError("DOMAIN_INVALID", "domain is too long")
    if "://" in domain or "/" in domain or ":" in domain or "@" in domain:
        raise DirectoryError(
            "DOMAIN_INVALID", "domain must be a bare host, no scheme/port/path"
        )
    if not _DOMAIN_RE.match(domain):
        raise DirectoryError("DOMAIN_INVALID", "domain has an invalid format")
    if domain.count(".") < 1:
        raise DirectoryError("DOMAIN_INVALID", "domain needs at least two labels")
    return domain


def registrable_domain(domain: str) -> str:
    """Approximate the registrable domain (last two labels).

    Good enough for .com/.es/.org; deliberately conservative for multi-label
    public suffixes — a CNAME inside those is rarer than a provider CNAME.
    """
    labels = domain.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def _within(parent: str, child: str) -> bool:
    """True if ``child == parent`` or ``child`` ends with ``.parent``."""
    return child == parent or child.endswith("." + parent)


def check_dns_txt(domain: str, token: str) -> None:
    """Resolve ``_haap.<domain>`` TXT and require the token verbatim."""
    name = f"_haap.{domain}"
    try:
        proc = subprocess.run(
            ["dig", "+noall", "+answer", "TXT", name],
            capture_output=True,
            text=True,
            timeout=_DNS_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise DirectoryError(
            "DNS_ERROR_TEMPORARY", "DNS resolution failed; retry shortly"
        ) from exc
    if proc.returncode != 0:
        raise DirectoryError("DNS_ERROR_TEMPORARY", "DNS lookup tool failed")

    txt_values: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # answer line: name TTL IN TXT "value"  |  name TTL IN CNAME target.
        parts = line.split()
        if len(parts) >= 4 and parts[3] == "CNAME":
            target = parts[4].rstrip(".").lower()
            if not _within(registrable_domain(domain), registrable_domain(target)):
                raise DirectoryError(
                    "DNS_TXT_NOT_FOUND", "off-domain CNAME is not accepted"
                )
            continue
        if len(parts) >= 5 and parts[3] == "TXT":
            value = " ".join(parts[4:]).strip('"')
            txt_values.append(value)

    for value in txt_values:
        if value == token or value.startswith(_TOKEN_PREFIX + token):
            return
    raise DirectoryError(
        "DNS_TXT_NOT_FOUND", "token not found in _haap TXT records"
    )


class _SameDomainRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only within the same registrable domain."""

    def __init__(self, domain: str) -> None:
        super().__init__()
        self._domain = domain

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        target = urlsplit(newurl)
        if target.scheme != "https":
            raise urllib.error.URLError("insecure redirect")
        host = (target.hostname or "").lower()
        if not _within(registrable_domain(self._domain), host):
            raise urllib.error.URLError("redirect leaves the registrable domain")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_well_known(domain: str, path: str) -> bytes:
    url = f"https://{domain}{path}"
    opener = urllib.request.build_opener(_SameDomainRedirect(domain))
    req = urllib.request.Request(url, method="GET")
    with opener.open(req, timeout=_HTTPS_TIMEOUT_S) as resp:
        return resp.read(_MAX_WELL_KNOWN_BYTES + 1)


def check_https_well_known(domain: str, token: str) -> None:
    """Fetch the well-known file over TLS and require the token."""
    body: bytes
    try:
        body = _fetch_well_known(domain, "/.well-known/haap-verify.txt")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise DirectoryError(
                "WELL_KNOWN_NOT_FOUND", "well-known file unreachable"
            ) from exc
        try:
            body = _fetch_well_known(domain, "/.well-known/haap-verify.json")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            raise DirectoryError(
                "WELL_KNOWN_NOT_FOUND", "well-known file unreachable"
            ) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise DirectoryError(
            "WELL_KNOWN_NOT_FOUND", "well-known file unreachable"
        ) from exc

    text = body.decode("utf-8", errors="replace").strip()
    if text == token:
        return
    # JSON variant: {"haap_verify_token": "<token>"}
    try:
        parsed = json.loads(text)
        if (
            isinstance(parsed, dict)
            and parsed.get("haap_verify_token") == token
        ):
            return
    except ValueError:
        pass
    raise DirectoryError("WELL_KNOWN_MISMATCH", "token absent or wrong")
