# -*- coding: utf-8 -*-
"""Extended manifest validation (SPEC §5.1).

Validates the ``haap-public-manifest-v1`` object an agent registers, with
the hard rules that protect the signed wire form:

* fingerprint matches ``^HF-[0-9a-f]{16}$`` (bound to the key server-side);
* endpoint is ``http(s)://`` with no query, fragment, or URL credentials;
* NO forbidden field (``private_key`` / ``signature`` / ``nonce``) at any
  depth (mirrors ``haap.capabilities.parse_manifest``);
* NO float anywhere (canonical JSON forbids floats — prices are strings,
  geo is integer micro-degrees). This is the single most common v1 bug.

Validation NEVER mutates the manifest: its canonical byte form must remain
identical to what the agent signed.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from . import MANIFEST_FORMAT
from .errors import DirectoryError
from .identity import FINGERPRINT_RE

FORBIDDEN_FIELDS = ("private_key", "signature", "nonce")
_ALLOWED_SCHEMES = ("http", "https")


def _scan_forbidden_and_floats(node: object, path: str = "$") -> None:
    """Recursively reject forbidden keys and any float value."""
    if isinstance(node, float):
        raise DirectoryError(
            "FLOAT_FORBIDDEN", f"float value at {path} is not allowed in a signed manifest"
        )
    if isinstance(node, dict):
        for key, value in node.items():
            if key in FORBIDDEN_FIELDS:
                raise DirectoryError(
                    "FORBIDDEN_FIELD", f"forbidden field '{key}' present in manifest"
                )
            _scan_forbidden_and_floats(value, f"{path}.{key}")
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            _scan_forbidden_and_floats(value, f"{path}[{index}]")


def validate_endpoint(endpoint: str) -> None:
    """Validate the declared messaging endpoint (SPEC §5.1)."""
    if not isinstance(endpoint, str) or not endpoint:
        raise DirectoryError("ENDPOINT_INVALID", "endpoint is required")
    parts = urlsplit(endpoint)
    if parts.scheme not in _ALLOWED_SCHEMES:
        raise DirectoryError("ENDPOINT_INVALID", "endpoint must be http:// or https://")
    if not parts.netloc or not parts.hostname:
        raise DirectoryError("ENDPOINT_INVALID", "endpoint has no host")
    if parts.query or parts.fragment:
        raise DirectoryError("ENDPOINT_INVALID", "endpoint must not contain a query or fragment")
    if parts.username or parts.password:
        raise DirectoryError("ENDPOINT_INVALID", "endpoint must not contain credentials")


def validate_manifest(manifest: object) -> dict:
    """Validate a parsed manifest dict; return it unchanged on success.

    Raises ``DirectoryError`` with a stable code on the first violation.
    """
    if not isinstance(manifest, dict):
        raise DirectoryError("INVALID_SCHEMA", "manifest must be a JSON object")

    if manifest.get("format") != MANIFEST_FORMAT:
        raise DirectoryError("INVALID_SCHEMA", "unsupported manifest format")

    agent = manifest.get("agent")
    if not isinstance(agent, dict):
        raise DirectoryError("INVALID_SCHEMA", "manifest.agent must be an object")

    fingerprint = agent.get("fingerprint")
    if not isinstance(fingerprint, str) or not FINGERPRINT_RE.match(fingerprint):
        raise DirectoryError("INVALID_SCHEMA", "agent.fingerprint has an invalid format")

    # Forbidden fields + floats anywhere (checked before touching endpoint so
    # a float/forbidden field always wins its dedicated stable code).
    _scan_forbidden_and_floats(manifest)

    validate_endpoint(agent.get("endpoint"))

    roles = manifest.get("roles_accepted")
    if roles is not None:
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise DirectoryError("INVALID_SCHEMA", "roles_accepted must be a list of strings")

    services = manifest.get("services")
    if services is not None:
        if not isinstance(services, list):
            raise DirectoryError("INVALID_SCHEMA", "services must be a list")
        for svc in services:
            if not isinstance(svc, dict) or not isinstance(svc.get("id"), str):
                raise DirectoryError("INVALID_SCHEMA", "each service needs a string id")

    return manifest
