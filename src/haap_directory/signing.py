# -*- coding: utf-8 -*-
"""Helpers to verify Ed25519-signed request bodies (SPEC §3.3/§3.4/§3.5).

Mutating agent endpoints have no session auth — the key is the credential.
Each request carries a signature by the agent (or moderator) key over the
canonical JSON of a defined subset of the body. These helpers centralize that
check so every handler enforces it identically.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json
from .crypto import b64d, verify_with


def verify_over(pubkey_b64: str, payload: Any, signature_b64: str) -> bool:
    """Verify ``signature_b64`` over ``canonical_json(payload)`` with a key."""
    try:
        raw_pub = b64d(pubkey_b64)
        sig = b64d(signature_b64)
    except Exception:  # noqa: BLE001 - malformed base64
        return False
    return verify_with(raw_pub, canonical_json(payload), sig)


def subset(body: dict, fields: tuple[str, ...]) -> dict:
    """The signed subset of a body (only the named fields that are present)."""
    return {k: body[k] for k in fields if k in body}
