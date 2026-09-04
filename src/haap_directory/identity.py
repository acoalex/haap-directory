# -*- coding: utf-8 -*-
"""Fingerprint helpers — identical semantics to ``haap.identity``.

Fingerprint = ``"HF-"`` + first 16 hex chars of ``sha256(raw_public_key)``.
The directory NEVER trusts a client-supplied fingerprint: it always
recomputes it from the presented public key (SPEC §2.7.2).
"""

from __future__ import annotations

import hashlib
import re

FINGERPRINT_PREFIX = "HF-"
FINGERPRINT_HEX_LEN = 16
FINGERPRINT_RE = re.compile(r"^HF-[0-9a-f]{16}$")


def fingerprint_of_public_key(pub_raw: bytes) -> str:
    """Compute the HAAP fingerprint of a raw 32-byte Ed25519 public key."""
    digest = hashlib.sha256(pub_raw).hexdigest()
    return FINGERPRINT_PREFIX + digest[:FINGERPRINT_HEX_LEN]


def is_fingerprint(value: str) -> bool:
    return bool(FINGERPRINT_RE.match(value or ""))
