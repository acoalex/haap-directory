# -*- coding: utf-8 -*-
"""Canonical JSON — the single serialization used for every signature.

This MUST be byte-for-byte identical to the canonical form used by the
``haap`` client package (``haap/registry_client.py`` and
``haap/envelope.py``):

    json.dumps(obj, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False).encode("utf-8")

Any deviation breaks signature verification. It is deliberately vendored
here (rather than imported from ``haap``) so the directory has no hard
import dependency on the client package — see SPEC §6.3.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Return the canonical UTF-8 byte serialization of ``obj``."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_str(obj: Any) -> str:
    """Canonical JSON as a ``str`` (for hashing/logging convenience)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
