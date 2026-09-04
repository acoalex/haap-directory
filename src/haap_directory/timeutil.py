# -*- coding: utf-8 -*-
"""Time helpers and the injectable clock.

The whole service reads "now" through a ``Clock`` callable returning epoch
seconds (float). Tests inject a controllable clock so expiry/decay can be
exercised deterministically without sleeping real TTLs (SPEC §7 F2/F3/F4).

On the wire, timestamps are fixed-width RFC 3339 UTC strings
(``YYYY-MM-DDTHH:MM:SSZ``); server time is authoritative for all TTLs.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable

Clock = Callable[[], float]

# Default clock: real wall time.
system_clock: Clock = time.time


def to_rfc3339(epoch: float) -> str:
    """Format an epoch time as a fixed-width RFC 3339 UTC string.

    Integer-second precision keeps the format fixed-width, which makes the
    string both signature-stable and lexicographically ordered == time
    ordered.
    """
    dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def from_rfc3339(value: str) -> float:
    """Parse an RFC 3339 UTC timestamp to epoch seconds.

    Accepts a trailing ``Z`` or an explicit offset. Raises ``ValueError``
    on anything unparseable (callers map that to a stable error code).
    """
    if not isinstance(value, str) or not value:
        raise ValueError("empty timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()
