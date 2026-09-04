# -*- coding: utf-8 -*-
"""Per-key token-bucket rate limiting (SPEC §2.7.7, §5, §8 T-D09).

Anonymous endpoints are limited per client IP; agent-mutating endpoints can
additionally be limited per fingerprint. Buckets refill continuously. The
clock is injectable so flood tests are deterministic.

This is intentionally in-memory: it protects a single instance. Multi-instance
deployments put a shared limiter / WAF in front (documented in OPERATE.md).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

from .timeutil import Clock, system_clock


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """A named set of token buckets keyed by an arbitrary string."""

    def __init__(self, capacity: int, refill_seconds: float, clock: Clock = system_clock):
        self.capacity = float(capacity)
        # tokens added per second to fully refill over ``refill_seconds``.
        self.rate = self.capacity / float(refill_seconds) if refill_seconds > 0 else 0.0
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Consume one token for ``key``.

        Returns ``(allowed, retry_after_seconds)``. When denied, retry_after
        is the whole seconds until one token is available.
        """
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate)
            bucket.updated = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0
            missing = 1.0 - bucket.tokens
            retry_after = int(missing / self.rate) + 1 if self.rate > 0 else 3600
            return False, retry_after

    def remaining(self, key: str) -> int:
        with self._lock:
            bucket = self._buckets.get(key)
            return int(bucket.tokens) if bucket else int(self.capacity)


class RateLimiterSet:
    """The directory's named limiters (search, register)."""

    def __init__(self, config, clock: Clock = system_clock):
        self.search = RateLimiter(config.rate_search_per_min, 60.0, clock)
        self.register = RateLimiter(config.rate_register_per_hour, 3600.0, clock)
