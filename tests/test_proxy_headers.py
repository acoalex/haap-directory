# -*- coding: utf-8 -*-
"""Proxy-header handling for per-IP rate limiting (reverse-proxy deployment).

When ``trust_proxy_headers`` is enabled and the TCP peer is loopback, the
client IP for rate limiting comes from CF-Connecting-IP / X-Forwarded-For so
each external client keeps its own bucket behind a shared reverse proxy.
When disabled (default), the header is ignored — it is spoofable.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from conftest import http_get


def _get_with_ip(url: str, ip: str) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, headers={"X-Forwarded-For": ip}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            import json as _json

            return r.status, _json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        import json as _json

        return e.code, _json.loads(e.read() or b"{}")


def test_proxy_headers_ignored_by_default(running):
    """Spoofed X-Forwarded-For must NOT change the rate-limit key by default."""
    low = running.server.config.rate_search_per_min
    # Exhaust the single 127.0.0.1 bucket with spoofed distinct IPs.
    for _ in range(low + 5):
        status, _ = _get_with_ip(f"{running.url}/v1/search", ip="1.2.3.4")
        if status == 429:
            break
    # A request with a different spoofed IP is still throttled (same bucket).
    status, _ = _get_with_ip(f"{running.url}/v1/search", ip="5.6.7.8")
    assert status == 429


def test_proxy_headers_trusted_when_enabled(make_server):
    running = make_server(trust_proxy_headers=True, rate_search_per_min=3)
    # Exhaust the bucket for 9.9.9.9 only.
    status = 200
    for _ in range(4):
        status, _ = _get_with_ip(f"{running.url}/v1/search", ip="9.9.9.9")
    assert status == 429
    # A different client IP still has its own bucket.
    status, _ = _get_with_ip(f"{running.url}/v1/search", ip="8.8.8.8")
    assert status == 200
    # And no header at all falls back to the loopback peer.
    status, _ = http_get(f"{running.url}/v1/search")
    assert status == 200
