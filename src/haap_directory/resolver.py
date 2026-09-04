# -*- coding: utf-8 -*-
"""Domain-control resolvers for L2 verification (SPEC §3.3, §8 T-D08).

The directory performs L2 checks *itself* (the agent never reports its own
success): it resolves a DNS TXT record, or fetches a well-known file over TLS.
The resolver is an injectable seam so tests can stub DNS/HTTP deterministically
and so production can choose its DNS library.

SSRF containment: ``fetch_well_known`` only ever fetches
``https://<domain>/.well-known/haap-verify.{txt,json}`` for the exact,
already-validated domain, verifies TLS against public CAs, caps the body size,
enforces a timeout, and refuses redirects to a different registrable domain.
Registration never contacts the agent's endpoint at all.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Protocol

WELL_KNOWN_PATHS = ("/.well-known/haap-verify.txt", "/.well-known/haap-verify.json")


class ResolverTemporary(Exception):
    """Transient failure (DNS servfail, timeout) — the caller may retry."""


class ResolverNotFound(Exception):
    """The record/file does not exist or is not fetchable."""


class Resolver(Protocol):
    def resolve_txt(self, name: str) -> list[str]:
        """Return the TXT strings at ``name`` ([] if none); raise on transient."""

    def fetch_well_known(self, domain: str) -> str:
        """Return the well-known file body for ``domain``; raise if absent."""


def _registrable(host: str) -> str:
    """A cheap registrable-domain approximation (last two labels).

    Not a public-suffix-list implementation; sufficient to reject blatant
    off-domain redirects. Multi-label ccTLDs are treated conservatively.
    """
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


class SystemResolver:
    """Real resolver: dnspython for TXT (optional), stdlib TLS for well-known."""

    def __init__(self, timeout_s: int = 10, max_bytes: int = 4096):
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes

    def resolve_txt(self, name: str) -> list[str]:
        try:
            import dns.resolver  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ResolverTemporary(
                "DNS TXT resolution requires the optional 'dnspython' dependency"
            ) from exc
        try:  # pragma: no cover - network dependent
            answers = dns.resolver.resolve(name, "TXT", lifetime=self.timeout_s)
        except dns.resolver.NXDOMAIN:  # pragma: no cover
            return []
        except dns.resolver.NoAnswer:  # pragma: no cover
            return []
        except Exception as exc:  # pragma: no cover - servfail/timeout
            raise ResolverTemporary(str(exc)) from exc
        out: list[str] = []
        for rdata in answers:  # pragma: no cover - network dependent
            out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        return out

    def fetch_well_known(self, domain: str) -> str:  # pragma: no cover - network
        registrable = _registrable(domain)
        ctx = ssl.create_default_context()
        last_exc: Exception | None = None
        for path in WELL_KNOWN_PATHS:
            url = f"https://{domain}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "haap-dird/verify"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s, context=ctx) as r:
                    final_host = urllib.parse.urlparse(r.geturl()).hostname or ""
                    if _registrable(final_host) != registrable:
                        raise ResolverNotFound("redirect left the registrable domain")
                    return r.read(self.max_bytes + 1)[: self.max_bytes].decode(
                        "utf-8", "replace"
                    )
            except urllib.error.HTTPError as exc:
                last_exc = ResolverNotFound(f"HTTP {exc.code}")
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                last_exc = ResolverTemporary(str(exc))
        if isinstance(last_exc, ResolverTemporary):
            raise last_exc
        raise last_exc or ResolverNotFound("well-known not fetchable")
