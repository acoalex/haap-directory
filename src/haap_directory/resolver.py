# -*- coding: utf-8 -*-
"""Domain-control resolver seam for L2 verification (SPEC §3.3, §8 T-D08).

The directory performs L2 checks *itself* (the agent never reports its own
success). The check is an injectable seam so tests stub DNS/HTTP
deterministically and production chooses its mechanism.

``SystemResolver`` delegates to :mod:`haap_directory.verify`, which resolves
``_haap.<domain>`` TXT via the system ``dig`` (rejecting off-registrable-domain
CNAMEs) and fetches the well-known file over TLS (same-registrable-domain
redirects only, size/timeout capped). Both raise ``DirectoryError`` with the
stable §4.10 codes on failure, so no extra Python DNS dependency is required.
"""

from __future__ import annotations

from typing import Protocol

from . import verify


class Resolver(Protocol):
    def check(self, domain: str, method: str, token: str) -> None:
        """Verify domain control; raise ``DirectoryError`` on failure."""


class SystemResolver:
    """Real resolver: ``dig`` for DNS TXT, stdlib TLS for well-known."""

    def check(self, domain: str, method: str, token: str) -> None:
        if method == "dns_txt":
            verify.check_dns_txt(domain, token)
        else:
            verify.check_https_well_known(domain, token)
