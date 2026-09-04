# -*- coding: utf-8 -*-
"""Directory configuration with documented precedence.

Precedence (highest wins): CLI flags > ``~/.haap/dird.json`` > env
``HAAP_DIRD_*`` > built-in defaults (SPEC §9.1).

Only plain, non-secret operational settings live here. The directory
signing key is handled separately (see ``keystore.py``): it is never
embedded in this config object.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.haap/dird.json")

_ENV_PREFIX = "HAAP_DIRD_"


@dataclass
class DirectoryConfig:
    """Operational configuration for a directory instance."""

    db_path: str = "dird.db"
    host: str = "0.0.0.0"
    port: int = 8444
    ttl_hours: float = 24.0
    challenge_ttl_s: int = 120
    max_agents: int = 10_000
    max_pending_challenges: int = 5_000
    max_manifest_bytes: int = 256 * 1024
    max_body_bytes: int = 512 * 1024
    # Anonymous per-IP rate limits (capacity, refill window seconds).
    rate_search_per_min: int = 60
    rate_register_per_hour: int = 5
    # L2 domain verification (SPEC §3.3).
    domain_challenge_ttl_s: int = 1800        # token TTL: 30 minutes
    domain_validity_days: float = 90.0        # verified signal lifetime
    max_pending_domain_verifications: int = 5 # per agent (§4.3)
    # Trust X-Forwarded-For / CF-Connecting-IP from loopback peers only
    # (set true when running behind a trusted local reverse proxy).
    trust_proxy_headers: bool = False
    # L4 moderator keys (SPEC §3.5.5): base64 Ed25519 public keys authorised
    # to takedown / suspend / unsuspend / resolve appeals. Empty => moderation
    # endpoints reject with MODERATOR_UNKNOWN (directory is consumer-only).
    moderator_key_b64: list[str] = field(default_factory=list)
    # L4 automation thresholds (SPEC §3.5.2).
    report_auto_suspend_count: int = 3     # unique eligible reporters (7d)
    report_suspend_window_s: int = 7 * 86400
    report_decay_s: int = 180 * 86400      # > this age stops counting
    report_duplicate_window_s: int = 24 * 3600
    report_throttle_window_s: int = 24 * 3600
    report_war_window_s: int = 30 * 86400
    reporter_min_tenure_s: int = 72 * 3600
    vouch_max_outgoing: int = 10           # cap active outgoing vouches
    vouch_max_days: int = 180              # max expiry horizon
    key_path: str = ""  # directory signing key file; "" -> alongside db

    @property
    def ttl_seconds(self) -> float:
        return self.ttl_hours * 3600.0

    def resolved_key_path(self) -> str:
        if self.key_path:
            return self.key_path
        base = os.path.splitext(os.path.abspath(self.db_path))[0]
        return base + ".dirkey.json"

    # -- construction with precedence -------------------------------------
    @classmethod
    def load(
        cls,
        cli_overrides: Optional[dict[str, Any]] = None,
        config_path: Optional[str] = None,
        environ: Optional[dict[str, str]] = None,
    ) -> "DirectoryConfig":
        """Build a config applying env, then file, then CLI overrides."""
        cfg = cls()
        environ = environ if environ is not None else dict(os.environ)

        # 1. defaults are already set on ``cfg``.
        # 2. environment variables (HAAP_DIRD_<UPPER_FIELD>).
        cfg._apply(cls._from_environ(environ))
        # 3. config file.
        path = config_path or environ.get(_ENV_PREFIX + "CONFIG") or DEFAULT_CONFIG_PATH
        cfg._apply(cls._from_file(path))
        # 4. CLI overrides (highest precedence).
        cfg._apply(cli_overrides or {})
        return cfg

    def _apply(self, values: dict[str, Any]) -> None:
        for key, value in values.items():
            if value is None:
                continue
            if hasattr(self, key):
                setattr(self, key, _coerce(getattr(self, key), value))

    @staticmethod
    def _from_environ(environ: dict[str, str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, value in environ.items():
            if not name.startswith(_ENV_PREFIX):
                continue
            field_name = name[len(_ENV_PREFIX):].lower()
            if field_name == "config":
                continue
            out[field_name] = value
        return out

    @staticmethod
    def _from_file(path: str) -> dict[str, Any]:
        if not path or not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}


def _coerce(current: Any, value: Any) -> Any:
    """Coerce ``value`` to the type of the existing default ``current``."""
    if isinstance(current, bool):
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if isinstance(current, int) and not isinstance(current, bool):
        return int(value)
    if isinstance(current, float):
        return float(value)
    return str(value) if isinstance(current, str) else value
