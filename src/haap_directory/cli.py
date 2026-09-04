# -*- coding: utf-8 -*-
"""``haap-dird`` command-line entry point (SPEC §9.1).

    haap-dird --db /var/lib/haap/dird.db --host 0.0.0.0 --port 8444 \
        --ttl-hours 24 --max-agents 10000
    haap-dird --prune       # offline prune of expired entries
    haap-dird --gen-key     # mint/show the directory signing key

Config precedence: CLI flags > ~/.haap/dird.json > env HAAP_DIRD_* > defaults.
Graceful shutdown on SIGTERM/SIGINT flushes and closes the database.
"""

from __future__ import annotations

import argparse
import signal
import sys
from typing import Optional

from . import __version__
from .config import DirectoryConfig
from .http_api import DirectoryHTTPServer
from .identity import fingerprint_of_public_key
from .keystore import load_or_create_key
from .store import Store
from .timeutil import system_clock


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="haap-dird", description="HAAP Public Directory service"
    )
    p.add_argument("--db", dest="db_path", help="SQLite database path")
    p.add_argument("--host", help="bind host")
    p.add_argument("--port", type=int, help="bind port (0 = ephemeral)")
    p.add_argument("--ttl-hours", dest="ttl_hours", type=float, help="entry TTL in hours")
    p.add_argument("--max-agents", dest="max_agents", type=int, help="listed-agent cap")
    p.add_argument("--key", dest="key_path", help="directory signing key file")
    p.add_argument("--config", dest="config_path", help="config file path")
    p.add_argument("--prune", action="store_true", help="prune expired entries and exit")
    p.add_argument("--gen-key", action="store_true", help="mint/show directory key and exit")
    p.add_argument("--version", action="version", version=f"haap-dird {__version__}")
    return p


def _cli_overrides(args: argparse.Namespace) -> dict:
    keys = ("db_path", "host", "port", "ttl_hours", "max_agents", "key_path")
    return {k: getattr(args, k) for k in keys if getattr(args, k) is not None}


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    config = DirectoryConfig.load(
        cli_overrides=_cli_overrides(args), config_path=args.config_path
    )

    if args.prune:
        store = Store(config.db_path, clock=system_clock)
        pruned = store.prune_expired()
        store.close()
        print(f"pruned {pruned} expired entr{'y' if pruned == 1 else 'ies'}")
        return 0

    keypair = load_or_create_key(config.resolved_key_path())
    fingerprint = fingerprint_of_public_key(keypair.public_key)

    if args.gen_key:
        print(f"directory_fingerprint: {fingerprint}")
        print(f"key_path: {config.resolved_key_path()}")
        return 0

    server = DirectoryHTTPServer.build(config, keypair, clock=system_clock)

    def _shutdown(_signum, _frame):
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(
        f"haap-dird {__version__} listening on {config.host}:{config.port} "
        f"(db={config.db_path}, directory_fingerprint={fingerprint})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
