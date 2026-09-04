# -*- coding: utf-8 -*-
"""HAAP Public Directory service.

The federated "phone book" of the HAAP (Hermes Agent Alliance Protocol)
ecosystem: agents register a signed capability manifest, prove control of
their messaging endpoint (proof-of-endpoint), keep their entry alive with
signed heartbeats, and are discoverable by search.

Design principle (never violated): *the directory is a phone book, not a
notary.* Identity lives in the agents' Ed25519 keys, not in the directory.
The directory indexes signed manifests and verifies endpoint control; its
compromise must never allow impersonation.

This package is stdlib-first (``http.server`` + ``sqlite3``); the only hard
dependency is ``cryptography`` for Ed25519 verification. It stays wire
compatible with the unmodified ``haap`` client package (legacy routes in
``http_api``) while exposing a canonical ``/v1`` API (see ``docs/SPEC.md``).
"""

__version__ = "0.1.0"
PROTOCOL_VERSION = "1.0"
MANIFEST_FORMAT = "haap-public-manifest-v1"

__all__ = ["__version__", "PROTOCOL_VERSION", "MANIFEST_FORMAT"]
