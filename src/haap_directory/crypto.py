# -*- coding: utf-8 -*-
"""Ed25519 primitives for the directory (verification-first).

The directory only ever *verifies* agent signatures; it also owns a single
"directory key" used to sign challenge nonces and (L5) audit checkpoints.

These are thin standalone wrappers over ``cryptography`` with the exact
encoding conventions of the ``haap`` client (raw 32-byte keys, standard
base64), so the directory needs no import dependency on the client package.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64e(data: bytes) -> str:
    """Standard base64 encode: bytes -> ASCII str."""
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """Standard base64 decode: str -> bytes (raises on invalid input)."""
    return base64.b64decode(data.encode("ascii"))


def _public_key_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _private_key_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def verify_with(raw_pub: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 ``signature`` over ``data`` with a raw public key.

    Returns ``False`` on any failure (bad signature, malformed key/sig)
    rather than raising, so callers never leak crypto internals.
    """
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass
class KeyPair:
    """Ed25519 key pair (raw 32-byte keys) — used for the directory key."""

    public_key: bytes = field(repr=False)
    private_key: bytes = field(repr=False)

    @classmethod
    def generate(cls) -> "KeyPair":
        priv = Ed25519PrivateKey.generate()
        return cls(
            public_key=_public_key_bytes(priv.public_key()),
            private_key=_private_key_bytes(priv),
        )

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyPair":
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(public_key=_public_key_bytes(priv.public_key()), private_key=raw)

    def public_key_b64(self) -> str:
        return b64e(self.public_key)

    def private_key_b64(self) -> str:
        return b64e(self.private_key)

    def sign(self, data: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(self.private_key).sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        return verify_with(self.public_key, data, signature)
