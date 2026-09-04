# -*- coding: utf-8 -*-
"""Persistence of the directory's own Ed25519 signing key.

The directory key signs challenge nonces (legacy compatibility) and, from
L5, audit checkpoints. Its fingerprint is the ``directory_fingerprint``
returned on responses. The key is stored with 0600 permissions and is NEVER
part of any config object or manifest.
"""

from __future__ import annotations

import json
import os
import stat

from .crypto import KeyPair, b64d
from .identity import fingerprint_of_public_key

KEY_FORMAT = "haap-directory-key-v1"


def load_or_create_key(path: str) -> KeyPair:
    """Load the directory key from ``path`` or mint and persist a new one."""
    if os.path.exists(path):
        return load_key(path)
    kp = KeyPair.generate()
    save_key(kp, path)
    return kp


def load_key(path: str) -> KeyPair:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("format") != KEY_FORMAT:
        raise ValueError("unrecognized directory key format")
    return KeyPair.from_private_bytes(b64d(data["private_key"]))


def save_key(kp: KeyPair, path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    payload = {
        "format": KEY_FORMAT,
        "fingerprint": fingerprint_of_public_key(kp.public_key),
        "public_key": kp.public_key_b64(),
        "private_key": kp.private_key_b64(),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
