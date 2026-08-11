"""Key files on disk: the one-liner persistence layer.

Two formats, both already part of the standard — nothing new is invented here:

- **Plain**: the raw 64-byte ``signing || agreement`` form
  (``KeyPair.to_bytes``). The file IS the secret; the caller owns its safety.
- **Encrypted**: the ``FGID`` v1 container (scrypt + ChaCha20-Poly1305,
  ``KeyPair.to_encrypted_bytes``), selected by passing a passphrase.

``load_or_create_keys`` is the entry point behind
``AgentIdentity.load_or_create`` / ``OwnerIdentity.load_or_create``.
"""

from __future__ import annotations

import os
from pathlib import Path

from .keys import _KEYFILE_MAGIC, KeyPair

_RAW_KEY_BYTES = 64


def save_keys(keys: KeyPair, path: str | Path, passphrase: str | None = None) -> None:
    """Write a keypair to ``path`` (mode 0600), encrypted when a passphrase is given."""
    data = keys.to_encrypted_bytes(passphrase) if passphrase else keys.to_bytes()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    os.chmod(target, 0o600)


def load_keys(path: str | Path, passphrase: str | None = None) -> KeyPair:
    """Read a keypair from ``path``, detecting plain vs encrypted format."""
    data = Path(path).read_bytes()
    if data.startswith(_KEYFILE_MAGIC):
        if not passphrase:
            raise ValueError(
                f"key file {path} is encrypted — pass the passphrase it was created with"
            )
        return KeyPair.from_encrypted_bytes(data, passphrase)
    if passphrase:
        raise ValueError(
            f"key file {path} is not encrypted, but a passphrase was given — "
            "refusing to guess which was intended"
        )
    if len(data) != _RAW_KEY_BYTES:
        raise ValueError(
            f"key file {path} is corrupt: expected {_RAW_KEY_BYTES} raw bytes "
            f"or an encrypted FGID container, got {len(data)} bytes"
        )
    return KeyPair.from_bytes(data)


def load_or_create_keys(path: str | Path, passphrase: str | None = None) -> KeyPair:
    """Load the keypair at ``path`` if it exists; otherwise generate and save one."""
    if Path(path).exists():
        return load_keys(path, passphrase)
    keys = KeyPair.generate()
    save_keys(keys, path, passphrase)
    return keys
