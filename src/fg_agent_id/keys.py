"""Key material for an agent: Ed25519 (signing) + X25519 (key agreement).

Private keys never leave this module's objects; everything that crosses the
wire is a public key or a signature.
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .errors import SignatureError

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Encrypted key-file parameters. scrypt cost is tuned for interactive unlock
# (~100ms); raise _SCRYPT_N if key files may be exposed to offline attack.
_KEYFILE_MAGIC = b"FGID"
_KEYFILE_VERSION = 1
_SALT_BYTES = 16
_NONCE_BYTES = 12
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    # NFC-normalize first: the same passphrase typed on different platforms can
    # arrive as different byte sequences (macOS composes to NFD), which would
    # lock the owner out of their own key file. Same reasoning as canonical.py.
    normalized = unicodedata.normalize("NFC", passphrase)
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(normalized.encode("utf-8"))


def base58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = _ALPHABET[rem] + encoded
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + encoded


def base58_decode(text: str) -> bytes:
    num = 0
    for char in text:
        num = num * 58 + _ALPHABET.index(char)
    decoded = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = 0
    for char in text:
        if char == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + decoded


def _raw_public(key: Ed25519PublicKey | X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class KeyPair:
    """An agent's full key material (holds private keys)."""

    signing_key: Ed25519PrivateKey
    agreement_key: X25519PrivateKey

    @classmethod
    def generate(cls) -> KeyPair:
        return cls(
            signing_key=Ed25519PrivateKey.generate(),
            agreement_key=X25519PrivateKey.generate(),
        )

    @property
    def public(self) -> PublicKeys:
        return PublicKeys(
            signing=_raw_public(self.signing_key.public_key()),
            agreement=_raw_public(self.agreement_key.public_key()),
        )

    def sign(self, message: bytes) -> bytes:
        return self.signing_key.sign(message)

    def to_bytes(self) -> bytes:
        """Serialize private keys (64 bytes: signing || agreement). Caller owns secrecy."""
        signing = self.signing_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        agreement = self.agreement_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return signing + agreement

    @classmethod
    def from_bytes(cls, data: bytes) -> KeyPair:
        if len(data) != 64:
            raise ValueError("KeyPair serialization must be exactly 64 bytes")
        return cls(
            signing_key=Ed25519PrivateKey.from_private_bytes(data[:32]),
            agreement_key=X25519PrivateKey.from_private_bytes(data[32:]),
        )

    def to_encrypted_bytes(self, passphrase: str) -> bytes:
        """Serialize under a passphrase, so key files are not plaintext secrets.

        Format: ``FGID`` || version || salt(16) || nonce(12) || ciphertext,
        with scrypt for the KDF and ChaCha20-Poly1305 for the sealing. The
        header is authenticated, so a tampered version byte fails to open
        rather than silently selecting different parameters.
        """
        if not passphrase:
            raise ValueError("passphrase must not be empty")
        salt = os.urandom(_SALT_BYTES)
        nonce = os.urandom(_NONCE_BYTES)
        header = _KEYFILE_MAGIC + bytes([_KEYFILE_VERSION])
        key = _derive_key(passphrase, salt)
        sealed = ChaCha20Poly1305(key).encrypt(nonce, self.to_bytes(), header)
        return header + salt + nonce + sealed

    @classmethod
    def from_encrypted_bytes(cls, data: bytes, passphrase: str) -> KeyPair:
        """Open a passphrase-sealed keypair. Raises ValueError if it won't open."""
        header = _KEYFILE_MAGIC + bytes([_KEYFILE_VERSION])
        prefix = len(header) + _SALT_BYTES + _NONCE_BYTES
        if len(data) <= prefix or not data.startswith(_KEYFILE_MAGIC):
            raise ValueError("not an encrypted fareground key file")
        if data[len(_KEYFILE_MAGIC)] != _KEYFILE_VERSION:
            raise ValueError(f"unsupported key file version: {data[len(_KEYFILE_MAGIC)]}")
        salt = data[len(header):len(header) + _SALT_BYTES]
        nonce = data[len(header) + _SALT_BYTES:prefix]
        key = _derive_key(passphrase, salt)
        try:
            plain = ChaCha20Poly1305(key).decrypt(nonce, data[prefix:], header)
        except Exception as exc:
            raise ValueError("could not decrypt key file — wrong passphrase or corrupt") from exc
        return cls.from_bytes(plain)


@dataclass(frozen=True)
class PublicKeys:
    """Public halves, safe to publish (raw 32-byte keys)."""

    signing: bytes
    agreement: bytes

    def verify(self, signature: bytes, message: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self.signing).verify(signature, message)
        except InvalidSignature as exc:
            raise SignatureError("Ed25519 signature verification failed") from exc

    @property
    def signing_b58(self) -> str:
        return base58_encode(self.signing)

    @property
    def agreement_b58(self) -> str:
        return base58_encode(self.agreement)

    def x25519_public(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self.agreement)
