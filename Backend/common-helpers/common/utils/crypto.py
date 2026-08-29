"""Cryptographic primitives for Pingora.

Two independent layers live here:

1. Envelope encryption (``encrypt_payload`` / ``decrypt_payload``) --
   RSA-OAEP-SHA256 wraps a fresh AES-256-GCM content key. Used to encrypt JWT
   claim sets and, optionally, HTTP request/response bodies. Only the holder of
   the private key can unwrap; GCM supplies integrity.

2. Symmetric AEAD (``aes_encrypt`` / ``aes_decrypt``) -- AES-256-GCM under a
   single shared key from settings. Cheaper; used for short-lived server-side
   values that never leave the trust boundary.

Both formats are versioned so the wire format can evolve without ambiguity.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common.config.settings import get_settings

AES_KEY_SIZE = 32    # AES-256
AES_NONCE_SIZE = 12  # 96-bit nonce, the GCM standard
GCM_TAG_SIZE = 16

_ENVELOPE_VERSION = b"\x01"
_AEAD_VERSION = b"\x01"

_lock = threading.Lock()
_rsa_private_key: rsa.RSAPrivateKey | None = None
_rsa_public_key: rsa.RSAPublicKey | None = None


class CryptoError(Exception):
    """Raised when encryption or decryption fails. Never leaks plaintext."""


# --- Key management -------------------------------------------------------
def _load_keys() -> tuple[rsa.RSAPrivateKey | None, rsa.RSAPublicKey]:
    global _rsa_private_key, _rsa_public_key

    if _rsa_public_key is not None:
        return _rsa_private_key, _rsa_public_key

    with _lock:
        if _rsa_public_key is not None:
            return _rsa_private_key, _rsa_public_key

        settings = get_settings()

        try:
            with open(settings.rsa_public_key_path, "rb") as fh:
                public_key = serialization.load_pem_public_key(
                    fh.read(), backend=default_backend()
                )
        except FileNotFoundError as exc:
            raise CryptoError(
                f"RSA public key not found at {settings.rsa_public_key_path}. "
                "Run scripts/generate_secrets.py."
            ) from exc

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CryptoError("Configured public key is not an RSA key")

        private_key = None
        if os.path.exists(settings.rsa_private_key_path):
            with open(settings.rsa_private_key_path, "rb") as fh:
                loaded = serialization.load_pem_private_key(
                    fh.read(), password=None, backend=default_backend()
                )
            if not isinstance(loaded, rsa.RSAPrivateKey):
                raise CryptoError("Configured private key is not an RSA key")
            if loaded.key_size < 2048:
                raise CryptoError("RSA key must be at least 2048 bits")
            private_key = loaded

        _rsa_private_key, _rsa_public_key = private_key, public_key
        return _rsa_private_key, _rsa_public_key


def reset_key_cache() -> None:
    global _rsa_private_key, _rsa_public_key
    with _lock:
        _rsa_private_key = _rsa_public_key = None


def _oaep() -> asym_padding.OAEP:
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# --- Envelope encryption: RSA-OAEP + AES-256-GCM --------------------------
def encrypt_payload(payload: Any, *, aad: bytes | None = None) -> str:
    _, public_key = _load_keys()

    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    content_key = os.urandom(AES_KEY_SIZE)
    nonce = os.urandom(AES_NONCE_SIZE)
    ciphertext = AESGCM(content_key).encrypt(nonce, plaintext, aad)

    wrapped_key = public_key.encrypt(content_key, _oaep())

    return _b64e(_ENVELOPE_VERSION + wrapped_key + nonce + ciphertext)


def decrypt_payload(token: str, *, aad: bytes | None = None) -> Any:
    private_key, _ = _load_keys()
    if private_key is None:
        raise CryptoError("No RSA private key available; this service cannot decrypt")

    try:
        envelope = _b64d(token)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("Malformed envelope encoding") from exc

    if not envelope or envelope[:1] != _ENVELOPE_VERSION:
        raise CryptoError("Unsupported envelope version")

    key_size = private_key.key_size // 8
    body = envelope[1:]
    if len(body) < key_size + AES_NONCE_SIZE + GCM_TAG_SIZE:
        raise CryptoError("Envelope truncated")

    wrapped_key = body[:key_size]
    nonce = body[key_size : key_size + AES_NONCE_SIZE]
    ciphertext = body[key_size + AES_NONCE_SIZE :]

    try:
        content_key = private_key.decrypt(wrapped_key, _oaep())
        plaintext = AESGCM(content_key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # noqa: BLE001
        # Deliberately opaque: distinguishing an unwrap failure from a tag
        # failure would hand an attacker a padding oracle.
        raise CryptoError("Payload decryption failed") from exc

    return json.loads(plaintext.decode())


# --- Symmetric AEAD under the shared key ----------------------------------
def _shared_key() -> bytes:
    return base64.b64decode(get_settings().aes_secret_key)


def aes_encrypt(data: str, *, aad: bytes | None = None) -> str:
    """AES-256-GCM encrypt a string. Layout: version || nonce || ct+tag."""
    nonce = os.urandom(AES_NONCE_SIZE)
    ciphertext = AESGCM(_shared_key()).encrypt(nonce, data.encode(), aad)
    return _b64e(_AEAD_VERSION + nonce + ciphertext)


def aes_decrypt(token: str, *, aad: bytes | None = None) -> str:
    try:
        raw = _b64d(token)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("Malformed ciphertext encoding") from exc

    if not raw or raw[:1] != _AEAD_VERSION:
        raise CryptoError("Unsupported ciphertext version")

    body = raw[1:]
    if len(body) < AES_NONCE_SIZE + GCM_TAG_SIZE:
        raise CryptoError("Ciphertext truncated")

    try:
        plaintext = AESGCM(_shared_key()).decrypt(
            body[:AES_NONCE_SIZE], body[AES_NONCE_SIZE:], aad
        )
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("Decryption failed") from exc

    return plaintext.decode()


# --- Keyed hashing --------------------------------------------------------
def hmac_sha256(message: str, key: str) -> str:
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def public_key_pem() -> str:
    _, public_key = _load_keys()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


# Backwards-compatible alias for the original misspelling.
encryp_payload = encrypt_payload
