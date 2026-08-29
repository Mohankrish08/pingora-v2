"""JWT issuance and verification.

Token types
-----------
``access``  -- 15 min, sent as ``Authorization: Bearer``, held in memory by the
               SPA. Never persisted to localStorage.
``refresh`` -- 7 days, delivered in an HttpOnly cookie, fingerprint stored in
               ``user_sessions``, rotated on every use with reuse detection.
``mfa``     -- 5 min, issued after the password factor succeeds and consumed by
               ``/auth/verify-totp``. This is what stops an attacker from
               brute-forcing TOTP codes against a bare user id.

Signing algorithm
-----------------
Configurable. HS256 keeps a single shared secret; RS256 lets the auth service
hold the private key alone while every other service verifies with the public
key. Prefer RS256 once more than one service validates tokens.

Payload confidentiality
-----------------------
A signed JWT is readable by anyone holding it. When ``encrypt_jwt_payload`` is
on, the real claim set is sealed with RSA-OAEP + AES-256-GCM and carried in an
``enc`` claim; only routing metadata (``jti``, ``exp``) stays in the clear so
intermediaries can still expire tokens without reading them.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from jose import JWTError, jwt

from common.config.settings import get_settings
from common.utils.crypto import CryptoError, decrypt_payload, encrypt_payload, hmac_sha256

TokenType = Literal["access", "refresh", "mfa"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _signing_key() -> str:
    settings = get_settings()
    if settings.uses_asymmetric_jwt:
        with open(settings.rsa_private_key_path, "r", encoding="utf-8") as fh:
            return fh.read()
    return settings.jwt_secret_key


def _verification_key() -> str:
    settings = get_settings()
    if settings.uses_asymmetric_jwt:
        with open(settings.rsa_public_key_path, "r", encoding="utf-8") as fh:
            return fh.read()
    return settings.jwt_secret_key


def _envelope(inner_claims: dict[str, Any], jti: str, exp: int) -> dict[str, Any]:
    settings = get_settings()

    outer: dict[str, Any] = {
        "jti": jti,
        "exp": exp,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }

    if settings.encrypt_jwt_payload:
        outer["enc"] = encrypt_payload(inner_claims)
    else:
        outer["claims"] = inner_claims

    return outer


def _encode(outer_claims: dict[str, Any]) -> str:
    settings = get_settings()
    return jwt.encode(outer_claims, _signing_key(), algorithm=settings.jwt_algorithm)


# --- Access token ---------------------------------------------------------
def create_access_token(
    user_id: str,
    email: str,
    phone: str | None,
    display_name: str | None,
    unique_session_id: str,
    roles: list[str] | None = None,
) -> tuple[str, str]:
    """Return ``(token, jti)``.

    The CSRF token is minted separately by the route from the same session id;
    keeping the two concerns apart means a service that only needs to *verify*
    tokens never has to link against the CSRF module.
    """
    settings = get_settings()
    now = _utcnow()
    jti = secrets.token_urlsafe(24)
    exp = now + timedelta(minutes=settings.access_token_expire_minutes)

    inner_claims = {
        "sub": user_id,
        "email": email,
        "uid": unique_session_id,
        "phone": phone,
        "display_name": display_name,
        "roles": roles or ["user"],
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "type": "access",
    }

    return _encode(_envelope(inner_claims, jti, int(exp.timestamp()))), jti


# --- Refresh token --------------------------------------------------------
def create_refresh_token(
    user_id: str,
    unique_session_id: str,
) -> tuple[str, str, str]:
    """Return ``(token, jti, fingerprint)``.

    Only the fingerprint reaches the database. It is an HMAC rather than a bare
    SHA-256 so that a leaked ``user_sessions`` table cannot be attacked offline
    without also stealing the signing secret.
    """
    settings = get_settings()
    now = _utcnow()
    jti = secrets.token_urlsafe(24)
    exp = now + timedelta(days=settings.refresh_token_expire_days)

    inner_claims = {
        "sub": user_id,
        "uid": unique_session_id,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "type": "refresh",
    }

    token = _encode(_envelope(inner_claims, jti, int(exp.timestamp())))
    return token, jti, hash_refresh_token(token)


# --- MFA challenge token --------------------------------------------------
def create_mfa_challenge_token(user_id: str) -> tuple[str, str]:
    """Short-lived proof that the password factor already succeeded."""
    settings = get_settings()
    now = _utcnow()
    jti = secrets.token_urlsafe(24)
    exp = now + timedelta(minutes=settings.mfa_challenge_expire_minutes)

    inner_claims = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "type": "mfa",
    }

    return _encode(_envelope(inner_claims, jti, int(exp.timestamp()))), jti


# --- Decode and verify ----------------------------------------------------
def decode_token(token: str, expected_type: TokenType | None = None) -> dict[str, Any]:
    settings = get_settings()

    try:
        outer = jwt.decode(
            token,
            _verification_key(),
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
                "leeway": settings.jwt_leeway_seconds,
            },
        )
    except JWTError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise JWTError(f"Token verification failed: {exc}") from exc

    if "enc" in outer:
        try:
            claims = decrypt_payload(outer["enc"])
        except CryptoError as exc:
            raise JWTError("Token payload could not be decrypted") from exc
    elif "claims" in outer:
        claims = outer["claims"]
    else:
        raise JWTError("Token is missing its claim set")

    if not isinstance(claims, dict):
        raise JWTError("Token claim set is malformed")

    # The inner jti must match the outer one, otherwise a valid envelope could
    # be spliced onto a different signed header.
    if claims.get("jti") != outer.get("jti"):
        raise JWTError("Token claim set does not match its envelope")

    if expected_type is not None and claims.get("type") != expected_type:
        raise JWTError(f"Expected a {expected_type} token")

    return claims


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Convenience wrapper that also enforces the refresh type."""
    return decode_token(token, expected_type="refresh")


def hash_refresh_token(token: str) -> str:
    """Fingerprint stored in ``user_sessions``. Keyed, so it is not reversible."""
    return hmac_sha256(token, get_settings().jwt_secret_key)


def token_remaining_seconds(claims: dict[str, Any]) -> int:
    """Seconds until ``exp``, floored at zero. Used to size blacklist TTLs."""
    exp = claims.get("exp")
    if not isinstance(exp, int):
        return 0
    return max(0, exp - int(_utcnow().timestamp()))
