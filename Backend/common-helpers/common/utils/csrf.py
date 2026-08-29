"""CSRF protection: OWASP "Signed Double Submit Cookie".

The token is ``base64url(payload) . base64url(HMAC-SHA256(payload))`` where the
payload binds the token to a specific session id and carries its own expiry.

Why HMAC rather than encryption: the token is not a secret -- the browser must
be able to read it out of a JavaScript-readable cookie and echo it back in the
``X-CSRF-Token`` header. What matters is that an attacker cannot *forge* one for
a victim's session, which a keyed signature guarantees. Signing is also faster
and produces a shorter token than AES-GCM.

Binding to the session id is what defeats the classic double-submit weakness: a
subdomain attacker who can set cookies still cannot mint a token carrying the
victim's session id.
"""

from __future__ import annotations

import base64
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from common.config.settings import get_settings
from common.utils.crypto import hmac_sha256

_SEPARATOR = "."


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def generate_csrf_token(unique_session_id: str) -> str:
    """Mint a CSRF token bound to ``unique_session_id``."""
    settings = get_settings()

    payload = {
        "uid": unique_session_id,
        "nonce": secrets.token_urlsafe(16),
        "exp": _now() + settings.csrf_token_expire_minutes * 60,
    }

    encoded = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = hmac_sha256(encoded, settings.csrf_secret_key)

    return f"{encoded}{_SEPARATOR}{signature}"


def validate_csrf_token(token: str, unique_session_id: str) -> bool:
    """Verify signature, expiry and session binding. Never raises."""
    if not token or not unique_session_id:
        return False

    settings = get_settings()

    try:
        encoded, signature = token.rsplit(_SEPARATOR, 1)
    except ValueError:
        return False

    # Verify the signature before parsing the payload, so malformed input never
    # reaches the JSON decoder.
    expected = hmac_sha256(encoded, settings.csrf_secret_key)
    if not hmac.compare_digest(signature, expected):
        return False

    try:
        payload = json.loads(_b64d(encoded).decode())
    except Exception:  # noqa: BLE001
        return False

    if not isinstance(payload, dict):
        return False

    bound_uid = payload.get("uid")
    if not isinstance(bound_uid, str):
        return False
    if not hmac.compare_digest(bound_uid.encode(), unique_session_id.encode()):
        return False

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < _now():
        return False

    return True


def csrf_token_ttl_seconds() -> int:
    """Cookie lifetime that matches the token's own expiry."""
    return get_settings().csrf_token_expire_minutes * 60


def csrf_expires_at() -> datetime:
    settings = get_settings()
    return datetime.now(timezone.utc) + timedelta(
        minutes=settings.csrf_token_expire_minutes
    )
