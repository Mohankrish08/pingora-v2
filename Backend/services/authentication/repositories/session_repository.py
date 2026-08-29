"""Persistence for refresh-token sessions.

One row per login. The refresh token itself is never stored -- only a keyed
fingerprint -- so a database leak does not hand out live sessions.

Rotation with reuse detection is the reason this table exists at all: each
refresh swaps the stored fingerprint for a new one. If an old fingerprint ever
comes back, the token was replayed (stolen), and the whole session family is
revoked rather than just that token.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from common.config.supabase_client import get_supabase_client

TABLE = "user_sessions"


def _iso(value: datetime) -> str:
    """Supabase speaks JSON; datetimes must be serialised explicitly."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def create_session(
    user_id: str,
    session_id: str,
    refresh_token_hash: str,
    expires_at: datetime,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> dict[str, Any]:
    client = get_supabase_client()

    result = (
        client.table(TABLE)
        .insert(
            {
                "user_id": user_id,
                "session_id": session_id,
                "refresh_token_hash": refresh_token_hash,
                "expires_at": _iso(expires_at),
                "revoked": False,
                "user_agent": (user_agent or "")[:512] or None,
                "ip_address": ip_address,
            }
        )
        .execute()
    )

    if not result.data:
        raise RuntimeError("Failed to create session")

    return result.data[0]


def find_session_by_hash(refresh_token_hash: str) -> Optional[dict[str, Any]]:
    """Look up a session by fingerprint regardless of its revoked state.

    Revoked rows are returned on purpose: the caller needs to see them to detect
    replay of an already-rotated token.
    """
    client = get_supabase_client()

    result = (
        client.table(TABLE)
        .select("*")
        .eq("refresh_token_hash", refresh_token_hash)
        .limit(1)
        .execute()
    )

    rows = result.data or []
    return rows[0] if rows else None


def find_active_session_by_hash(refresh_token_hash: str) -> Optional[dict[str, Any]]:
    """Only non-revoked, non-expired sessions."""
    session = find_session_by_hash(refresh_token_hash)
    if not session or session.get("revoked"):
        return None

    expires_at = session.get("expires_at")
    if expires_at:
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                return None
        except ValueError:
            return None

    return session


def rotate_session(
    session_id: str,
    old_refresh_token_hash: str,
    new_refresh_token_hash: str,
    new_expires_at: datetime,
) -> Optional[dict[str, Any]]:
    client = get_supabase_client()

    result = (
        client.table(TABLE)
        .update(
            {
                "refresh_token_hash": new_refresh_token_hash,
                "expires_at": _iso(new_expires_at),
                "last_used_at": _iso(datetime.now(timezone.utc)),
            }
        )
        .eq("session_id", session_id)
        .eq("refresh_token_hash", old_refresh_token_hash)
        .eq("revoked", False)
        .execute()
    )

    rows = result.data or []
    return rows[0] if rows else None


def revoke_session_by_hash(refresh_token_hash: str) -> None:
    client = get_supabase_client()
    (
        client.table(TABLE)
        .update({"revoked": True, "revoked_at": _iso(datetime.now(timezone.utc))})
        .eq("refresh_token_hash", refresh_token_hash)
        .execute()
    )


def revoke_session_by_id(session_id: str) -> None:
    client = get_supabase_client()
    (
        client.table(TABLE)
        .update({"revoked": True, "revoked_at": _iso(datetime.now(timezone.utc))})
        .eq("session_id", session_id)
        .execute()
    )


def revoke_all_sessions_for_user(user_id: str) -> int:
    """Log the user out of every device. Returns the number of rows revoked."""
    client = get_supabase_client()

    result = (
        client.table(TABLE)
        .update({"revoked": True, "revoked_at": _iso(datetime.now(timezone.utc))})
        .eq("user_id", user_id)
        .eq("revoked", False)
        .execute()
    )

    return len(result.data or [])


def list_active_sessions(user_id: str) -> list[dict[str, Any]]:
    client = get_supabase_client()

    result = (
        client.table(TABLE)
        .select("session_id, created_at, last_used_at, expires_at, user_agent, ip_address")
        .eq("user_id", user_id)
        .eq("revoked", False)
        .order("created_at", desc=True)
        .execute()
    )

    return result.data or []
