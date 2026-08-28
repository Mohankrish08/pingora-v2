from datetime import datetime, timezone
from typing import Optional
from common.config.supabase_client import get_supabase_client

def create_session(
        user_id: str,
        session_id: str,
        refresh_token_hash: str,
        expires_at: datetime
) -> dict:
    client = get_supabase_client()

    result = (
        client.table("user_sessions")
        .insert({
            "user_id": user_id,
            "session_id": session_id,
            "refresh_token_hash": refresh_token_hash,
            "expires_at": expires_at,
            "revoked": False
        })
        .execute()
    )

    if not result.data:
        raise RuntimeError("Failed to create session")

    return result.data[0]

def find_active_session_by_hash(refresh_token_hash: str) -> Optional[dict]:
    client = get_supabase_client()

    result = (
        client.table("user_sessions")
        .select("*")
        .eq("refresh_token_hash", refresh_token_hash)
        .eq("revoked", False)
        .limit(1)
        .execute()
    )

def revoke_session_by_hash(refresh_token_hash: str) -> None:
    client = get_supabase_client()
    (
        client.table("user_sessions")
        .update({
            "revoked": True,
            "revoked_at": datetime.now(timezone.utc)
        })
        .eq("refresh_token_hash", refresh_token_hash)
        .execute()
    )