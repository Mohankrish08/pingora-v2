from typing import Optional
from common.config.supabase_client import get_supabase_client

def find_by_email_or_phone(email: str, phone_number: str) -> Optional[dict]:
    client = get_supabase_client()

    result = (
        client.table("users")
        .select("id, email, phone_number, password_hash, display_name, totp_secret")
        .or_(f"email.eq.{email}, phone_number.eq.{phone_number}")
        .limit(1)
        .execute()
    )

    rows = result.data or []
    return rows[0] if rows else None

def find_by_id(user_id: str):
    client = get_supabase_client()

    result = (
        client.table("users")
        .select("id, email, phone_number, password_hash, display_name, totp_secret")
        .or_(f"id.eq.{user_id}")
        .limit(1)
        .execute()
    )

    rows = result.data or []
    return rows[0] if rows else None

def create_user(
        email: str,
        phone_number: str,
        password_hash: str,
        display_name: str,
        encrypted_totp_secret: str
) -> dict:
    client = get_supabase_client()

    result = (
        client.table("users")
        .insert(
            {
                "email": email,
                "phone_number": phone_number,
                "password_hash": password_hash,
                "display_name": display_name,
                "totp_secret": encrypted_totp_secret,
                "email_verified": False,
                "phone_verified": False,
                "status": "offline",
                "is_online": False
            }
        )
        .execute()
    )

    if not result.data:
        raise RuntimeError("Failed to create user")
    
    return result.data[0]