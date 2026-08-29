"""User persistence.

Note on filters: PostgREST's ``or_`` takes a raw filter expression, so any value
interpolated into it must be escaped. An unescaped comma or parenthesis in an
email would otherwise let a caller rewrite the filter -- injection, just against
PostgREST rather than SQL. ``_quote`` handles that; equality lookups use ``eq``
which is parameterised and needs no escaping.
"""

from __future__ import annotations

from typing import Any, Optional

from common.config.supabase_client import get_supabase_client

TABLE = "users"

PUBLIC_COLUMNS = "id, email, phone_number, display_name, email_verified, phone_verified, status, is_online, created_at"
AUTH_COLUMNS = (
    "id, email, phone_number, password_hash, display_name, totp_secret, "
    "email_verified, phone_verified, is_active"
)


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def find_by_email(email: str) -> Optional[dict[str, Any]]:
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select(AUTH_COLUMNS)
        .eq("email", email.strip().lower())
        .limit(1)
        .execute()
    )
    rows = result.data or []
    return rows[0] if rows else None


def find_by_phone(phone_number: str) -> Optional[dict[str, Any]]:
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select(AUTH_COLUMNS)
        .eq("phone_number", phone_number.strip())
        .limit(1)
        .execute()
    )
    rows = result.data or []
    return rows[0] if rows else None


def find_by_email_or_phone(
    email: str | None = None, phone_number: str | None = None
) -> Optional[dict[str, Any]]:
    if not email and not phone_number:
        return None

    client = get_supabase_client()

    conditions = []
    if email:
        conditions.append(f"email.eq.{_quote(email.strip().lower())}")
    if phone_number:
        conditions.append(f"phone_number.eq.{_quote(phone_number.strip())}")

    result = (
        client.table(TABLE)
        .select(AUTH_COLUMNS)
        .or_(",".join(conditions))
        .limit(1)
        .execute()
    )

    rows = result.data or []
    return rows[0] if rows else None


def find_by_id(user_id: str) -> Optional[dict[str, Any]]:
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select(AUTH_COLUMNS)
        .eq("id", user_id)
        .limit(1)
        .execute()
    )
    rows = result.data or []
    return rows[0] if rows else None


def get_profile(user_id: str) -> Optional[dict[str, Any]]:
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select(PUBLIC_COLUMNS)
        .eq("id", user_id)
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
    encrypted_totp_secret: str,
) -> dict[str, Any]:
    client = get_supabase_client()

    result = (
        client.table(TABLE)
        .insert(
            {
                "email": email.strip().lower(),
                "phone_number": phone_number.strip(),
                "password_hash": password_hash,
                "display_name": display_name.strip(),
                "totp_secret": encrypted_totp_secret,
                "email_verified": False,
                "phone_verified": False,
                "is_active": True,
                "status": "offline",
                "is_online": False,
            }
        )
        .execute()
    )

    if not result.data:
        raise RuntimeError("Failed to create user")

    return result.data[0]


def update_password_hash(user_id: str, password_hash: str) -> None:
    client = get_supabase_client()
    (
        client.table(TABLE)
        .update({"password_hash": password_hash})
        .eq("id", user_id)
        .execute()
    )


def mark_phone_verified(user_id: str) -> None:
    client = get_supabase_client()
    client.table(TABLE).update({"phone_verified": True}).eq("id", user_id).execute()


def mark_email_verified(user_id: str) -> None:
    client = get_supabase_client()
    client.table(TABLE).update({"email_verified": True}).eq("id", user_id).execute()
