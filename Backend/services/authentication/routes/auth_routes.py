"""Authentication endpoints.

Flow
----
``POST /auth/register``     create account, send SMS OTP, return TOTP QR URI
``POST /auth/login``        password factor; issues either a full session or a
                            short-lived MFA challenge
``POST /auth/verify-totp``  second factor; consumes the MFA challenge
``POST /auth/refresh``      rotates the refresh token, with reuse detection
``POST /auth/logout``       revokes this session (or every session)
``GET  /auth/me``           current profile
``GET  /auth/sessions``     active sessions
``DELETE /auth/sessions/{id}`` revoke one session

Threat notes are inline where a decision is not obvious.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status
from jose import JWTError

from common.config.redis_client import get_redis_client
from common.config.settings import get_settings
from common.middleware.auth_middleware import client_ip
from common.security.cookies import (
    SessionEndedError,
    clear_auth_cookies,
    set_csrf_cookie,
    set_refresh_cookie,
)
from common.security.password import hash_password, needs_rehash, verify_password
from common.security.token_store import (
    clear_failed_logins,
    lockout_seconds_remaining,
    register_failed_login,
    revoke_session,
    revoke_token,
)
from common.utils.crypto import CryptoError, aes_decrypt, aes_encrypt
from common.utils.csrf import generate_csrf_token
from common.utils.jwt_handler import (
    create_access_token,
    create_mfa_challenge_token,
    create_refresh_token,
    decode_token,
    hash_refresh_token,
    token_remaining_seconds,
)
from common.utils.otp import (
    create_sms_otp,
    generate_totp_secret,
    get_totp_provisioning_uri,
    verify_totp,
)
from repositories import session_repository as sessions
from repositories import user_repository as users
from schema.auth_schemas import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    LogoutResponse,
    MeResponse,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
    SessionInfo,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])

GENERIC_LOGIN_ERROR = "Invalid email or password"

_DUMMY_HASH = hash_password("pingora-timing-equalisation-placeholder")


async def _send_sms(phone_number: str, otp: str) -> None:
    if get_settings().is_production:
        logger.info("Dispatching OTP SMS", extra={"phone_suffix": phone_number[-4:]})
        raise NotImplementedError("Configure an SMS provider before going live")
    logger.warning("[DEV ONLY] OTP for %s is %s", phone_number, otp)


def _issue_session(
    response: Response,
    request: Request,
    user: dict,
) -> tuple[str, str, str]:
    settings = get_settings()
    session_id = str(uuid.uuid4())

    access_token, _ = create_access_token(
        user_id=user["id"],
        email=user["email"],
        phone=user.get("phone_number"),
        display_name=user.get("display_name"),
        unique_session_id=session_id,
    )
    refresh_token, _, refresh_hash = create_refresh_token(
        user_id=user["id"], unique_session_id=session_id
    )
    csrf_token = generate_csrf_token(session_id)

    sessions.create_session(
        user_id=user["id"],
        session_id=session_id,
        refresh_token_hash=refresh_hash,
        expires_at=datetime.now(timezone.utc)
        + timedelta(days=settings.refresh_token_expire_days),
        user_agent=request.headers.get("User-Agent"),
        ip_address=client_ip(request),
    )

    set_refresh_cookie(response, refresh_token)
    set_csrf_cookie(response, csrf_token)

    return access_token, csrf_token, session_id


def _access_token_ttl() -> int:
    return get_settings().access_token_expire_minutes * 60


# --- Register -------------------------------------------------------------
@router.post(
    "/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED
)
async def register(payload: RegisterRequest):
    existing = users.find_by_email_or_phone(payload.email, payload.phone_number)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or phone number already registered",
        )

    password_hash = hash_password(payload.password)

    totp_secret = generate_totp_secret()
    encrypted_totp_secret = aes_encrypt(totp_secret)
    provisioning_uri = get_totp_provisioning_uri(totp_secret, payload.email)

    try:
        user = users.create_user(
            email=payload.email,
            phone_number=payload.phone_number,
            password_hash=password_hash,
            display_name=payload.display_name,
            encrypted_totp_secret=encrypted_totp_secret,
        )
    except Exception:  # noqa: BLE001
        logger.exception("User creation failed")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not create the account",
        )

    otp = await create_sms_otp(get_redis_client(), identifier=payload.phone_number)
    await _send_sms(payload.phone_number, otp)

    return RegisterResponse(
        user_id=user["id"],
        email=user["email"],
        phone_number=user["phone_number"],
        totp_provisioning_uri=provisioning_uri,
        email_verified=False,
        phone_verified=False,
    )


# --- Login ----------------------------------------------------------------
@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, response: Response):
    print("Login attempt for", payload)
    settings = get_settings()
    redis = get_redis_client()
    identifier = payload.email.lower()

    locked_for = await lockout_seconds_remaining(redis, identifier)
    if locked_for:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked after repeated failed attempts",
            headers={"Retry-After": str(locked_for)},
        )

    user = users.find_by_email(payload.email)

    stored_hash = user["password_hash"] if user else _DUMMY_HASH
    password_ok = verify_password(payload.password, stored_hash)

    if not user or not password_ok:
        await register_failed_login(
            redis,
            identifier,
            settings.login_max_failed_attempts,
            settings.login_lockout_minutes,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_LOGIN_ERROR
        )

    if user.get("is_active") is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled"
        )

    await clear_failed_logins(redis, identifier)

    # Transparently upgrade the hash if Argon2's parameters have since changed.
    if needs_rehash(user["password_hash"]):
        try:
            users.update_password_hash(user["id"], hash_password(payload.password))
        except Exception:  # noqa: BLE001
            logger.warning("Password rehash failed", exc_info=True)

    if user.get("totp_secret"):
        mfa_token, _ = create_mfa_challenge_token(user["id"])
        return LoginResponse(
            requires_totp=True,
            mfa_token=mfa_token,
            message="Password accepted. Enter your authenticator code to continue.",
        )

    access_token, csrf_token, _ = _issue_session(response, request, user)

    return LoginResponse(
        requires_totp=False,
        user_id=user["id"],
        email=user["email"],
        display_name=user.get("display_name"),
        access_token=access_token,
        csrf_token=csrf_token,
        expires_in=_access_token_ttl(),
        message="Login successful.",
    )


# --- TOTP -----------------------------------------------------------------
@router.post("/verify-totp", response_model=TOTPVerifyResponse)
async def verify_totp_endpoint(
    payload: TOTPVerifyRequest, request: Request, response: Response
):
    try:
        claims = decode_token(payload.mfa_token, expected_type="mfa")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your verification window expired. Please sign in again.",
        )

    redis = get_redis_client()
    challenge_jti = claims.get("jti")

    if challenge_jti and await redis.exists(f"blacklist:jti:{challenge_jti}"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This verification token has already been used",
        )

    user = users.find_by_id(claims["sub"])
    if not user or not user.get("totp_secret"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid request"
        )

    try:
        totp_secret = aes_decrypt(user["totp_secret"])
    except CryptoError:
        logger.exception("Could not decrypt the stored TOTP secret")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Two-factor verification is unavailable",
        )

    if not verify_totp(totp_secret, payload.totp_code):
        await register_failed_login(
            redis,
            user["email"].lower(),
            get_settings().login_max_failed_attempts,
            get_settings().login_lockout_minutes,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authenticator code",
        )

    if challenge_jti:
        await revoke_token(redis, challenge_jti, token_remaining_seconds(claims))

    await clear_failed_logins(redis, user["email"].lower())

    access_token, csrf_token, _ = _issue_session(response, request, user)

    return TOTPVerifyResponse(
        user_id=user["id"],
        email=user["email"],
        display_name=user.get("display_name"),
        access_token=access_token,
        csrf_token=csrf_token,
        expires_in=_access_token_ttl(),
    )


# --- Refresh --------------------------------------------------------------
@router.post("/refresh", response_model=RefreshResponse)
async def refresh(request: Request, response: Response):
    settings = get_settings()
    redis = get_redis_client()

    refresh_token = request.cookies.get(settings.refresh_cookie_name)
    if not refresh_token:
        raise SessionEndedError("Refresh token missing")

    try:
        claims = decode_token(refresh_token, expected_type="refresh")
    except JWTError:
        raise SessionEndedError("Invalid or expired refresh token")

    user_id, session_id = claims.get("sub"), claims.get("uid")
    if not user_id or not session_id:
        raise SessionEndedError("Invalid token claims")

    presented_hash = hash_refresh_token(refresh_token)
    stored = sessions.find_session_by_hash(presented_hash)

    if stored is None or stored.get("revoked"):
        # Either a forged fingerprint or a replayed, already-rotated token.
        logger.warning(
            "Refresh token reuse detected", extra={"session_id": session_id}
        )
        sessions.revoke_session_by_id(session_id)
        await revoke_session(
            redis, session_id, settings.refresh_token_expire_days * 24 * 3600
        )
        raise SessionEndedError("Session invalidated. Please sign in again.")

    user = users.find_by_id(user_id)
    if not user or user.get("is_active") is False:
        sessions.revoke_session_by_id(session_id)
        raise SessionEndedError("Account unavailable")

    new_refresh_token, _, new_hash = create_refresh_token(
        user_id=user_id, unique_session_id=session_id
    )
    new_expiry = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )

    # Compare-and-swap on the old fingerprint: if two requests race with the
    # same token, only one can win and the loser trips reuse detection.
    rotated = sessions.rotate_session(
        session_id=session_id,
        old_refresh_token_hash=presented_hash,
        new_refresh_token_hash=new_hash,
        new_expires_at=new_expiry,
    )
    if rotated is None:
        raise SessionEndedError("Session invalidated. Please sign in again.")

    access_token, _ = create_access_token(
        user_id=user["id"],
        email=user["email"],
        phone=user.get("phone_number"),
        display_name=user.get("display_name"),
        unique_session_id=session_id,
    )
    csrf_token = generate_csrf_token(session_id)

    set_refresh_cookie(response, new_refresh_token)
    set_csrf_cookie(response, csrf_token)

    return RefreshResponse(
        access_token=access_token,
        csrf_token=csrf_token,
        expires_in=_access_token_ttl(),
    )


# --- Logout ---------------------------------------------------------------
@router.post("/logout", response_model=LogoutResponse)
async def logout(payload: LogoutRequest, request: Request, response: Response):
    settings = get_settings()
    redis = get_redis_client()

    user_id = getattr(request.state, "user_id", None)
    session_id = getattr(request.state, "unique_session_id", None)
    jti = getattr(request.state, "jti", None)
    claims = getattr(request.state, "token_claims", {}) or {}

    revoked = 0

    if payload.all_devices and user_id:
        revoked = sessions.revoke_all_sessions_for_user(user_id)
        await revoke_session(
            redis, session_id, settings.refresh_token_expire_days * 24 * 3600
        )
    elif session_id:
        sessions.revoke_session_by_id(session_id)
        await revoke_session(
            redis, session_id, settings.refresh_token_expire_days * 24 * 3600
        )
        revoked = 1

    if jti:
        await revoke_token(redis, jti, token_remaining_seconds(claims))

    clear_auth_cookies(response)

    return LogoutResponse(sessions_revoked=revoked)


# --- Profile and sessions -------------------------------------------------
@router.get("/me", response_model=MeResponse)
async def me(request: Request):
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    profile = users.get_profile(user_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return MeResponse(
        user_id=profile["id"],
        email=profile["email"],
        phone_number=profile.get("phone_number"),
        display_name=profile.get("display_name"),
        email_verified=bool(profile.get("email_verified")),
        phone_verified=bool(profile.get("phone_verified")),
        roles=getattr(request.state, "roles", ["user"]) or ["user"],
    )


@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(request: Request):
    user_id = getattr(request.state, "user_id", None)
    current_session = getattr(request.state, "unique_session_id", None)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    return [
        SessionInfo(**row, current=row.get("session_id") == current_session)
        for row in sessions.list_active_sessions(user_id)
    ]


@router.delete("/sessions/{session_id}", response_model=LogoutResponse)
async def revoke_one_session(session_id: str, request: Request):
    """Revoke a single session -- "sign out that other device"."""
    settings = get_settings()
    user_id = getattr(request.state, "user_id", None)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    # Only sessions belonging to the caller may be revoked.
    owned = {s["session_id"] for s in sessions.list_active_sessions(user_id)}
    if session_id not in owned:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
        )

    sessions.revoke_session_by_id(session_id)
    await revoke_session(
        get_redis_client(),
        session_id,
        settings.refresh_token_expire_days * 24 * 3600,
    )

    return LogoutResponse(message="Session revoked.", sessions_revoked=1)
