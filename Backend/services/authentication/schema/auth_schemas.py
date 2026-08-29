"""Request and response contracts for the authentication service.

Response models never carry a password hash, a TOTP secret or a refresh token.
The refresh token travels only in an HttpOnly cookie, so it is deliberately
absent from every schema here.
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")  # E.164

COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "qwerty123", "letmein1", "welcome1", "admin123", "iloveyou1",
    "passw0rd", "abc12345", "football1", "monkey123", "sunshine1",
}


def _validate_password(value: str) -> str:
    if len(value) < 12:
        raise ValueError("Password must be at least 12 characters")
    if len(value) > 128:
        # Argon2 is happy with long input, but an unbounded field is a cheap DoS.
        raise ValueError("Password must be at most 128 characters")
    if not re.search(r"[A-Z]", value):
        raise ValueError("Password must contain an uppercase letter")
    if not re.search(r"[a-z]", value):
        raise ValueError("Password must contain a lowercase letter")
    if not re.search(r"\d", value):
        raise ValueError("Password must contain a digit")
    if not re.search(r"[^A-Za-z0-9]", value):
        raise ValueError("Password must contain a symbol")
    if value.lower() in COMMON_PASSWORDS:
        raise ValueError("This password is too common")
    return value


# --- Register -------------------------------------------------------------
class RegisterRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    phone_number: str
    password: str = Field(min_length=12, max_length=128)
    display_name: str

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, v: str) -> str:
        if not PHONE_PATTERN.match(v):
            raise ValueError("Phone number must be in E.164 format, e.g. +14155552671")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, v: str) -> str:
        v = v.strip()
        if not 2 <= len(v) <= 50:
            raise ValueError("Display name must be between 2 and 50 characters")
        return v


class RegisterResponse(BaseModel):
    user_id: str
    email: str
    phone_number: str
    totp_provisioning_uri: str
    email_verified: bool
    phone_verified: bool
    message: str = (
        "Account created. Scan the QR code with your authenticator app and "
        "verify the code sent to your phone."
    )


# --- Login ----------------------------------------------------------------
class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):

    requires_totp: bool
    message: str

    user_id: str | None = None
    email: str | None = None
    display_name: str | None = None

    access_token: str | None = None
    csrf_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int | None = None

    mfa_token: str | None = None


# --- TOTP -----------------------------------------------------------------
class TOTPVerifyRequest(BaseModel):
    mfa_token: str = Field(min_length=1)
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPVerifyResponse(BaseModel):
    user_id: str
    email: str
    display_name: str | None = None
    access_token: str
    csrf_token: str
    token_type: str = "Bearer"
    expires_in: int
    message: str = "Authentication complete."


# --- Refresh --------------------------------------------------------------
class RefreshResponse(BaseModel):
    access_token: str
    csrf_token: str
    token_type: str = "Bearer"
    expires_in: int


# --- Logout ---------------------------------------------------------------
class LogoutRequest(BaseModel):
    all_devices: bool = False


class LogoutResponse(BaseModel):
    message: str = "Signed out."
    sessions_revoked: int = 0


# --- Session / profile ----------------------------------------------------
class SessionInfo(BaseModel):
    session_id: str
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    user_agent: str | None = None
    ip_address: str | None = None
    current: bool = False


class MeResponse(BaseModel):
    user_id: str
    email: str
    phone_number: str | None = None
    display_name: str | None = None
    email_verified: bool = False
    phone_verified: bool = False
    roles: list[str] = Field(default_factory=lambda: ["user"])


# --- Errors ---------------------------------------------------------------
class ErrorResponse(BaseModel):
    detail: str
    code: str | None = None
