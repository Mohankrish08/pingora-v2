import re
from pydantic import BaseModel, EmailStr, Field, field_validator

class RegisterRequest(BaseModel):
    email: EmailStr
    phone_number: str
    password: str
    display_name: str

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, v: str) -> str:
        if not re.match(r"^\+[1-9]\d{7,14}$", v):
            raise ValueError("Invalid phone number")
        return v
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str)-> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contains a uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contains a lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contains a digit")
        return v

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, v: str) -> str:
        v = v.strip()
        if not (2 <= len(v) <= 50):
            raise ValueError("Display name must be between 2 and 50 characters")
        return v
    
class RegisterResponse(BaseModel):
    user_id: str
    email: str
    phone_number: str
    totp_provisioning_uri: str
    email_verified: bool
    phone_verified: bool
    message: str = "Account created. Scan the QR code to set up your authenticator app and verify the OTP sent to your phone."

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    requires_totp: bool
    access_token: str | None = None
    token_type: str = "Bearer"
    message: str = "Login Successful"

class TOTPVerifyRequest(BaseModel):
    user_id: str
    totp_code: str = Field(min_length=6, max_length=6)


class TOTPVerifyResponse(BaseModel):
    access_token: str   
    token_type: str = "bearer"
    message: str = "TOTP verified. Login complete."