from fastapi import APIRouter, HTTPException, status
import uuid

from common.config.redis_client import get_redis_client
from common.security.password import hash_password, verify_password
from common.utils.otp import generate_totp_secret, get_totp_provisioning_uri, create_sms_otp, verify_totp
from common.utils.crypto import aes_encrypt
from common.utils.jwt_handler import create_access_token


from schema.auth_schemas import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse, TOTPVerifyRequest, TOTPVerifyResponse
from repositories.user_repository import find_by_email_or_phone, create_user, find_by_id

router = APIRouter(tags=["auth"])

async def _send_sms(phone_number: str, otp: str) -> None:
    print("f[DEV ONLY] need to send SMS to {phone_number} with OTP: {otp}")

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest):
   

    # 1. Check if email or phone number is already registered
    existing = find_by_email_or_phone(payload.email, payload.phone_number)

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or phone number already exists"
        )

    # 2. Password Hash
    password_hash = hash_password(payload.password)

    # 3. Generate TOTP secret and encrypt it
    totp_secret = generate_totp_secret()
    encrypted_totp_secret = aes_encrypt(totp_secret)
    provisioning_uri = get_totp_provisioning_uri(totp_secret, payload.email)

    # 4. Create the user in the database
    try:
        user = create_user(
            email=payload.email,
            phone_number=payload.phone_number,
            password_hash=password_hash,
            display_name=payload.display_name,
            encrypted_totp_secret=encrypted_totp_secret
        )
        print("PAYLOAD: ", payload)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Failed to create user: {e}"
        )
    
   # 5. Generate OTP and send it via SMS
    redis = get_redis_client()
    otp = await create_sms_otp(redis, identifier=payload.phone_number)
    await _send_sms(payload.phone_number, otp)

    return RegisterResponse(
        user_id=user["id"],
        email=user["email"],
        phone_number=user["phone_number"],
        totp_provisioning_uri=provisioning_uri,
        email_verified=False,
        phone_verified=False
    )
    
@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest):
    # 1. Look up user
    user = find_by_email_or_phone(email=payload.email, phone_number=None)
    session_id = str(uuid.uuid4())

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # 2. Verify password
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        ) 
    
    # 3. TOT 
    if user.get("totp_secret"):
        return LoginResponse(
            user_id=user["id"],
            email=user["email"],
            display_name=user["display_name"],
            requires_totp=True,
            access_token=None,
            message="Password verified. Enter your authenticator code to continue."
        )
    
    # 4. NO TOT - issue token
    access_token, jti = create_access_token(user_id=user["id"], email=user["email"], phone=user["phone_number"], display_name=user['display_name'], unique_session_id=session_id)
    return LoginResponse(
        user_id=user["id"],
        email=user["email"],
        display_name=user["display_name"],
        requires_totp=False,
        access_token=access_token,
        message="Login successful."
    )

@router.post("/verify-totp", response_model=TOTPVerifyResponse)
async def verify_totp_method(payload: TOTPVerifyRequest):

    # 1. look up user
    user = await find_by_id(payload.user_id)
    if not user or not user.get("totp_secret"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid request"
        )
    
    # 2. Decrypt sorted secret and verify code
    decrypted_secret = aes_encrypt(user["totp_secret"])
    session_id = str(uuid.uuid4())
    if not verify_totp(decrypted_secret, payload.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authenticator code"
        )
    
    # 3. code valid - issue token now
    access_token, jti = create_access_token(user_id=user["id"], email=user["email"], phone=user["phone_number"], display_name=user['display_name'], unique_session_id=session_id)
    return TOTPVerifyResponse(access_token=access_token)