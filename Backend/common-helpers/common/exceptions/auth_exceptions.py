from fastapi import HTTPException, status

# ------ Authentication Exceptions ------
class AuthException(HTTPException):
    def __init__(self, detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(status_code=status_code, detail=detail)

class InvalidCredentialsException(AuthException):
    def __init__(self):
        super().__init__("Invalid credentials", status.HTTP_401_UNAUTHORIZED)

class TokenExpiredException(AuthException):
    def __init__(self):
        super().__init__("Token has expired", status.HTTP_401_UNAUTHORIZED)

class TokenInvalidException(AuthException):
    def __init__(self):
        super().__init__("Invalid token", status.HTTP_401_UNAUTHORIZED)

class TokenBlacklistedException(AuthException):
    def __init__(self):
        super().__init__("Token has been blacklisted", status.HTTP_401_UNAUTHORIZED)

# ----- CSRF Exceptions -----
class CSRFValiationException(HTTPException):
    def __init__(self):
        super().__init__(status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")

# ----- Rate limiting Exceptions -----
class RateLimitException(HTTPException):
    def __init__(self, retry_after: int=60):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests. Please try after {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

# ----- User Exceptions -----
class UserNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(status.HTTP_404_NOT_FOUND, detail="User not found")

class UserAlreadyExistsException(HTTPException):
    def __init__(self, field: str = "email"):
        super().__init__(status.HTTP_409_CONFLICT, detail=f"User with the {field} already exists")

# ---- OTP Exceptions ----
class OTPInvalidException(HTTPException):
    def __init__(self):
        super().__init__(status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP")

# ----- Session Exceptions -----
class SessionNotFoundException(AuthException):
    def __init__(self):
        super().__init__("Session not found or expired", status.HTTP_401_UNAUTHORIZED)
