from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

_hasher = PasswordHasher()

def hash_password(plain_password: str) -> str:
    return _hasher.hash(plain_password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        _hasher.verify(password_hash, plain_password)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False
    
def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)