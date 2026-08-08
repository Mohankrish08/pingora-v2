import secrets
import json 
from datetime import datetime, timedelta, timezone
from common.utils.crypto import aes_encrypt, aes_decrypt
from common.config.settings import get_settings

def generate_csrf_token(unique_session_id: str) -> str:
    settings = get_settings()
    payload = {
        "uid": unique_session_id,
        "nonce": secrets.token_hex(16),
        "exp": int(
            (datetime.now(timezone.utc) + timedelta(minutes=settings.csrf_token_expire_minutes)).timestamp()
        ),
    }
    return aes_encrypt(json.dumps(payload))

def validate_csrf_token(token: str, unique_session_id: str) -> bool:
    try:
        payload = json.loads(aes_decrypt(token))
        now = int(datetime.now(timezone.utc).timestamp())
        
        if payload.get("uid") != unique_session_id:
            return False
        if payload.get("exp", 0) < now:
            return False
        return True
    except Exception as e:
        return False