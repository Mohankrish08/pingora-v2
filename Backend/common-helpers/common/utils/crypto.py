import base64
import json 
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from common.config.settings import get_settings

AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
RSA_KEY_SIZE = 256

_rsa_private_key = None
_rsa_public_key = None

def _load_key():
    global _rsa_private_key, _rsa_public_key
    if _rsa_private_key is None:
        settings = get_settings()
        with open(settings.rsa_private_key_path, "rb") as f:
            _rsa_private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(settings.rsa_public_key_path, "rb") as f:
            _rsa_public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

# RSA-OAEP + AES-256-GCM Hybrid Encrypt
def encryp_payload(payload: dict) -> str:
    """
    Encrypts a dict payload using RSA+AES hybrid
    Returns a base64 string safe to embed in JWT claims
    """
    _load_key()
     
    raw = json.dumps(payload, separators=(",", ":")).encode()

    # AES-GCM encrypt
    aes_key = os.urandom(AES_KEY_SIZE)
    nonce = os.urandom(AES_NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(nonce, raw, None)

    # RES-OAEP encrypt the AES key
    enc_aes_key = _rsa_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    envelope = enc_aes_key + nonce + encrypted
    return base64.urlsafe_b64encode(envelope).decode()

def decrypt_payload(token: str) -> dict:
    """ 
    Decrypts a base64 envelope back to dict
    Raises ValueError or any integrity failure
    """

    _load_key()

    try:
        envelope = base64.urlsafe_b64decode(token.encode())
        enc_aes_key = envelope[:RSA_KEY_SIZE]
        nonce = envelope[RSA_KEY_SIZE:RSA_KEY_SIZE + AES_NONCE_SIZE]
        ciphertext = envelope[RSA_KEY_SIZE + AES_NONCE_SIZE:]

        # Decrypt AES key
        aes_key = _rsa_private_key.decrypt(
            enc_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt payload (GCM also validates auth tag)
        aesgcm = AESGCM(aes_key)
        raw = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(raw.decode())

    except Exception as e:
        raise ValueError(f"Payload decryption failed: {e}") from e
    

# Lightweight AES-GCM for non-RSA use (CSRF token body)
def aes_encrypt(data: str) -> str:
    """
    Encrypt a string with the shared AES key from settings.
    """
    settings = get_settings()
    aes_key = base64.b64decode(settings.aes_secret_key)
    nonce = os.urandom(AES_NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(nonce, data.encode(), None)
    return base64.urlsafe_b64encode(nonce + encrypted).decode()

def aes_decrypt(token: str) -> str:
    """"
    Decrypt a string encrypted by aes_encrypt
    """
    settings = get_settings()
    aes_key = base64.b64decode(settings.aes_secret_key)
    raw = base64.urlsafe_b64decode(token.encode())
    nonce = raw[:AES_NONCE_SIZE]
    cipher = raw[AES_NONCE_SIZE:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, cipher, None).decode()