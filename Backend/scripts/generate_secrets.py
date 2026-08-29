"""Generate every secret the stack needs.

    python scripts/generate_secrets.py            # print to stdout
    python scripts/generate_secrets.py --write    # also write Backend/.env

Uses the `cryptography` library rather than shelling out to `openssl`, so it
works identically on Windows, macOS and inside the slim container image.
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BACKEND_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = BACKEND_ROOT / "keys"
ENV_PATH = BACKEND_ROOT / ".env"
EXAMPLE_PATH = BACKEND_ROOT / ".env.example"


def generate_rsa_keypair(force: bool = False) -> tuple[Path, Path]:
    """Write a 2048-bit RSA key pair, refusing to clobber an existing one.

    Overwriting silently would invalidate every token and every encrypted TOTP
    secret already in the database, so it takes an explicit --force.
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_path = KEYS_DIR / "private.pem"
    public_path = KEYS_DIR / "public.pem"

    if private_path.exists() and not force:
        print(f"  keys already exist at {KEYS_DIR} (use --force to replace)")
        return private_path, public_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass  # Windows has no POSIX modes.

    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"  RSA-2048 key pair written to {KEYS_DIR}")
    return private_path, public_path


def generate_secrets() -> dict[str, str]:
    return {
        # 32 raw bytes, base64 -> AES-256.
        "AES_SECRET_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        # 64 hex chars = 256 bits of entropy each. Distinct keys, so a leak of
        # one does not compromise the other.
        "JWT_SECRET_KEY": secrets.token_hex(32),
        "CSRF_SECRET_KEY": secrets.token_hex(32),
    }


def write_env(values: dict[str, str]) -> None:
    """Seed .env from .env.example, filling in the generated secrets."""
    if ENV_PATH.exists():
        print(f"\n  {ENV_PATH} already exists -- not overwriting.")
        print("  Copy the values above into it by hand.")
        return

    if not EXAMPLE_PATH.exists():
        print(f"\n  {EXAMPLE_PATH} not found; cannot seed .env.")
        return

    lines = []
    for line in EXAMPLE_PATH.read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in values:
            lines.append(f"{key}={values[key]}")
        else:
            lines.append(line)

    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass

    print(f"\n  Wrote {ENV_PATH}")
    print("  Fill in SUPABASE_URL and the Supabase keys before starting.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write Backend/.env")
    parser.add_argument("--force", action="store_true", help="replace existing RSA keys")
    args = parser.parse_args()

    print("=" * 62)
    print(" Pingora secret generator")
    print("=" * 62)

    print("\n[1/2] RSA key pair")
    generate_rsa_keypair(force=args.force)

    print("\n[2/2] Symmetric secrets")
    values = generate_secrets()
    for key, value in values.items():
        print(f"  {key}={value}")

    if args.write:
        write_env(values)

    print("\n  These are secrets. Never commit them; .env and keys/ are")
    print("  gitignored and excluded from the Docker build context.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
