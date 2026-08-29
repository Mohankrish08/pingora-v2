"""Test fixtures: an in-process auth service with Supabase and Redis faked.

The fakes are deliberately thin. They exist so the security behaviour under
test -- token issuance, CSRF binding, rotation, revocation -- runs against the
real middleware and route code rather than against mocks of it.
"""

from __future__ import annotations

import base64
import os
import pathlib
import secrets
import sys
import tempfile

import pytest

BACKEND_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "common-helpers"))
sys.path.insert(0, str(BACKEND_ROOT / "services" / "authentication"))

_KEY_DIR = tempfile.mkdtemp(prefix="pingora-test-keys-")

# Must be set before anything imports settings: pydantic-settings reads the
# environment once and get_settings() is lru_cached.
os.environ.update(
    {
        "SUPABASE_URL": "https://test.supabase.co",
        "SUPABASE_ANON_KEY": "test-anon-key",
        "SUPABASE_SERVICE_ROLE_KEY": "test-service-key",
        "JWT_SECRET_KEY": secrets.token_hex(32),
        "CSRF_SECRET_KEY": secrets.token_hex(32),
        "AES_SECRET_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        "RSA_PRIVATE_KEY_PATH": os.path.join(_KEY_DIR, "private.pem"),
        "RSA_PUBLIC_KEY_PATH": os.path.join(_KEY_DIR, "public.pem"),
        "APP_ENV": "development",
        "DEBUG": "false",
        "ALLOWED_ORIGINS": "http://localhost:4200",
        # Raised so the limiter does not mask the behaviour a test is asserting.
        # Rate limiting has its own dedicated test that lowers it again.
        "RATE_LIMIT_LOGIN_PER_MINUTE": "100",
        "RATE_LIMIT_OTP_PER_MINUTE": "100",
        "RATE_LIMIT_REGISTER_PER_MINUTE": "100",
    }
)


# --- Fake Supabase --------------------------------------------------------
class _Query:
    """Minimal PostgREST-shaped query builder over a list of dicts."""

    def __init__(self, store: list[dict], table: str):
        self._store = store
        self._rows = list(store)
        self._table = table
        self._op = "select"
        self._payload: dict | None = None

    def select(self, *_args, **_kwargs):
        return self

    def insert(self, data: dict):
        self._op, self._payload = "insert", data
        return self

    def update(self, data: dict):
        self._op, self._payload = "update", data
        return self

    def eq(self, column: str, value):
        self._rows = [r for r in self._rows if r.get(column) == value]
        return self

    def or_(self, expression: str):
        wanted = []
        for clause in expression.split(","):
            column, _, value = clause.partition(".eq.")
            wanted.append((column.strip(), value.strip().strip('"')))
        self._rows = [
            r for r in self._rows if any(r.get(c) == v for c, v in wanted)
        ]
        return self

    def limit(self, _n):
        return self

    def order(self, *_args, **_kwargs):
        return self

    def execute(self):
        if self._op == "insert":
            row = dict(self._payload or {})
            row.setdefault("id", secrets.token_hex(8))
            self._store.append(row)
            return _Result([row])
        if self._op == "update":
            for row in self._rows:
                row.update(self._payload or {})
            return _Result(self._rows)
        return _Result(self._rows)


class _Result:
    def __init__(self, data):
        self.data = data


class FakeSupabase:
    def __init__(self):
        self.users: list[dict] = []
        self.sessions: list[dict] = []

    def table(self, name: str) -> _Query:
        store = self.users if name == "users" else self.sessions
        return _Query(store, name)


@pytest.fixture
def db(monkeypatch) -> FakeSupabase:
    """Fresh in-memory database, wired into every module that reaches for one."""
    fake = FakeSupabase()

    import common.config.supabase_client as supabase_client
    import repositories.session_repository as session_repository
    import repositories.user_repository as user_repository

    for module in (supabase_client, user_repository, session_repository):
        monkeypatch.setattr(module, "get_supabase_client", lambda: fake)

    return fake


@pytest.fixture
def redis(monkeypatch):
    """Fresh fake Redis per test, so rate-limit and lockout state never leaks."""
    import fakeredis.aioredis

    instance = fakeredis.aioredis.FakeRedis(decode_responses=True)

    import common.config.redis_client as redis_client
    import common.middleware.auth_middleware as auth_middleware
    import routes.auth_routes as auth_routes

    for module in (redis_client, auth_middleware, auth_routes):
        monkeypatch.setattr(module, "get_redis_client", lambda: instance)

    return instance


@pytest.fixture
def client(db, redis):
    from fastapi.testclient import TestClient

    from main import create_app, ensure_rsa_keypair

    ensure_rsa_keypair()
    return TestClient(create_app())


@pytest.fixture
def credentials() -> dict[str, str]:
    return {
        "email": "ada@example.com",
        "phone_number": "+14155550100",
        "password": "Str0ng!Passphrase42",
        "display_name": "Ada Lovelace",
    }


@pytest.fixture
def registered(client, credentials, db):
    """A registered account with TOTP disabled, for single-factor tests."""
    response = client.post("/auth/register", json=credentials)
    assert response.status_code == 201, response.text
    db.users[0]["totp_secret"] = None
    return credentials


@pytest.fixture
def signed_in(client, registered):
    """Returns the login body: access token, CSRF token, and cookies set."""
    response = client.post(
        "/auth/login",
        json={"email": registered["email"], "password": registered["password"]},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def auth_headers(signed_in) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {signed_in['access_token']}",
        "X-CSRF-Token": signed_in["csrf_token"],
    }
