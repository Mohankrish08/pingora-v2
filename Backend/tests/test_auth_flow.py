"""Security guarantees of the authentication service.

Each test names the attack it prevents. If one of these starts failing, a real
vulnerability has been reintroduced -- not just a refactor gone stale.
"""

from __future__ import annotations

import pyotp
import pytest

from common.utils.crypto import aes_decrypt


# --- Registration ---------------------------------------------------------
class TestRegistration:
    def test_creates_account_with_totp_uri(self, client, credentials):
        response = client.post("/auth/register", json=credentials)

        assert response.status_code == 201
        assert response.json()["totp_provisioning_uri"].startswith("otpauth://")

    def test_never_returns_password_hash(self, client, credentials):
        response = client.post("/auth/register", json=credentials)

        assert "password_hash" not in response.text
        assert credentials["password"] not in response.text

    def test_totp_secret_is_encrypted_at_rest(self, client, credentials, db):
        response = client.post("/auth/register", json=credentials)

        stored = db.users[0]["totp_secret"]
        uri = response.json()["totp_provisioning_uri"]

        # A database dump alone must not yield a working second factor.
        assert stored != aes_decrypt(stored)
        assert aes_decrypt(stored) in uri

    def test_rejects_duplicate_email(self, client, credentials):
        client.post("/auth/register", json=credentials)
        response = client.post("/auth/register", json=credentials)

        assert response.status_code == 409

    @pytest.mark.parametrize(
        "password",
        [
            "short1!A",              # under 12 characters
            "alllowercase123!",      # no uppercase
            "ALLUPPERCASE123!",      # no lowercase
            "NoDigitsHereAtAll!",    # no digit
            "NoSymbolsHere1234",     # no symbol
            "password",              # common
        ],
    )
    def test_rejects_weak_passwords(self, client, credentials, password):
        response = client.post(
            "/auth/register", json={**credentials, "password": password}
        )

        assert response.status_code == 422

    def test_validation_errors_do_not_echo_the_password(self, client, credentials):
        secret = "aB1!aB1!aB1!unique-marker"
        response = client.post(
            "/auth/register",
            json={**credentials, "phone_number": "not-a-phone", "password": secret},
        )

        assert response.status_code == 422
        # Pydantic's default handler would include the submitted input here.
        assert secret not in response.text


# --- Login ----------------------------------------------------------------
class TestLogin:
    def test_issues_tokens(self, signed_in):
        assert signed_in["access_token"]
        assert signed_in["csrf_token"]
        assert signed_in["requires_totp"] is False

    def test_refresh_token_only_in_httponly_cookie(self, client, registered):
        response = client.post(
            "/auth/login",
            json={"email": registered["email"], "password": registered["password"]},
        )

        # Not in the body: JavaScript must never be able to read it.
        assert "refresh_token" not in response.json()

        cookies = response.headers.get_list("set-cookie")
        refresh = next(c for c in cookies if c.startswith("refresh_token="))
        assert "HttpOnly" in refresh

    def test_csrf_cookie_is_readable_by_javascript(self, client, registered):
        response = client.post(
            "/auth/login",
            json={"email": registered["email"], "password": registered["password"]},
        )

        cookies = response.headers.get_list("set-cookie")
        csrf = next(c for c in cookies if c.startswith("XSRF-TOKEN="))
        # Deliberately readable: the SPA copies it into the request header.
        assert "HttpOnly" not in csrf

    def test_wrong_password_is_rejected(self, client, registered):
        response = client.post(
            "/auth/login",
            json={"email": registered["email"], "password": "Wr0ng!Passphrase42"},
        )

        assert response.status_code == 401

    def test_unknown_account_is_indistinguishable_from_wrong_password(
        self, client, registered
    ):
        """Prevents user enumeration."""
        wrong_password = client.post(
            "/auth/login",
            json={"email": registered["email"], "password": "Wr0ng!Passphrase42"},
        )
        unknown_user = client.post(
            "/auth/login",
            json={"email": "nobody@example.com", "password": "Wr0ng!Passphrase42"},
        )

        assert wrong_password.status_code == unknown_user.status_code == 401
        assert wrong_password.json()["detail"] == unknown_user.json()["detail"]


# --- Two-factor -----------------------------------------------------------
class TestTwoFactor:
    @pytest.fixture
    def mfa(self, client, credentials, db):
        client.post("/auth/register", json=credentials)
        response = client.post(
            "/auth/login",
            json={
                "email": credentials["email"],
                "password": credentials["password"],
            },
        )
        body = response.json()
        return body, aes_decrypt(db.users[0]["totp_secret"])

    def test_password_alone_grants_no_access_token(self, mfa):
        body, _ = mfa

        assert body["requires_totp"] is True
        assert body["access_token"] is None
        assert body["mfa_token"]

    def test_challenge_does_not_leak_the_user_id(self, mfa):
        """A bare user id would let anyone brute-force codes without a password."""
        body, _ = mfa

        assert body["user_id"] is None

    def test_correct_code_completes_sign_in(self, client, mfa):
        body, secret = mfa

        response = client.post(
            "/auth/verify-totp",
            json={"mfa_token": body["mfa_token"], "totp_code": pyotp.TOTP(secret).now()},
        )

        assert response.status_code == 200
        assert response.json()["access_token"]

    def test_wrong_code_is_rejected(self, client, mfa):
        body, _ = mfa

        response = client.post(
            "/auth/verify-totp",
            json={"mfa_token": body["mfa_token"], "totp_code": "000000"},
        )

        assert response.status_code == 401

    def test_forged_challenge_token_is_rejected(self, client, mfa):
        _, secret = mfa

        response = client.post(
            "/auth/verify-totp",
            json={"mfa_token": "forged.token.value", "totp_code": pyotp.TOTP(secret).now()},
        )

        assert response.status_code == 401

    def test_challenge_token_is_single_use(self, client, mfa):
        """Stops a captured challenge from being replayed to retry codes."""
        body, secret = mfa

        first = client.post(
            "/auth/verify-totp",
            json={"mfa_token": body["mfa_token"], "totp_code": pyotp.TOTP(secret).now()},
        )
        replay = client.post(
            "/auth/verify-totp",
            json={"mfa_token": body["mfa_token"], "totp_code": pyotp.TOTP(secret).now()},
        )

        assert first.status_code == 200
        assert replay.status_code == 401


# --- Bearer token ---------------------------------------------------------
class TestBearerToken:
    def test_protected_route_requires_a_token(self, client):
        assert client.get("/auth/me").status_code == 401

    def test_valid_token_is_accepted(self, client, auth_headers, registered):
        response = client.get("/auth/me", headers=auth_headers)

        assert response.status_code == 200
        assert response.json()["email"] == registered["email"]

    @pytest.mark.parametrize(
        "header",
        [
            "garbage.token.here",
            "Bearer garbage.token.here",
            "Basic dXNlcjpwYXNz",
            "Bearer ",
        ],
    )
    def test_malformed_tokens_are_rejected(self, client, header):
        response = client.get("/auth/me", headers={"Authorization": header})

        assert response.status_code == 401

    def test_refresh_token_cannot_be_used_as_a_bearer_token(self, client, signed_in):
        """Type confusion: a long-lived token must not buy API access."""
        refresh = client.cookies.get("refresh_token")

        response = client.get("/auth/me", headers={"Authorization": f"Bearer {refresh}"})

        assert response.status_code == 401

    def test_claims_are_not_readable_from_the_token(self, signed_in):
        """The payload is sealed, so an intercepted token leaks no PII."""
        import base64
        import json

        payload = signed_in["access_token"].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        outer = json.loads(base64.urlsafe_b64decode(payload))

        assert "enc" in outer
        assert "sub" not in outer
        assert "email" not in outer


# --- CSRF -----------------------------------------------------------------
class TestCsrf:
    def test_state_changing_request_needs_the_header(self, client, signed_in):
        response = client.post(
            "/auth/logout",
            json={"all_devices": False},
            headers={"Authorization": f"Bearer {signed_in['access_token']}"},
        )

        assert response.status_code == 403

    def test_forged_token_is_rejected(self, client, signed_in):
        response = client.post(
            "/auth/logout",
            json={"all_devices": False},
            headers={
                "Authorization": f"Bearer {signed_in['access_token']}",
                "X-CSRF-Token": "forged-token-value",
            },
        )

        assert response.status_code == 403

    def test_token_from_another_session_is_rejected(
        self, client, signed_in, registered
    ):
        """Session binding is what makes double-submit safe."""
        other = client.post(
            "/auth/login",
            json={"email": registered["email"], "password": registered["password"]},
        ).json()

        response = client.post(
            "/auth/logout",
            json={"all_devices": False},
            headers={
                "Authorization": f"Bearer {signed_in['access_token']}",
                "X-CSRF-Token": other["csrf_token"],
            },
        )

        assert response.status_code == 403

    def test_valid_token_is_accepted(self, client, auth_headers):
        response = client.post(
            "/auth/logout", json={"all_devices": False}, headers=auth_headers
        )

        assert response.status_code == 200

    def test_safe_methods_need_no_token(self, client, signed_in):
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {signed_in['access_token']}"},
        )

        assert response.status_code == 200


# --- Refresh --------------------------------------------------------------
class TestRefresh:
    def test_issues_a_new_access_token(self, client, signed_in):
        response = client.post("/auth/refresh")

        assert response.status_code == 200
        assert response.json()["access_token"] != signed_in["access_token"]

    def test_rotates_both_tokens(self, client, signed_in):
        before = client.cookies.get("refresh_token")

        response = client.post("/auth/refresh")

        assert client.cookies.get("refresh_token") != before
        assert response.json()["csrf_token"] != signed_in["csrf_token"]

    def test_without_a_cookie_is_rejected(self, client):
        client.cookies.clear()

        assert client.post("/auth/refresh").status_code == 401

    def test_reuse_of_a_rotated_token_is_rejected(self, client, signed_in):
        stolen = client.cookies.get("refresh_token")
        client.post("/auth/refresh")

        client.cookies.set("refresh_token", stolen)
        response = client.post("/auth/refresh")

        assert response.status_code == 401

    def test_reuse_revokes_the_whole_session_family(self, client, signed_in, db):
        """A thief replaying an old token must not leave the victim signed in.

        Killing the family logs out both parties; the victim can sign in again,
        the attacker cannot.
        """
        stolen = client.cookies.get("refresh_token")
        client.post("/auth/refresh")
        legitimate = client.cookies.get("refresh_token")

        client.cookies.set("refresh_token", stolen)
        client.post("/auth/refresh")

        client.cookies.set("refresh_token", legitimate)
        response = client.post("/auth/refresh")

        assert response.status_code == 401
        assert any(session.get("revoked") for session in db.sessions)


# --- Logout ---------------------------------------------------------------
class TestLogout:
    def test_revokes_the_access_token_immediately(self, client, auth_headers):
        """A signed JWT stays valid until exp, so logout needs a deny list."""
        client.post("/auth/logout", json={"all_devices": False}, headers=auth_headers)

        response = client.get(
            "/auth/me", headers={"Authorization": auth_headers["Authorization"]}
        )

        assert response.status_code == 401

    def test_blocks_further_refreshes(self, client, auth_headers):
        client.post("/auth/logout", json={"all_devices": False}, headers=auth_headers)

        assert client.post("/auth/refresh").status_code == 401

    def test_clears_the_cookies(self, client, auth_headers):
        response = client.post(
            "/auth/logout", json={"all_devices": False}, headers=auth_headers
        )

        cookies = " ".join(response.headers.get_list("set-cookie"))
        assert "refresh_token=" in cookies
        assert "Max-Age=0" in cookies or "expires=" in cookies.lower()


# --- Hardening ------------------------------------------------------------
class TestSecurityHeaders:
    def test_baseline_headers_are_present(self, client, signed_in):
        response = client.get("/health")

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]

    def test_auth_responses_are_not_cacheable(self, client, registered):
        response = client.post(
            "/auth/login",
            json={"email": registered["email"], "password": registered["password"]},
        )

        assert "no-store" in response.headers["Cache-Control"]

    def test_request_id_is_echoed_for_tracing(self, client):
        response = client.get("/health", headers={"X-Request-ID": "trace-me-123"})

        assert response.headers["X-Request-ID"] == "trace-me-123"


class TestRateLimiting:
    def test_login_attempts_are_throttled(self, client, registered, monkeypatch):
        from common.config.settings import get_settings

        get_settings.cache_clear()
        monkeypatch.setenv("RATE_LIMIT_LOGIN_PER_MINUTE", "3")

        try:
            codes = [
                client.post(
                    "/auth/login",
                    json={"email": registered["email"], "password": "Wr0ng!Passphrase42"},
                ).status_code
                for _ in range(6)
            ]
            assert 429 in codes
        finally:
            get_settings.cache_clear()

    def test_repeated_failures_lock_the_account(self, client, registered):
        for _ in range(6):
            client.post(
                "/auth/login",
                json={"email": registered["email"], "password": "Wr0ng!Passphrase99"},
            )

        response = client.post(
            "/auth/login",
            json={"email": registered["email"], "password": registered["password"]},
        )

        # Locked out even with the correct password.
        assert response.status_code in (401, 429)
