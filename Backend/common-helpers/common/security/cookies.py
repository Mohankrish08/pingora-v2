"""Centralised cookie policy.

Three cookies, deliberately different:

``refresh_token`` -- HttpOnly. JavaScript must never touch it; that is what
                     makes an XSS bug unable to steal a long-lived credential.
                     Scoped to ``/auth`` so it is not attached to ordinary API
                     calls.
``XSRF-TOKEN``    -- readable by JavaScript on purpose. The SPA copies it into
                     the ``X-CSRF-Token`` header, which is the half of the
                     double-submit pattern a cross-origin attacker cannot forge.
``session_hint``  -- readable, and carries no credential at all: the literal
                     "1". Because the refresh cookie is HttpOnly, the SPA has
                     no way to tell an anonymous visitor from a returning one,
                     and would otherwise fire a doomed refresh on every single
                     page load. This flag answers that question without
                     exposing anything. It is never proof of a session -- the
                     server still decides every refresh from the HttpOnly
                     cookie -- so forging it buys nothing but the 401 the
                     forger would have received anyway.

Every attribute is derived from settings so a single environment flip hardens
the whole surface for production.
"""

from __future__ import annotations

from fastapi import HTTPException, Response, status

from common.config.settings import get_settings
from common.utils.csrf import csrf_token_ttl_seconds


def set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    max_age = settings.refresh_token_expire_days * 24 * 60 * 60

    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        path=settings.refresh_cookie_path,
    )

    # Paired here rather than at the call sites so the hint cannot drift out of
    # sync with the credential it describes. Sharing max_age is the whole point:
    # a hint that expired first would tell the SPA "no session" while a usable
    # refresh cookie was still in the jar, silently signing the user out. That
    # rules out reusing XSRF-TOKEN for this, whose TTL is deliberately shorter.
    response.set_cookie(
        key=settings.session_hint_cookie_name,
        value="1",
        max_age=max_age,
        httponly=False,  # intentional: this cookie exists to be read
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        # Site-wide, unlike the refresh cookie: at /auth the SPA could not see
        # it from the pages that need to ask the question.
        path="/",
    )


def clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        domain=settings.cookie_domain,
        path=settings.refresh_cookie_path,
    )
    response.delete_cookie(
        key=settings.session_hint_cookie_name,
        domain=settings.cookie_domain,
        path="/",
    )


def set_csrf_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=token,
        max_age=csrf_token_ttl_seconds(),
        httponly=False,  # intentional: the SPA must read this one
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        path="/",
    )


def clear_csrf_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.csrf_cookie_name,
        domain=settings.cookie_domain,
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    clear_refresh_cookie(response)
    clear_csrf_cookie(response)


class SessionEndedError(HTTPException):
    """A 401 that must also clear the auth cookies on its way out.

    Cookies written to the injected ``Response`` are silently discarded when a
    route raises: FastAPI builds a fresh response from the exception and never
    looks at the one the handler was given. So the obvious spelling --
    ``clear_auth_cookies(response)`` followed by ``raise HTTPException(...)`` --
    reads correctly and does nothing, leaving a dead session's cookies in the
    jar to be replayed on every subsequent request.

    Raising this instead routes through the handler registered in ``main.py``,
    which applies the cookie clearing to the response that is actually sent.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)
