"""Authentication and OAuth endpoints."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from .. import auth, config
from ..schemas import LoginRequest, RegisterRequest

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
_STATE_COOKIE = "cs_oauth_state"


def _sign(state: str) -> str:
    digest = hmac.new(
        config.OAUTH_STATE_SECRET.encode("utf-8"), state.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{state}.{digest}"


def _valid_state(value: str) -> bool:
    try:
        state, signature = value.rsplit(".", 1)
    except ValueError:
        return False
    expected = hmac.new(
        config.OAUTH_STATE_SECRET.encode("utf-8"), state.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return bool(state) and hmac.compare_digest(signature, expected)


def _payload(user=None) -> dict:
    return {
        "user": user,
        "auth_enabled": config.AUTH_MODE != "off",
        "oauth_enabled": auth.oauth_enabled(),
    }


def _login_response(user, response: Response) -> dict:
    token = auth.create_session(user.id)
    auth.set_session_cookie(response, token)
    return _payload(user)


@router.post("/register")
def register(payload: RegisterRequest, request: Request, response: Response) -> dict:
    if config.AUTH_MODE == "off":
        raise HTTPException(status_code=400, detail="Registration is disabled")
    auth.check_login_rate(f"register:{request.client.host if request.client else 'unknown'}")
    try:
        user = auth.create_user(payload.email, payload.password, payload.name)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _login_response(user, response)


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    auth.check_login_rate(f"login:{request.client.host if request.client else 'unknown'}")
    user = auth.authenticate(payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return _login_response(user, response)


@router.post("/logout")
def logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(config.COOKIE_NAME, "") or auth.bearer_token(request)
    if token and token != config.API_TOKEN:
        auth.revoke_session(token)
    auth.clear_session_cookie(response)
    return {"ok": True}


@router.get("/me")
def me(request: Request) -> dict:
    return _payload(auth.user_from_request(request))


@router.get("/github")
def github_start() -> RedirectResponse:
    if not auth.oauth_enabled():
        raise HTTPException(status_code=404, detail="GitHub OAuth is not configured")
    state = secrets.token_urlsafe(24)
    response = RedirectResponse(auth.github_authorize_url(state))
    response.set_cookie(
        _STATE_COOKIE, _sign(state), max_age=600, httponly=True,
        samesite="lax", secure=config.COOKIE_SECURE, path="/",
    )
    return response


@router.get("/github/callback")
def github_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    if not auth.oauth_enabled():
        raise HTTPException(status_code=404, detail="GitHub OAuth is not configured")
    cookie = request.cookies.get(_STATE_COOKIE, "")
    if not code or not state or not cookie or not _valid_state(cookie) or cookie.rsplit(".", 1)[0] != state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    profile = auth.exchange_github_code(code)
    user = auth.github_login_or_register(profile)
    token = auth.create_session(user.id)
    response = RedirectResponse(f"{config.FRONTEND_URL}/#/dashboard")
    response.set_cookie(
        config.COOKIE_NAME, token, max_age=config.SESSION_TTL_DAYS * 86400,
        httponly=True, samesite="lax", secure=config.COOKIE_SECURE, path="/",
    )
    response.delete_cookie(_STATE_COOKIE, path="/")
    return response
