"""Local accounts, opaque session tokens, API tokens, and optional GitHub OAuth."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request

from . import config, db
from .schemas import User, utcnow

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_LEN = 32
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_WINDOW = 300.0
_LOGIN_MAX = 12


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_SCRYPT_LEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n),
            r=int(r), p=int(p), dklen=len(bytes.fromhex(digest_hex)),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def check_login_rate(key: str) -> None:
    now = time.monotonic()
    attempts = [t for t in _LOGIN_ATTEMPTS.get(key, []) if now - t < _LOGIN_WINDOW]
    if len(attempts) >= _LOGIN_MAX:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    attempts.append(now)
    _LOGIN_ATTEMPTS[key] = attempts


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: str, conn=None) -> str:
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(days=config.SESSION_TTL_DAYS)
    owns = conn is None
    conn = conn or db.connect()
    try:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?,?,?,?)",
            (_token_hash(token), user_id, expires.isoformat(), utcnow().isoformat()),
        )
        if owns:
            conn.commit()
    finally:
        if owns:
            conn.close()
    return token


def revoke_session(token: str) -> None:
    with db.session() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def _row_to_user(row) -> User:
    return User(
        id=row["id"], email=row["email"], name=row["name"], role=row["role"],
        avatar_url=row["avatar_url"], created_at=datetime.fromisoformat(row["created_at"]),
    )


def create_user(
    email: str, password: str, name: str, role: str = "member",
    avatar_url: str = "", github_id: Optional[str] = None,
) -> User:
    email = normalize_email(email)
    user_id = uuid.uuid4().hex
    with db.session() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise ValueError("An account with this email already exists")
        conn.execute(
            "INSERT INTO users (id, email, name, password_hash, role, avatar_url, github_id, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                user_id, email, name.strip() or email.split("@")[0], hash_password(password),
                role, avatar_url, github_id, utcnow().isoformat(),
            ),
        )
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user(row)


def get_user_by_email(email: str) -> Optional[User]:
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (normalize_email(email),)).fetchone()
    return _row_to_user(row) if row else None


def authenticate(email: str, password: str) -> Optional[User]:
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (normalize_email(email),)).fetchone()
    if row and verify_password(password, row["password_hash"]):
        return _row_to_user(row)
    return None


def ensure_user(
    email: str, name: str, password: str = "", role: str = "member",
    avatar_url: str = "", github_id: Optional[str] = None,
) -> User:
    user = get_user_by_email(email)
    if user:
        return user
    return create_user(email, password or secrets.token_urlsafe(24), name, role, avatar_url, github_id)


def ensure_demo_user() -> User:
    return ensure_user(
        "demo@codeshield.local", "Demo Analyst", "demo1234", role="owner"
    )


def ensure_service_user() -> User:
    return ensure_user(
        "ci@codeshield.local", "CI Service", secrets.token_urlsafe(24), role="service"
    )


def resolve_session(token: str) -> Optional[User]:
    if not token:
        return None
    with db.session() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id"
            " WHERE s.token_hash = ? AND s.expires_at > ?",
            (_token_hash(token), utcnow().isoformat()),
        ).fetchone()
    return _row_to_user(row) if row else None


def bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def user_from_request(request: Request) -> Optional[User]:
    if config.AUTH_MODE == "off":
        return ensure_demo_user()
    token = request.cookies.get(config.COOKIE_NAME, "") or bearer_token(request)
    if not token:
        return None
    if config.API_TOKEN and hmac.compare_digest(token, config.API_TOKEN):
        return ensure_service_user()
    return resolve_session(token)


def require_user(request: Request) -> User:
    user = user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        config.COOKIE_NAME, token, max_age=config.SESSION_TTL_DAYS * 86400,
        httponly=True, samesite="lax", secure=config.COOKIE_SECURE, path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(config.COOKIE_NAME, path="/")


def oauth_enabled() -> bool:
    return bool(config.GITHUB_CLIENT_ID and config.GITHUB_CLIENT_SECRET)


def github_authorize_url(state: str) -> str:
    query = urlencode(
        {
            "client_id": config.GITHUB_CLIENT_ID,
            "redirect_uri": config.GITHUB_REDIRECT_URI,
            "scope": "read:user user:email",
            "state": state,
        }
    )
    return f"https://github.com/login/oauth/authorize?{query}"


def exchange_github_code(code: str) -> dict:
    with httpx.Client(timeout=20) as client:
        token_resp = client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": config.GITHUB_CLIENT_ID,
                "client_secret": config.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": config.GITHUB_REDIRECT_URI,
            },
        )
        token_resp.raise_for_status()
        access = token_resp.json().get("access_token")
        if not access:
            raise HTTPException(status_code=400, detail="GitHub did not return a token")
        headers = {"Authorization": f"Bearer {access}", "Accept": "application/json"}
        profile = client.get("https://api.github.com/user", headers=headers)
        profile.raise_for_status()
        data = profile.json()
        email = data.get("email") or ""
        if not email:
            emails = client.get("https://api.github.com/user/emails", headers=headers)
            if emails.status_code == 200:
                primary = [e for e in emails.json() if e.get("primary") and e.get("verified")]
                email = primary[0]["email"] if primary else ""
    if not email:
        raise HTTPException(status_code=400, detail="No verified email on GitHub account")
    return {
        "email": email,
        "name": data.get("name") or data.get("login") or email.split("@")[0],
        "avatar_url": data.get("avatar_url", ""),
        "github_id": str(data.get("id", "")),
    }


def github_login_or_register(profile: dict) -> User:
    with db.session() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE github_id = ? OR email = ?",
            (profile["github_id"], normalize_email(profile["email"])),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE users SET github_id = ?, avatar_url = ? WHERE id = ?",
                (profile["github_id"], profile["avatar_url"], row["id"]),
            )
            return _row_to_user(row)
    return ensure_user(
        profile["email"], profile["name"], secrets.token_urlsafe(24),
        avatar_url=profile["avatar_url"], github_id=profile["github_id"],
    )
