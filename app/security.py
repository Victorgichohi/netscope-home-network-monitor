from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.models import User


def hash_password(password: str, iterations: int = 600_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations_text))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _encode(payload: dict, secret: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def _decode(token: str, secret: str) -> dict | None:
    try:
        body, signature = token.rsplit(".", 1)
        expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if int(payload["exp"]) < int(time.time()):
            return None
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def create_session_token(user: User, settings: Settings) -> tuple[str, str]:
    csrf = secrets.token_urlsafe(24)
    payload = {
        "sub": user.id,
        "username": user.username,
        "csrf": csrf,
        "exp": int(time.time()) + settings.session_lifetime_seconds,
    }
    return _encode(payload, settings.secret_key), csrf


def get_session_payload(request: Request, settings: Settings = Depends(get_settings)) -> dict:
    token = request.cookies.get(settings.session_cookie_name)
    payload = _decode(token, settings.secret_key) if token else None
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return payload


def get_current_user(
    payload: dict = Depends(get_session_payload), db: Session = Depends(get_db)
) -> User:
    user = db.scalar(select(User).where(User.id == payload["sub"], User.is_active.is_(True)))
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


async def require_csrf(
    request: Request, payload: dict = Depends(get_session_payload)
) -> None:
    supplied = request.headers.get("X-CSRF-Token")
    if not supplied or not hmac.compare_digest(supplied, str(payload.get("csrf", ""))):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


@dataclass
class RateLimitRule:
    limit: int
    window_seconds: int


class RateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str, rule: RateLimitRule) -> None:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and events[0] <= now - rule.window_seconds:
                events.popleft()
            if len(events) >= rule.limit:
                raise HTTPException(status_code=429, detail="Too many requests; try again later")
            events.append(now)


rate_limiter = RateLimiter()
