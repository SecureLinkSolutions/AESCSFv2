"""Server-side sessions and failed-login throttling, stored in Valkey.

The browser only holds a random token. Valkey stores a SHA-256 of that token,
so a dump of Valkey doesn't contain usable session cookies, and deleting the
key revokes the session immediately.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass

import redis

SESSION_COOKIE = "slscan_session"
LOGIN_CSRF_COOKIE = "slscan_login_csrf"


@dataclass(frozen=True)
class SessionData:
    user_id: int
    csrf_token: str


def _session_key(token: str) -> str:
    return "session:" + hashlib.sha256(token.encode()).hexdigest()


def create_session(r: redis.Redis, user_id: int, ttl_seconds: int) -> str:
    token = secrets.token_urlsafe(32)
    data = {"user_id": user_id, "csrf_token": secrets.token_urlsafe(32)}
    r.set(_session_key(token), json.dumps(data), ex=ttl_seconds)
    return token


def load_session(r: redis.Redis, token: str | None) -> SessionData | None:
    if not token:
        return None
    raw = r.get(_session_key(token))
    if raw is None:
        return None
    data = json.loads(raw)
    return SessionData(user_id=int(data["user_id"]), csrf_token=data["csrf_token"])


def destroy_session(r: redis.Redis, token: str | None) -> None:
    if token:
        r.delete(_session_key(token))


def _failure_keys(username: str, client_ip: str) -> tuple[str, str]:
    return f"loginfail:user:{username.lower()}", f"loginfail:ip:{client_ip}"


def is_login_locked(r: redis.Redis, username: str, client_ip: str, max_failures: int) -> bool:
    return any(int(r.get(key) or 0) >= max_failures for key in _failure_keys(username, client_ip))


def record_login_failure(
    r: redis.Redis, username: str, client_ip: str, lockout_seconds: int
) -> None:
    pipe = r.pipeline()
    for key in _failure_keys(username, client_ip):
        pipe.incr(key)
        pipe.expire(key, lockout_seconds)
    pipe.execute()


def clear_login_failures(r: redis.Redis, username: str) -> None:
    r.delete(_failure_keys(username, "")[0])
