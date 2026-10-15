import secrets
from typing import Annotated

import redis
from fastapi import Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.sessions import SESSION_COOKIE, SessionData, load_session
from app.valkey import get_valkey


class NotAuthenticated(Exception):
    """Raised by auth dependencies; the app turns it into a redirect to /login."""


def get_session(request: Request, r: Annotated[redis.Redis, Depends(get_valkey)]) -> SessionData:
    session = load_session(r, request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise NotAuthenticated
    return session


def get_current_user(
    session: Annotated[SessionData, Depends(get_session)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise NotAuthenticated
    return user


def require_csrf(
    session: Annotated[SessionData, Depends(get_session)],
    csrf_token: Annotated[str, Form()] = "",
) -> None:
    if not secrets.compare_digest(csrf_token, session.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentSession = Annotated[SessionData, Depends(get_session)]
