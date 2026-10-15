import logging
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import redis
from fastapi import APIRouter, Depends, FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth import CurrentSession, CurrentUser, NotAuthenticated, require_csrf
from app.config import get_settings
from app.db import get_db
from app.models import User
from app.passwords import verify_password
from app.sessions import (
    LOGIN_CSRF_COOKIE,
    SESSION_COOKIE,
    clear_login_failures,
    create_session,
    destroy_session,
    is_login_locked,
    record_login_failure,
)
from app.valkey import get_valkey

log = logging.getLogger("app.auth")

APP_DIR = Path(__file__).parent

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app() -> FastAPI:
    settings = get_settings()
    base = settings.base_path

    app = FastAPI(title="Secure Link Scanner", docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=APP_DIR / "templates")
    templates.env.globals["base"] = base

    def cookie_args(max_age: int | None = None) -> dict:
        return {
            "path": base,
            "httponly": True,
            "secure": settings.cookie_secure,
            "samesite": "strict",
            "max_age": max_age,
        }

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(NotAuthenticated)
    async def not_authenticated(request: Request, exc: NotAuthenticated):
        if request.headers.get("HX-Request"):
            # htmx: force a full-page navigation to the login page.
            return Response(status_code=401, headers={"HX-Redirect": f"{base}/login"})
        response = RedirectResponse(f"{base}/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE, path=base)
        return response

    router = APIRouter(prefix=base)

    def render_login(request: Request, error: str | None = None, code: int = 200) -> Response:
        token = secrets.token_urlsafe(32)
        response = templates.TemplateResponse(
            request, "login.html", {"csrf_token": token, "error": error}, status_code=code
        )
        response.set_cookie(LOGIN_CSRF_COOKIE, token, **cookie_args(max_age=600))
        return response

    @router.get("/healthz", include_in_schema=False)
    def healthz(
        db: Annotated[Session, Depends(get_db)],
        r: Annotated[redis.Redis, Depends(get_valkey)],
    ):
        checks = {}
        try:
            db.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
        except Exception:
            checks["postgres"] = "fail"
        try:
            r.ping()
            checks["valkey"] = "ok"
        except Exception:
            checks["valkey"] = "fail"
        healthy = all(v == "ok" for v in checks.values())
        return JSONResponse(checks, status_code=200 if healthy else 503)

    @router.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return render_login(request)

    @router.post("/login")
    def login(
        request: Request,
        username: Annotated[str, Form(max_length=64)],
        password: Annotated[str, Form(max_length=1024)],
        csrf_token: Annotated[str, Form()],
        db: Annotated[Session, Depends(get_db)],
        r: Annotated[redis.Redis, Depends(get_valkey)],
    ):
        cookie_token = request.cookies.get(LOGIN_CSRF_COOKIE, "")
        if not cookie_token or not secrets.compare_digest(csrf_token, cookie_token):
            return render_login(request, "Your login form expired. Please try again.", 403)

        ip = client_ip(request)
        username = username.strip()
        if is_login_locked(r, username, ip, settings.login_max_failures):
            log.warning("login locked user=%r ip=%s", username, ip)
            return render_login(request, "Too many failed attempts. Try again later.", 429)

        user = db.scalar(select(User).where(User.username == username))
        ok = verify_password(user.password_hash if user else None, password)
        if not ok or user is None or not user.is_active:
            record_login_failure(r, username, ip, settings.login_lockout_seconds)
            log.warning("login failed user=%r ip=%s", username, ip)
            return render_login(request, "Invalid username or password.", 401)

        clear_login_failures(r, username)
        user.last_login_at = datetime.now(UTC)
        db.commit()
        # A fresh token on every login, so a pre-set cookie can't be fixed onto a session.
        destroy_session(r, request.cookies.get(SESSION_COOKIE))
        token = create_session(r, user.id, settings.session_ttl_seconds)
        log.info("login ok user=%r ip=%s", username, ip)

        response = RedirectResponse(f"{base}/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(SESSION_COOKIE, token, **cookie_args(settings.session_ttl_seconds))
        response.delete_cookie(LOGIN_CSRF_COOKIE, path=base)
        return response

    @router.post("/logout", dependencies=[Depends(require_csrf)])
    def logout(request: Request, r: Annotated[redis.Redis, Depends(get_valkey)]):
        destroy_session(r, request.cookies.get(SESSION_COOKIE))
        response = RedirectResponse(f"{base}/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE, path=base)
        return response

    @router.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, user: CurrentUser, session: CurrentSession):
        return templates.TemplateResponse(
            request, "dashboard.html", {"user": user, "csrf_token": session.csrf_token}
        )

    app.include_router(router)
    app.mount(f"{base}/static", StaticFiles(directory=APP_DIR / "static"), name="static")
    return app


app = create_app()
