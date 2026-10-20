"""UI routes for clients, authorisations, scope items and the audit log."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import services
from app.auth import CurrentSession, CurrentUser, require_csrf
from app.config import Settings, get_settings
from app.db import get_db
from app.models import AuditLog, Authorisation, Client, ScopeItem
from app.services import ServiceError, now_utc
from app.web import parse_local

Db = Annotated[Session, Depends(get_db)]
Config = Annotated[Settings, Depends(get_settings)]


def build_router(templates: Jinja2Templates, base: str) -> APIRouter:
    router = APIRouter(prefix=base)
    csrf = [Depends(require_csrf)]

    def get_or_404(db: Session, model, obj_id: int):
        obj = db.get(model, obj_id)
        if obj is None:
            raise HTTPException(status_code=404)
        return obj

    def client_page(request, db, user, session, client: Client, error=None, code=200):
        return templates.TemplateResponse(
            request,
            "client_detail.html",
            {
                "user": user,
                "csrf_token": session.csrf_token,
                "client": client,
                "now": now_utc(),
                "error": error,
                "audit": db.scalars(
                    select(AuditLog)
                    .where(AuditLog.details["client_id"].as_integer() == client.id)
                    .order_by(AuditLog.id.desc())
                    .limit(25)
                ).all(),
            },
            status_code=code,
        )

    def back_to(client_id: int) -> RedirectResponse:
        return RedirectResponse(f"{base}/clients/{client_id}", status_code=303)

    def scope_row(request, session, item: ScopeItem) -> Response:
        return templates.TemplateResponse(
            request,
            "_scope_row.html",
            {"item": item, "csrf_token": session.csrf_token, "now": now_utc()},
        )

    # Clients

    @router.get("/clients")
    def list_clients(request: Request, db: Db, user: CurrentUser, session: CurrentSession):
        clients = db.scalars(select(Client).order_by(Client.name)).all()
        return templates.TemplateResponse(
            request,
            "clients.html",
            {"user": user, "csrf_token": session.csrf_token, "clients": clients, "now": now_utc()},
        )

    @router.post("/clients", dependencies=csrf)
    def create_client(
        request: Request,
        db: Db,
        user: CurrentUser,
        session: CurrentSession,
        name: Annotated[str, Form(max_length=200)],
        contact_name: Annotated[str, Form(max_length=200)] = "",
        contact_email: Annotated[str, Form(max_length=320)] = "",
    ):
        try:
            client = services.create_client(db, user.username, name, contact_name, contact_email)
        except ServiceError as exc:
            clients = db.scalars(select(Client).order_by(Client.name)).all()
            return templates.TemplateResponse(
                request,
                "clients.html",
                {
                    "user": user,
                    "csrf_token": session.csrf_token,
                    "clients": clients,
                    "now": now_utc(),
                    "error": str(exc),
                },
                status_code=400,
            )
        return back_to(client.id)

    @router.get("/clients/{client_id}")
    def client_detail(
        request: Request, client_id: int, db: Db, user: CurrentUser, session: CurrentSession
    ):
        return client_page(request, db, user, session, get_or_404(db, Client, client_id))

    # Authorisations

    @router.post("/clients/{client_id}/authorisations", dependencies=csrf)
    def add_authorisation(
        request: Request,
        client_id: int,
        db: Db,
        settings: Config,
        user: CurrentUser,
        session: CurrentSession,
        document: Annotated[UploadFile, File()],
        signed_by: Annotated[str, Form(max_length=200)],
        valid_from: Annotated[str, Form()],
        valid_to: Annotated[str, Form()],
        source_ip: Annotated[str, Form(max_length=45)],
    ):
        client = get_or_404(db, Client, client_id)
        data = document.file.read(settings.max_authorisation_bytes + 1)
        try:
            try:
                start, end = parse_local(valid_from), parse_local(valid_to)
            except ValueError as exc:
                raise ServiceError("Enter valid start and end times") from exc
            services.add_authorisation(
                db,
                settings,
                user.username,
                client,
                document=data,
                signed_by=signed_by,
                valid_from=start,
                valid_to=end,
                source_ip=source_ip,
            )
        except ServiceError as exc:
            return client_page(request, db, user, session, client, str(exc), 400)
        return back_to(client.id)

    @router.get("/authorisations/{auth_id}/document")
    def authorisation_document(auth_id: int, db: Db, user: CurrentUser):
        auth = get_or_404(db, Authorisation, auth_id)
        return FileResponse(
            auth.document_path,
            media_type="application/pdf",
            filename=f"authorisation-{auth.client_id}-{auth.id}.pdf",
        )

    @router.post("/authorisations/{auth_id}/revoke", dependencies=csrf)
    def revoke_authorisation(
        request: Request,
        auth_id: int,
        db: Db,
        user: CurrentUser,
        session: CurrentSession,
        reason: Annotated[str, Form(max_length=500)] = "",
    ):
        auth = get_or_404(db, Authorisation, auth_id)
        try:
            services.revoke_authorisation(db, user.username, auth, reason)
        except ServiceError as exc:
            return client_page(request, db, user, session, auth.client, str(exc), 400)
        return back_to(auth.client_id)

    # Scope items

    @router.post("/clients/{client_id}/scope", dependencies=csrf)
    def add_scope(
        request: Request,
        client_id: int,
        db: Db,
        settings: Config,
        user: CurrentUser,
        session: CurrentSession,
        auth_id: Annotated[int, Form()],
        type: Annotated[str, Form()],
        value: Annotated[str, Form(max_length=253)],
    ):
        client = get_or_404(db, Client, client_id)
        auth = get_or_404(db, Authorisation, auth_id)
        try:
            services.add_scope_item(db, settings, user.username, client, auth, type, value)
        except ServiceError as exc:
            return client_page(request, db, user, session, client, str(exc), 400)
        return back_to(client.id)

    def scope_action(request, db, user, session, item_id, action) -> Response:
        item = get_or_404(db, ScopeItem, item_id)
        try:
            action(item)
        except ServiceError as exc:
            if request.headers.get("HX-Request"):
                return Response(str(exc), status_code=400, media_type="text/plain")
            return client_page(request, db, user, session, item.client, str(exc), 400)
        if request.headers.get("HX-Request"):
            return scope_row(request, session, item)
        return back_to(item.client_id)

    @router.post("/scope/{item_id}/verify", dependencies=csrf)
    def verify_scope(
        request: Request, item_id: int, db: Db, user: CurrentUser, session: CurrentSession
    ):
        return scope_action(
            request,
            db,
            user,
            session,
            item_id,
            lambda item: services.request_verification(db, user.username, item),
        )

    @router.post("/scope/{item_id}/attest", dependencies=csrf)
    def attest_scope(
        request: Request,
        item_id: int,
        db: Db,
        user: CurrentUser,
        session: CurrentSession,
        confirm: Annotated[str, Form()] = "",
    ):
        return scope_action(
            request,
            db,
            user,
            session,
            item_id,
            lambda item: services.attest_ip_item(db, user.username, item, confirm == "yes"),
        )

    @router.post("/scope/{item_id}/remove", dependencies=csrf)
    def remove_scope(
        request: Request, item_id: int, db: Db, user: CurrentUser, session: CurrentSession
    ):
        return scope_action(
            request,
            db,
            user,
            session,
            item_id,
            lambda item: services.remove_scope_item(db, user.username, item),
        )

    @router.get("/scope/{item_id}/row")
    def scope_row_partial(
        request: Request, item_id: int, db: Db, user: CurrentUser, session: CurrentSession
    ):
        return scope_row(request, session, get_or_404(db, ScopeItem, item_id))

    # Audit log

    @router.get("/audit")
    def audit_log(request: Request, db: Db, user: CurrentUser, session: CurrentSession):
        entries = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(500)).all()
        return templates.TemplateResponse(
            request,
            "audit.html",
            {"user": user, "csrf_token": session.csrf_token, "entries": entries},
        )

    return router
