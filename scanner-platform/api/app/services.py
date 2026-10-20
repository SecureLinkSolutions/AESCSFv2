"""Clients, authorisations and scope: every change goes through here and is audited.

Each function adds an audit_log row in the same transaction as the change it
records, so a change can't commit without its audit entry.
"""

import hashlib
import ipaddress
import secrets
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AuditLog, Authorisation, Client, ScopeItem, as_utc
from app.scope import (
    SCOPE_TYPES,
    ScopeEntry,
    ScopeError,
    normalise_scope_value,
    scope_overlaps,
)


class ServiceError(ValueError):
    """A request the rules refuse; the message is safe to show to staff."""


def now_utc() -> datetime:
    return datetime.now(UTC)


def audit(db: Session, actor: str, action: str, target: str = "", **details) -> None:
    db.add(AuditLog(actor=actor, action=action, target=target, details=details))


# Clients


def create_client(
    db: Session, actor: str, name: str, contact_name: str = "", contact_email: str = ""
) -> Client:
    name = name.strip()
    if not name:
        raise ServiceError("Client name is required")
    if db.scalar(select(Client).where(Client.name == name)):
        raise ServiceError(f"A client called {name!r} already exists")
    client = Client(
        name=name, contact_name=contact_name.strip(), contact_email=contact_email.strip()
    )
    db.add(client)
    db.flush()
    audit(db, actor, "client.create", f"client:{client.id}", name=name)
    db.commit()
    return client


# Authorisations


def add_authorisation(
    db: Session,
    settings: Settings,
    actor: str,
    client: Client,
    *,
    document: bytes,
    signed_by: str,
    valid_from: datetime,
    valid_to: datetime,
    source_ip: str,
) -> Authorisation:
    signed_by = signed_by.strip()
    if not signed_by:
        raise ServiceError("Signed by is required")
    if valid_to <= valid_from:
        raise ServiceError("The authorisation must end after it starts")
    if as_utc(valid_to) <= now_utc():
        raise ServiceError("That authorisation has already expired")
    try:
        source = ipaddress.ip_address(source_ip.strip())
    except ValueError as exc:
        raise ServiceError("Source IP must be the scanner's public IP address") from exc
    if not source.is_global:
        raise ServiceError("Source IP must be a public address")
    if not document.startswith(b"%PDF-"):
        raise ServiceError("The authorisation document must be a PDF")
    if len(document) > settings.max_authorisation_bytes:
        raise ServiceError("The authorisation document is too large")

    digest = hashlib.sha256(document).hexdigest()
    folder = Path(settings.authorisation_dir) / str(client.id)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{digest}.pdf"
    if not path.exists():
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(document)
        tmp.replace(path)

    auth = Authorisation(
        client_id=client.id,
        document_path=str(path),
        document_sha256=digest,
        signed_by=signed_by,
        valid_from=valid_from,
        valid_to=valid_to,
        source_ip=str(source),
        uploaded_by=actor,
    )
    db.add(auth)
    db.flush()
    audit(
        db,
        actor,
        "authorisation.add",
        f"authorisation:{auth.id}",
        client_id=client.id,
        signed_by=signed_by,
        valid_from=valid_from.isoformat(),
        valid_to=valid_to.isoformat(),
        source_ip=str(source),
        document_sha256=digest,
    )
    db.commit()
    return auth


def revoke_authorisation(db: Session, actor: str, auth: Authorisation, reason: str) -> None:
    if auth.revoked_at is not None:
        raise ServiceError("Already revoked")
    auth.revoked_at = now_utc()
    auth.revoked_by = actor
    audit(
        db,
        actor,
        "authorisation.revoke",
        f"authorisation:{auth.id}",
        client_id=auth.client_id,
        reason=reason.strip(),
    )
    db.commit()


# Scope items


def _active_items(db: Session):
    return select(ScopeItem).where(ScopeItem.removed_at.is_(None))


def add_scope_item(
    db: Session,
    settings: Settings,
    actor: str,
    client: Client,
    auth: Authorisation,
    kind: str,
    value: str,
) -> ScopeItem:
    if kind not in SCOPE_TYPES:
        raise ServiceError("Choose domain, IP or CIDR")
    if auth.client_id != client.id:
        raise ServiceError("That authorisation belongs to another client")
    # A letter that starts in the future is fine to add scope to; it just isn't scannable yet.
    if auth.revoked_at is not None or auth.is_expired(now_utc()):
        raise ServiceError("That authorisation is revoked or expired")
    try:
        value = normalise_scope_value(kind, value, settings.blocklist, settings.scope_limits)
    except ScopeError as exc:
        raise ServiceError(str(exc)) from exc

    new = ScopeEntry(kind, value)
    for other in db.scalars(_active_items(db)):
        if scope_overlaps(new, ScopeEntry(other.type, other.value)):
            if other.client_id == client.id:
                raise ServiceError(f"Already covered by scope item {other.type} {other.value}")
            # Never let two clients claim the same target.
            raise ServiceError(f"{value} overlaps another client's scope")

    item = ScopeItem(
        client_id=client.id,
        auth_id=auth.id,
        type=kind,
        value=value,
        verify_token=secrets.token_urlsafe(24),
        created_by=actor,
    )
    db.add(item)
    db.flush()
    audit(
        db,
        actor,
        "scope.add",
        f"scope:{item.id}",
        client_id=client.id,
        auth_id=auth.id,
        type=kind,
        value=value,
    )
    db.commit()
    return item


def remove_scope_item(db: Session, actor: str, item: ScopeItem) -> None:
    if item.removed_at is not None:
        raise ServiceError("Already removed")
    item.removed_at = now_utc()
    item.removed_by = actor
    audit(db, actor, "scope.remove", f"scope:{item.id}", client_id=item.client_id, value=item.value)
    db.commit()


def request_verification(db: Session, actor: str, item: ScopeItem) -> None:
    if item.type != "domain":
        raise ServiceError(
            "Only domains are verified by DNS or file; attest IPs against the letter"
        )
    if item.removed_at is not None:
        raise ServiceError("That scope item was removed")
    item.verify_requested_at = now_utc()
    audit(
        db,
        actor,
        "scope.verify_request",
        f"scope:{item.id}",
        client_id=item.client_id,
        value=item.value,
    )
    db.commit()


def attest_ip_item(db: Session, actor: str, item: ScopeItem, confirmed: bool) -> None:
    """IPs and CIDRs can't be proven by DNS, so a person confirms they're in the signed letter."""
    if item.type == "domain":
        raise ServiceError("Domains must be verified by DNS TXT or the well-known file")
    if item.removed_at is not None:
        raise ServiceError("That scope item was removed")
    if not confirmed:
        raise ServiceError("Tick the box to confirm the address is listed in the signed letter")
    item.verified_at = now_utc()
    item.verify_method = "letter_attested"
    item.verified_by = actor
    item.last_verify_error = None
    audit(
        db,
        actor,
        "scope.attest",
        f"scope:{item.id}",
        client_id=item.client_id,
        value=item.value,
        auth_id=item.auth_id,
        document_sha256=item.authorisation.document_sha256,
    )
    db.commit()


def record_verification(db: Session, item: ScopeItem, ok: bool, method: str | None, detail: str):
    """Called by the verifier. A failed recheck withdraws an earlier verification."""
    item.last_verify_attempt_at = now_utc()
    item.verify_requested_at = None
    if ok:
        item.verified_at = now_utc()
        item.verify_method = method
        item.verified_by = "system:verifier"
        item.last_verify_error = None
        audit(
            db,
            "system:verifier",
            "scope.verified",
            f"scope:{item.id}",
            client_id=item.client_id,
            value=item.value,
            method=method,
            detail=detail,
        )
    else:
        item.verified_at = None
        item.verify_method = None
        item.last_verify_error = detail[:500]
        audit(
            db,
            "system:verifier",
            "scope.verify_failed",
            f"scope:{item.id}",
            client_id=item.client_id,
            value=item.value,
            detail=detail,
        )
    db.commit()


def scannable_scope(db: Session, client_id: int, at: datetime | None = None) -> list[ScopeEntry]:
    """Scope the worker may use right now: verified, not removed, under a live authorisation."""
    at = at or now_utc()
    items = db.scalars(
        _active_items(db).where(
            ScopeItem.client_id == client_id, ScopeItem.verified_at.is_not(None)
        )
    )
    return [ScopeEntry(item.type, item.value) for item in items if item.authorisation.is_live(at)]
