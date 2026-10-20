from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, event, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def as_utc(dt: datetime) -> datetime:
    # SQLite (tests) drops tzinfo; Postgres keeps it. Treat naive values as UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class User(Base):
    """Secure Link Solutions staff account. Clients never get accounts here."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    contact_name: Mapped[str] = mapped_column(String(200), default="")
    contact_email: Mapped[str] = mapped_column(String(320), default="")
    # Filled in M4 when the DefectDojo product is created.
    dojo_product_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    authorisations: Mapped[list["Authorisation"]] = relationship(
        back_populates="client", order_by="Authorisation.valid_from.desc()"
    )
    scope_items: Mapped[list["ScopeItem"]] = relationship(
        back_populates="client", order_by="ScopeItem.id"
    )

    def live_authorisations(self, now: datetime) -> list["Authorisation"]:
        return [a for a in self.authorisations if a.is_live(now)]

    def usable_authorisations(self, now: datetime) -> list["Authorisation"]:
        """Authorisations scope can still be added to: not revoked and not expired."""
        return [a for a in self.authorisations if a.revoked_at is None and not a.is_expired(now)]


class Authorisation(Base):
    """A signed authorisation letter. Every scan must reference a live one."""

    __tablename__ = "authorisations"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"), index=True)
    document_path: Mapped[str] = mapped_column(String(500))
    document_sha256: Mapped[str] = mapped_column(String(64))
    signed_by: Mapped[str] = mapped_column(String(200))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # The scanner IP named in the letter; the worker checks its egress IP against it (M3).
    source_ip: Mapped[str] = mapped_column(String(45))
    uploaded_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))

    client: Mapped[Client] = relationship(back_populates="authorisations")

    def is_live(self, now: datetime) -> bool:
        return self.revoked_at is None and as_utc(self.valid_from) <= now <= as_utc(self.valid_to)

    def is_expired(self, now: datetime) -> bool:
        return as_utc(self.valid_to) < now


class ScopeItem(Base):
    """A target the client has authorised. A domain item also covers its subdomains."""

    __tablename__ = "scope_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"), index=True)
    auth_id: Mapped[int] = mapped_column(ForeignKey("authorisations.id"), index=True)
    type: Mapped[str] = mapped_column(String(10))  # domain, ip, cidr
    value: Mapped[str] = mapped_column(String(253))
    verify_token: Mapped[str] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # dns_txt, well_known_file, letter_attested
    verify_method: Mapped[str | None] = mapped_column(String(20))
    verified_by: Mapped[str | None] = mapped_column(String(64))
    verify_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verify_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verify_error: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_by: Mapped[str | None] = mapped_column(String(64))

    client: Mapped[Client] = relationship(back_populates="scope_items")
    authorisation: Mapped[Authorisation] = relationship()

    @property
    def verify_record_name(self) -> str:
        return f"_securelink-verify.{self.value}"

    @property
    def verify_record_value(self) -> str:
        return f"securelink-verify={self.verify_token}"


class AuditLog(Base):
    """Append only. Postgres enforces this with a trigger; the ORM refuses too."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(300), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


def _refuse_change(mapper, connection, target):
    raise RuntimeError("audit_log is append only")


event.listen(AuditLog, "before_update", _refuse_change)
event.listen(AuditLog, "before_delete", _refuse_change)
