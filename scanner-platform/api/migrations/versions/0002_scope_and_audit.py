"""clients, authorisations, scope items, append-only audit log

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("contact_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("contact_email", sa.String(320), nullable=False, server_default=""),
        sa.Column("dojo_product_id", sa.Integer(), nullable=True),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "authorisations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("client_id", sa.Integer(), sa.ForeignKey("clients.id"), nullable=False),
        sa.Column("document_path", sa.String(500), nullable=False),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.Column("signed_by", sa.String(200), nullable=False),
        sa.Column("valid_from", TZ, nullable=False),
        sa.Column("valid_to", TZ, nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("uploaded_by", sa.String(64), nullable=False),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", TZ, nullable=True),
        sa.Column("revoked_by", sa.String(64), nullable=True),
        sa.CheckConstraint("valid_to > valid_from", name="ck_authorisations_window"),
    )
    op.create_index("ix_authorisations_client_id", "authorisations", ["client_id"])
    op.create_table(
        "scope_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("client_id", sa.Integer(), sa.ForeignKey("clients.id"), nullable=False),
        sa.Column("auth_id", sa.Integer(), sa.ForeignKey("authorisations.id"), nullable=False),
        sa.Column("type", sa.String(10), nullable=False),
        sa.Column("value", sa.String(253), nullable=False),
        sa.Column("verify_token", sa.String(64), nullable=False),
        sa.Column("verified_at", TZ, nullable=True),
        sa.Column("verify_method", sa.String(20), nullable=True),
        sa.Column("verified_by", sa.String(64), nullable=True),
        sa.Column("verify_requested_at", TZ, nullable=True),
        sa.Column("last_verify_attempt_at", TZ, nullable=True),
        sa.Column("last_verify_error", sa.String(500), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("removed_at", TZ, nullable=True),
        sa.Column("removed_by", sa.String(64), nullable=True),
        sa.CheckConstraint("type IN ('domain', 'ip', 'cidr')", name="ck_scope_items_type"),
    )
    op.create_index("ix_scope_items_client_id", "scope_items", ["client_id"])
    op.create_index("ix_scope_items_auth_id", "scope_items", ["auth_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(300), nullable=False, server_default=""),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])

    if op.get_bind().dialect.name == "postgresql":
        # Append only, enforced by the database rather than just the app.
        op.execute(
            """
            CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit_log is append only';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            "CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log "
            "FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();"
        )
        op.execute(
            "CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log "
            "FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log")
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_update_delete ON audit_log")
        op.execute("DROP FUNCTION IF EXISTS audit_log_append_only()")
    op.drop_table("audit_log")
    op.drop_table("scope_items")
    op.drop_table("authorisations")
    op.drop_table("clients")
