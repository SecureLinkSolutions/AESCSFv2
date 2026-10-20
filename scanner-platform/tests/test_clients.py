"""Clients, authorisations, scope items and the audit log, through the UI and service layer."""

import re
from datetime import UTC, datetime, timedelta

import pytest
from conftest import login
from sqlalchemy import select

from app import services
from app.config import get_settings
from app.models import AuditLog, Authorisation, Client
from app.scope import ScopeEntry
from app.verifier import process_pending
from app.verify import VerifyResult

PDF = b"%PDF-1.7\n% fake letter\n%%EOF\n"


def csrf(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


@pytest.fixture
def staff(client, user):
    login(client)
    return csrf(client.get("/app/clients").text)


def make_client(db, name="Acme Energy"):
    return services.create_client(db, "alice", name, "Pat", "pat@acme.example")


def make_auth(db, client, start=-1, end=30):
    now = datetime.now(UTC)
    return services.add_authorisation(
        db,
        get_settings(),
        "alice",
        client,
        document=PDF,
        signed_by="Pat CEO",
        valid_from=now + timedelta(days=start),
        valid_to=now + timedelta(days=end),
        source_ip="45.79.10.20",
    )


def actions(db):
    return [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id))]


# Pages and CSRF


def test_pages_require_login(client):
    for path in ("/app/clients", "/app/clients/1", "/app/audit", "/app/authorisations/1/document"):
        assert client.get(path, follow_redirects=False).status_code == 303, path


def test_create_client_via_ui(client, staff, db):
    resp = client.post(
        "/app/clients", data={"csrf_token": staff, "name": "Acme Energy"}, follow_redirects=False
    )
    assert resp.status_code == 303
    acme = db.scalar(select(Client).where(Client.name == "Acme Energy"))
    assert resp.headers["location"] == f"/app/clients/{acme.id}"
    assert "client.create" in actions(db)
    page = client.get(resp.headers["location"])
    assert "No authorisations yet" in page.text


def test_post_without_csrf_is_refused(client, staff, db):
    resp = client.post("/app/clients", data={"csrf_token": "nope", "name": "Evil"})
    assert resp.status_code == 403
    assert db.scalar(select(Client)) is None


def test_duplicate_client_name(client, staff, db):
    make_client(db)
    resp = client.post("/app/clients", data={"csrf_token": staff, "name": "Acme Energy"})
    assert resp.status_code == 400
    assert "already exists" in resp.text


# Authorisations


def test_upload_authorisation_via_ui(client, staff, db, tmp_path):
    acme = make_client(db)
    resp = client.post(
        f"/app/clients/{acme.id}/authorisations",
        data={
            "csrf_token": staff,
            "signed_by": "Pat CEO",
            "valid_from": "2026-01-01T09:00",
            "valid_to": "2099-12-31T17:00",
            "source_ip": "45.79.10.20",
        },
        files={"document": ("letter.pdf", PDF, "application/pdf")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    auth = db.scalar(select(Authorisation))
    assert auth.signed_by == "Pat CEO"
    # Entered as Sydney time (AEDT, UTC+11), stored as UTC.
    assert auth.valid_from.replace(tzinfo=None) == datetime(2025, 12, 31, 22, 0)
    download = client.get(f"/app/authorisations/{auth.id}/document")
    assert download.content == PDF
    assert download.headers["content-type"] == "application/pdf"
    assert "authorisation.add" in actions(db)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"document": b"MZ not a pdf"}, "must be a PDF"),
        ({"source_ip": "10.0.0.1"}, "public address"),
        ({"source_ip": "scanner"}, "public IP"),
        ({"signed_by": "  "}, "Signed by"),
        ({"valid_to_days": -1}, "already expired"),
        ({"valid_to_days": -10}, "end after it starts"),
    ],
)
def test_authorisation_validation(db, overrides, message):
    acme = make_client(db)
    now = datetime.now(UTC)
    kwargs = dict(
        document=PDF,
        signed_by="Pat",
        valid_from=now - timedelta(days=5),
        valid_to=now + timedelta(days=30),
        source_ip="45.79.10.20",
    )
    if "valid_to_days" in overrides:
        kwargs["valid_to"] = now + timedelta(days=overrides.pop("valid_to_days"))
    kwargs.update(overrides)
    with pytest.raises(services.ServiceError, match=message):
        services.add_authorisation(db, get_settings(), "alice", acme, **kwargs)


def test_oversized_document_refused(db):
    acme = make_client(db)
    big = PDF + b"0" * get_settings().max_authorisation_bytes
    with pytest.raises(services.ServiceError, match="too large"):
        services.add_authorisation(
            db,
            get_settings(),
            "alice",
            acme,
            document=big,
            signed_by="Pat",
            valid_from=datetime.now(UTC),
            valid_to=datetime.now(UTC) + timedelta(days=1),
            source_ip="45.79.10.20",
        )


# Scope items


def test_add_scope_via_ui_and_blocked_value_shows_error(client, staff, db):
    acme = make_client(db)
    auth = make_auth(db, acme)
    ok = client.post(
        f"/app/clients/{acme.id}/scope",
        data={"csrf_token": staff, "auth_id": auth.id, "type": "domain", "value": "Acme.com.au"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    bad = client.post(
        f"/app/clients/{acme.id}/scope",
        data={"csrf_token": staff, "auth_id": auth.id, "type": "ip", "value": "169.254.169.254"},
    )
    assert bad.status_code == 400
    assert "blocked" in bad.text
    page = client.get(f"/app/clients/{acme.id}")
    assert "acme.com.au" in page.text
    assert "_securelink-verify.acme.com.au" in page.text


def test_scope_cannot_overlap_within_or_across_clients(db):
    settings = get_settings()
    acme, other = make_client(db), make_client(db, "Other Co")
    a1, a2 = make_auth(db, acme), make_auth(db, other)
    services.add_scope_item(db, settings, "alice", acme, a1, "domain", "acme.com.au")
    services.add_scope_item(db, settings, "alice", acme, a1, "cidr", "8.8.8.0/28")
    with pytest.raises(services.ServiceError, match="Already covered"):
        services.add_scope_item(db, settings, "alice", acme, a1, "domain", "www.acme.com.au")
    with pytest.raises(services.ServiceError, match="another client"):
        services.add_scope_item(db, settings, "alice", other, a2, "domain", "shop.acme.com.au")
    with pytest.raises(services.ServiceError, match="another client"):
        services.add_scope_item(db, settings, "alice", other, a2, "ip", "8.8.8.5")


def test_scope_needs_matching_usable_authorisation(db):
    settings = get_settings()
    acme, other = make_client(db), make_client(db, "Other Co")
    other_auth = make_auth(db, other)
    with pytest.raises(services.ServiceError, match="another client"):
        services.add_scope_item(db, settings, "alice", acme, other_auth, "ip", "8.8.8.8")
    auth = make_auth(db, acme)
    services.revoke_authorisation(db, "alice", auth, "letter withdrawn")
    with pytest.raises(services.ServiceError, match="revoked or expired"):
        services.add_scope_item(db, settings, "alice", acme, auth, "ip", "8.8.8.8")
    future = make_auth(db, acme, start=7, end=30)
    assert services.add_scope_item(db, settings, "alice", acme, future, "ip", "8.8.8.8")


def test_ip_attestation(client, staff, db):
    acme = make_client(db)
    item = services.add_scope_item(
        db, get_settings(), "alice", acme, make_auth(db, acme), "ip", "8.8.8.8"
    )
    refused = client.post(f"/app/scope/{item.id}/attest", data={"csrf_token": staff})
    assert refused.status_code == 400
    resp = client.post(
        f"/app/scope/{item.id}/attest",
        data={"csrf_token": staff, "confirm": "yes"},
        headers={"HX-Request": "true"},
    )
    assert resp.status_code == 200
    assert "verified" in resp.text and f'id="scope-{item.id}"' in resp.text
    db.refresh(item)
    assert item.verify_method == "letter_attested" and item.verified_by == "alice"


def test_domain_cannot_be_attested(db):
    acme = make_client(db)
    item = services.add_scope_item(
        db, get_settings(), "alice", acme, make_auth(db, acme), "domain", "acme.com.au"
    )
    with pytest.raises(services.ServiceError, match="DNS TXT"):
        services.attest_ip_item(db, "alice", item, True)


def test_domain_verification_flow(client, staff, db):
    acme = make_client(db)
    item = services.add_scope_item(
        db, get_settings(), "alice", acme, make_auth(db, acme), "domain", "acme.com.au"
    )
    resp = client.post(
        f"/app/scope/{item.id}/verify", data={"csrf_token": staff}, headers={"HX-Request": "true"}
    )
    assert "checking" in resp.text and 'hx-trigger="every 3s"' in resp.text

    seen = []

    def ok(domain, expected):
        seen.append((domain, expected))
        return VerifyResult(True, "dns_txt", "found")

    assert process_pending(db, ok) == 1
    assert seen == [("acme.com.au", item.verify_record_value)]
    db.refresh(item)
    assert item.verified_at and item.verify_method == "dns_txt"
    assert item.verify_requested_at is None
    row = client.get(f"/app/scope/{item.id}/row")
    assert "every 3s" not in row.text and "verified" in row.text

    # A failed re-check withdraws the earlier verification.
    services.request_verification(db, "alice", item)
    process_pending(db, lambda d, e: VerifyResult(False, None, "no TXT record"))
    db.refresh(item)
    assert item.verified_at is None and item.last_verify_error == "no TXT record"
    assert actions(db)[-4:] == [
        "scope.verify_request",
        "scope.verified",
        "scope.verify_request",
        "scope.verify_failed",
    ]


def test_verifier_survives_a_crashing_check(db):
    acme = make_client(db)
    item = services.add_scope_item(
        db, get_settings(), "alice", acme, make_auth(db, acme), "domain", "acme.com.au"
    )
    services.request_verification(db, "alice", item)

    def boom(domain, expected):
        raise RuntimeError("resolver exploded")

    assert process_pending(db, boom) == 1
    db.refresh(item)
    assert item.verified_at is None and "RuntimeError" in item.last_verify_error


def test_remove_scope_item(client, staff, db):
    acme = make_client(db)
    item = services.add_scope_item(
        db, get_settings(), "alice", acme, make_auth(db, acme), "ip", "8.8.8.8"
    )
    resp = client.post(
        f"/app/scope/{item.id}/remove", data={"csrf_token": staff}, follow_redirects=False
    )
    assert resp.status_code == 303
    db.refresh(item)
    assert item.removed_at and item.removed_by == "alice"
    # Removed items free the value for re-use.
    assert services.add_scope_item(
        db, get_settings(), "alice", acme, item.authorisation, "ip", "8.8.8.8"
    )


def test_scannable_scope(db):
    settings = get_settings()
    acme = make_client(db)
    live, revoked, expired_later = make_auth(db, acme), make_auth(db, acme), make_auth(db, acme)
    future = make_auth(db, acme, start=7, end=30)

    def add(auth, kind, value, verify=True):
        item = services.add_scope_item(db, settings, "alice", acme, auth, kind, value)
        if verify:
            if kind == "domain":
                services.record_verification(db, item, True, "dns_txt", "ok")
            else:
                services.attest_ip_item(db, "alice", item, True)
        return item

    add(live, "domain", "acme.com.au")
    add(live, "cidr", "8.8.8.0/28")
    add(live, "ip", "1.1.1.1", verify=False)  # unverified
    removed = add(live, "ip", "1.0.0.1")
    services.remove_scope_item(db, "alice", removed)  # removed
    add(revoked, "ip", "9.9.9.9")
    services.revoke_authorisation(db, "alice", revoked, "withdrawn")
    add(future, "ip", "149.112.112.112")  # authorisation not started
    add(expired_later, "ip", "208.67.222.222")

    now = datetime.now(UTC)
    assert set(services.scannable_scope(db, acme.id, now)) == {
        ScopeEntry("domain", "acme.com.au"),
        ScopeEntry("cidr", "8.8.8.0/28"),
        ScopeEntry("ip", "208.67.222.222"),
    }
    # After the letters' end date nothing is scannable.
    assert services.scannable_scope(db, acme.id, now + timedelta(days=31)) == []
    # Once the future letter starts, its item becomes scannable.
    assert ScopeEntry("ip", "149.112.112.112") in services.scannable_scope(
        db, acme.id, now + timedelta(days=8)
    )


# Audit log


def test_audit_log_is_append_only_in_orm(db):
    make_client(db)
    entry = db.scalar(select(AuditLog))
    entry.action = "tampered"
    with pytest.raises(RuntimeError, match="append only"):
        db.commit()
    db.rollback()
    with pytest.raises(RuntimeError, match="append only"):
        db.delete(entry)
        db.commit()
    db.rollback()


def test_logins_are_audited(client, user, db):
    login(client, password="wrong password here")
    login(client)
    assert actions(db) == ["user.login_failed", "user.login"]


def test_audit_page_and_dashboard(client, staff, db):
    acme = make_client(db)
    auth = make_auth(db, acme, end=10)
    page = client.get("/app/audit")
    assert "client.create" in page.text and "authorisation.add" in page.text
    dash = client.get("/app/")
    assert "Authorisations expiring within 30 days" in dash.text
    assert f"/app/clients/{acme.id}" in dash.text
    assert auth.signed_by in dash.text
