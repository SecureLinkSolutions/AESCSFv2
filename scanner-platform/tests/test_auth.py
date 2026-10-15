import re

from conftest import login


def csrf_from(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_healthz_reports_dependencies(client):
    resp = client.get("/app/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"postgres": "ok", "valkey": "ok"}


def test_healthz_fails_when_valkey_down(app, client, valkey):
    from app.valkey import get_valkey

    class Down:
        def ping(self):
            raise ConnectionError

    app.dependency_overrides[get_valkey] = lambda: Down()
    resp = client.get("/app/healthz")
    assert resp.status_code == 503
    assert resp.json()["valkey"] == "fail"


def test_dashboard_requires_login(client):
    resp = client.get("/app/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/app/login"


def test_htmx_request_gets_hx_redirect(client):
    resp = client.get("/app/", headers={"HX-Request": "true"}, follow_redirects=False)
    assert resp.status_code == 401
    assert resp.headers["HX-Redirect"] == "/app/login"


def test_login_success_sets_session_and_shows_dashboard(client, user):
    resp = login(client)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/app/"
    set_cookie = resp.headers["set-cookie"].lower()
    assert "slscan_session=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/app" in set_cookie

    page = client.get("/app/")
    assert page.status_code == 200
    assert "alice" in page.text


def test_login_wrong_password(client, user):
    resp = login(client, password="wrong password here")
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.text
    assert "slscan_session" not in resp.cookies


def test_login_unknown_user_same_message(client):
    resp = login(client, username="mallory")
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.text


def test_login_rejects_missing_csrf(client, user):
    resp = client.post(
        "/app/login",
        data={"username": "alice", "password": "correct horse battery", "csrf_token": "x"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_lockout_after_repeated_failures(client, user):
    for _ in range(5):
        assert login(client, password="wrong password here").status_code == 401
    # Correct password is refused while locked out.
    assert login(client).status_code == 429


def test_disabled_user_cannot_login(client, user, db):
    user.is_active = False
    db.commit()
    assert login(client).status_code == 401


def test_disabling_user_ends_existing_session(client, user, db):
    login(client)
    assert client.get("/app/").status_code == 200
    user.is_active = False
    db.commit()
    assert client.get("/app/", follow_redirects=False).status_code == 303


def test_logout_requires_csrf(client, user):
    login(client)
    resp = client.post("/app/logout", data={"csrf_token": "bogus"}, follow_redirects=False)
    assert resp.status_code == 403
    assert client.get("/app/").status_code == 200


def test_logout_revokes_session_server_side(client, user, valkey):
    login(client)
    token = client.cookies.get("slscan_session")
    page = client.get("/app/")
    resp = client.post(
        "/app/logout", data={"csrf_token": csrf_from(page.text)}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert not list(valkey.scan_iter("session:*"))
    # Replaying the old cookie no longer works.
    client.cookies.set("slscan_session", token, path="/app")
    assert client.get("/app/", follow_redirects=False).status_code == 303


def test_session_token_not_stored_in_plaintext(client, user, valkey):
    login(client)
    token = client.cookies.get("slscan_session")
    keys = list(valkey.scan_iter("session:*"))
    assert len(keys) == 1
    assert token not in keys[0]


def test_security_headers(client):
    resp = client.get("/app/login")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["cache-control"] == "no-store"


def test_api_docs_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
