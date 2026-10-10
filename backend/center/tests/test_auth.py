import pyotp
from sqlalchemy import select

from app.models import AuditLog, AuthSession, User

from .conftest import PASSWORD, csrf, fresh, login_and_enroll


def test_first_login_enrolls_totp_and_gives_recovery_codes(client):
    secret, data = login_and_enroll(client)
    assert len(data["recovery_codes"]) == 8 and data["role"] == "admin"
    assert client.get("/api/auth/me").json()["username"] == "admin"


def test_totp_secret_is_encrypted_in_db(app, client):
    secret, _ = login_and_enroll(client)
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        assert secret not in user.totp_secret_enc
        for rc in user.recovery_codes:
            assert len(rc.code_hash) == 64  # хэш, не сам код


def test_session_token_stored_hashed(app, client):
    login_and_enroll(client)
    token = client.cookies.get("hf_session")
    with app.state.session_factory() as db:
        sessions = db.scalars(select(AuthSession)).all()
        assert token and all(token != s.token_hash for s in sessions)


def test_second_login_requires_code(app):
    c1 = fresh(app)
    secret, _ = login_and_enroll(c1)
    c2 = fresh(app)
    assert c2.post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).json() == {"next": "2fa"}
    assert c2.get("/api/auth/me").status_code == 401  # одного пароля недостаточно
    # тот же код (шаг) повторно использовать нельзя
    now_code = pyotp.TOTP(secret).now()
    assert c2.post("/api/auth/2fa/verify", json={"code": now_code}).status_code == 401
    future = pyotp.TOTP(secret).at(__import__("time").time() + 30)
    r = c2.post("/api/auth/2fa/verify", json={"code": future})
    assert r.status_code == 200, r.text
    assert c2.get("/api/auth/me").status_code == 200


def test_wrong_password_and_unknown_user_are_indistinguishable(client):
    a = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-1"})
    b = client.post("/api/auth/login", json={"username": "ghost", "password": "wrong-password-1"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_lockout_after_failures_even_with_right_password(client):
    for _ in range(3):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-1"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert r.status_code == 429


def test_lockout_applies_to_unknown_users_too(client):
    for _ in range(3):
        client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    assert client.post("/api/auth/login", json={"username": "ghost", "password": "x"}).status_code == 429


def test_totp_bruteforce_kills_pre_session(app):
    c1 = fresh(app)
    login_and_enroll(c1)
    c2 = fresh(app)
    c2.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    for _ in range(3):
        assert c2.post("/api/auth/2fa/verify", json={"code": "000000"}).status_code in (401, 429)
    assert c2.post("/api/auth/2fa/verify", json={"code": "000000"}).status_code == 401  # сессии больше нет


def test_recovery_code_works_once(app):
    c1 = fresh(app)
    _, data = login_and_enroll(c1)
    code = data["recovery_codes"][0]
    c2 = fresh(app)
    c2.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert c2.post("/api/auth/2fa/verify", json={"code": code.lower()}).status_code == 200
    c3 = fresh(app)
    c3.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert c3.post("/api/auth/2fa/verify", json={"code": code}).status_code == 401


def test_csrf_required_for_unsafe_methods(client):
    _, data = login_and_enroll(client)
    assert client.post("/api/auth/logout").status_code == 403
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert client.post("/api/auth/logout", headers=csrf(data)).status_code == 200
    assert client.get("/api/auth/me").status_code == 401  # сессия уничтожена на сервере


def test_session_fixation_pre_token_not_reused(app, client):
    client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    pre = client.cookies.get("hf_pre")
    secret = client.post("/api/auth/2fa/setup").json()["secret"]
    client.post("/api/auth/2fa/enable", json={"code": pyotp.TOTP(secret).now()})
    assert client.cookies.get("hf_session") != pre


def test_expired_session_rejected(app, client):
    from datetime import timedelta
    from app.models import utcnow
    login_and_enroll(client)
    with app.state.session_factory() as db:
        s = db.scalars(select(AuthSession).where(AuthSession.stage == "full")).one()
        s.last_seen = utcnow() - timedelta(minutes=31)
        db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_operator_cannot_manage_users_admin_can(app):
    admin = fresh(app)
    _, adata = login_and_enroll(admin, "admin")
    op = fresh(app)
    _, odata = login_and_enroll(op, "oper")
    assert op.get("/api/users").status_code == 403
    r = admin.post("/api/users", json={"username": "newbie", "password": "another long password", "role": "operator"},
                   headers=csrf(adata))
    assert r.status_code == 201
    assert admin.post("/api/users", json={"username": "weak", "password": "short"}, headers=csrf(adata)).status_code == 422
    uid = r.json()["id"]
    assert admin.patch(f"/api/users/{uid}", json={"is_active": False}, headers=csrf(adata)).status_code == 200
    blocked = fresh(app).post("/api/auth/login", json={"username": "newbie", "password": "another long password"})
    assert blocked.status_code == 401


def test_deactivate_revokes_sessions_and_reset_2fa(app):
    admin = fresh(app)
    _, adata = login_and_enroll(admin, "admin")
    op = fresh(app)
    login_and_enroll(op, "oper")
    with app.state.session_factory() as db:
        oper_id = db.scalar(select(User).where(User.username == "oper")).id
    assert admin.post(f"/api/users/{oper_id}/reset-2fa", headers=csrf(adata)).status_code == 200
    assert op.get("/api/auth/me").status_code == 401
    assert fresh(app).post("/api/auth/login", json={"username": "oper", "password": PASSWORD}).json() == {"next": "2fa_setup"}


def test_audit_log_records_events_without_secrets(app, client):
    client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-1"})
    login_and_enroll(client)
    with app.state.session_factory() as db:
        actions = [a.action for a in db.scalars(select(AuditLog))]
        text = " ".join(a.detail for a in db.scalars(select(AuditLog)))
    assert {"login.fail", "login.password_ok", "2fa.enabled", "login.ok"} <= set(actions)
    assert PASSWORD not in text and "wrong-password-1" not in text


def test_security_headers_and_no_docs(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    assert client.get("/docs").status_code == 404
