from app import security
from app.models import User

from .conftest import PASSWORD, csrf, fresh, login_and_enroll
from .test_center import PROFILE


def add_user(app, name, role):
    with app.state.session_factory() as db:
        db.add(User(username=name, password_hash=security.hash_password(PASSWORD), role=role))
        db.commit()


def login(app, name):
    c = fresh(app)
    _, data = login_and_enroll(c, name)
    c.h = csrf(data)
    c.me = data
    return c


def test_builtin_roles_and_me_permissions(app):
    add_user(app, "viewer1", "viewer")
    admin, viewer = login(app, "admin"), login(app, "viewer1")
    names = {r["name"] for r in admin.get("/api/roles").json()}
    assert {"admin", "operator", "analyst", "deployer", "auditor", "viewer"} <= names
    assert "users.manage" in admin.get("/api/auth/me").json()["permissions"]
    me = viewer.get("/api/auth/me").json()
    assert me["role_title"] == "Наблюдатель" and "traps.view" in me["permissions"] and "traps.manage" not in me["permissions"]


def test_viewer_reads_but_cannot_change(app):
    add_user(app, "viewer1", "viewer")
    admin, viewer = login(app, "admin"), login(app, "viewer1")
    assert admin.post("/api/profiles", json=PROFILE, headers=admin.h).status_code == 201
    assert viewer.get("/api/profiles").status_code == 200 and viewer.get("/api/traps").status_code == 200
    assert viewer.post("/api/profiles", json={**PROFILE, "name": "x"}, headers=viewer.h).status_code == 403
    assert viewer.post("/api/traps", json={"name": "t1"}, headers=viewer.h).status_code == 403
    assert viewer.get("/api/events/export.csv").status_code == 403 and viewer.get("/api/iocs.csv").status_code == 403
    assert viewer.get("/api/artifacts").status_code == 403 and viewer.get("/api/audit").status_code == 403
    assert viewer.get("/api/users").status_code == 403 and viewer.get("/api/events").status_code == 200


def test_analyst_and_deployer_split(app):
    add_user(app, "an", "analyst")
    add_user(app, "dep", "deployer")
    an, dep = login(app, "an"), login(app, "dep")
    assert an.get("/api/artifacts").status_code == 200 and an.get("/api/iocs.csv").status_code == 200
    assert an.get("/api/artifacts/" + "0" * 64 + "/download").status_code == 404  # доступ есть, файла нет
    assert an.post("/api/profiles", json=PROFILE, headers=an.h).status_code == 403
    assert dep.post("/api/profiles", json=PROFILE, headers=dep.h).status_code == 201
    assert dep.get("/api/artifacts").status_code == 403 and dep.get("/api/events/export.csv").status_code == 403


def test_custom_role_lifecycle_and_audit(app):
    admin = login(app, "admin")
    r = admin.post("/api/roles", json={"name": "soc-night", "title": "Ночная смена", "permissions": ["events.view", "files.view"]},
                   headers=admin.h)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert admin.post("/api/roles", json={"name": "soc-night", "title": "x"}, headers=admin.h).status_code == 409
    assert admin.post("/api/roles", json={"name": "bad", "title": "x", "permissions": ["no.such"]}, headers=admin.h).status_code == 422
    assert admin.post("/api/roles", json={"name": "viewer", "title": "x"}, headers=admin.h).status_code == 409  # имя системной
    u = admin.post("/api/users", json={"username": "night1", "password": "another long password", "role": "soc-night"}, headers=admin.h)
    assert u.status_code == 201
    assert admin.delete(f"/api/roles/{rid}", headers=admin.h).status_code == 409  # роль занята
    night = fresh(app)
    night.post("/api/auth/login", json={"username": "night1", "password": "another long password"})
    assert admin.patch(f"/api/roles/{rid}", json={"permissions": ["events.view"]}, headers=admin.h).json()["permissions"] == ["events.view"]
    assert admin.patch(f"/api/users/{u.json()['id']}", json={"role": "viewer"}, headers=admin.h).status_code == 200
    assert admin.delete(f"/api/roles/{rid}", headers=admin.h).status_code == 200
    actions = [i["action"] for i in admin.get("/api/audit").json()["items"]]
    assert {"role.create", "role.update", "role.delete"} <= set(actions)
    sys_id = next(x["id"] for x in admin.get("/api/roles").json() if x["name"] == "viewer")
    assert admin.patch(f"/api/roles/{sys_id}", json={"title": "x"}, headers=admin.h).status_code == 409
    assert admin.delete(f"/api/roles/{sys_id}", headers=admin.h).status_code == 409


def test_no_privilege_escalation(app):
    admin = login(app, "admin")
    admin.post("/api/roles", json={"name": "hr", "title": "Кадры", "permissions": ["users.manage", "roles.manage", "events.view"]},
               headers=admin.h)
    admin.post("/api/users", json={"username": "hr1", "password": "another long password", "role": "hr"}, headers=admin.h)
    hr = fresh(app)
    hr.post("/api/auth/login", json={"username": "hr1", "password": "another long password"})
    # первый вход: настройка 2FA тем же хелпером, но с другим паролем
    import pyotp
    secret = hr.post("/api/auth/2fa/setup").json()["secret"]
    data = hr.post("/api/auth/2fa/enable", json={"code": pyotp.TOTP(secret).now()}).json()
    h = csrf(data)
    # нельзя ни назначить admin, ни создать роль с правами, которых нет у самого
    assert hr.post("/api/users", json={"username": "evil1", "password": "another long password", "role": "admin"}, headers=h).status_code == 403
    assert hr.post("/api/roles", json={"name": "super", "title": "x", "permissions": ["files.download"]}, headers=h).status_code == 403
    ok = hr.post("/api/roles", json={"name": "lite", "title": "Лайт", "permissions": ["events.view"]}, headers=h)
    assert ok.status_code == 201
    assert hr.post("/api/users", json={"username": "lite1", "password": "another long password", "role": "lite"}, headers=h).status_code == 201
    assert hr.get("/api/audit").status_code == 403  # нет audit.view
