"""Бэкенд вкладки «Настройки» нового фронта: смена пароля, идеи ловушек; раздача собранного фронта."""
from pathlib import Path

from sqlalchemy import select

from app import config
from app.models import AuditLog, AuthSession, User

from .conftest import PASSWORD, csrf, fresh, login_and_enroll

NEW = "another long passphrase"


def test_change_password_keeps_this_session_and_closes_others(app):
    other = fresh(app)
    login_and_enroll(other)
    c = fresh(app)
    assert c.post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).json() == {"next": "2fa"}
    # первая сессия меняет пароль
    me = other.get("/api/auth/me").json()
    r = other.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": NEW}, headers=csrf(me))
    assert r.status_code == 200, r.text
    assert other.get("/api/auth/me").status_code == 200          # текущая сессия жива
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        assert db.scalar(select(AuthSession).where(AuthSession.user_id == user.id,
                                                   AuthSession.stage == "pre")) is None  # прочие сессии закрыты
        assert db.scalar(select(AuditLog).where(AuditLog.action == "password.change"))
    # старый пароль больше не подходит, новый — да
    assert fresh(app).post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).status_code == 401
    assert fresh(app).post("/api/auth/login", json={"username": "admin", "password": NEW}).status_code == 200


def test_change_password_checks_current_policy_and_csrf(client):
    _, me = login_and_enroll(client)
    url = "/api/auth/password"
    assert client.post(url, json={"current_password": PASSWORD, "new_password": NEW}).status_code == 403  # нет CSRF
    r = client.post(url, json={"current_password": "wrong-password", "new_password": NEW}, headers=csrf(me))
    assert r.status_code == 403 and "текущий" in r.json()["detail"]
    assert client.post(url, json={"current_password": PASSWORD, "new_password": "short"},
                       headers=csrf(me)).status_code == 422
    assert client.post(url, json={"current_password": PASSWORD, "new_password": "admin-" + NEW},
                       headers=csrf(me)).status_code == 422          # пароль содержит логин
    assert client.post(url, json={"current_password": PASSWORD, "new_password": PASSWORD},
                       headers=csrf(me)).status_code == 422          # тот же пароль
    assert client.get("/api/auth/me").status_code == 200              # ошибки не выкидывают из панели


def test_change_password_requires_session(client):
    r = client.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": NEW})
    assert r.status_code == 401


def test_ideas_create_list_and_admin_moderation(app):
    oper = fresh(app)
    _, om = login_and_enroll(oper, "oper")
    r = oper.post("/api/ideas", json={"title": "  Поддельный RDP  ", "description": "порт 3389"}, headers=csrf(om))
    assert r.status_code == 201, r.text
    idea = r.json()
    assert idea["title"] == "Поддельный RDP" and idea["author"] == "oper" and idea["status"] == "new"
    assert [i["id"] for i in oper.get("/api/ideas").json()] == [idea["id"]]
    assert oper.post("/api/ideas", json={"title": "x"}, headers=csrf(om)).status_code == 422
    # статус и удаление — только admin
    assert oper.patch(f"/api/ideas/{idea['id']}", json={"status": "accepted"}, headers=csrf(om)).status_code == 403
    adm = fresh(app)
    _, am = login_and_enroll(adm)
    r = adm.patch(f"/api/ideas/{idea['id']}", json={"status": "accepted"}, headers=csrf(am))
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    assert adm.patch(f"/api/ideas/{idea['id']}", json={"status": "bogus"}, headers=csrf(am)).status_code == 422
    assert adm.delete(f"/api/ideas/{idea['id']}", headers=csrf(am)).status_code == 204
    assert adm.get("/api/ideas").json() == []
    assert adm.delete(f"/api/ideas/{idea['id']}", headers=csrf(am)).status_code == 404


def test_ideas_need_login(client):
    assert client.get("/api/ideas").status_code == 401


def test_static_dir_prefers_build_and_skips_vite_source(tmp_path: Path, monkeypatch):
    src = tmp_path / "frontend"
    (src / "dist").mkdir(parents=True)
    (src / "index.html").write_text('<script type="module" src="/src/main.jsx"></script>')
    code = tmp_path / "backend" / "center" / "app" / "config.py"
    code.parent.mkdir(parents=True)
    code.write_text("")
    monkeypatch.setattr(config, "__file__", str(code))
    assert config._default_static_dir() == ""                          # исходник Vite без сборки не отдаём
    (src / "dist" / "index.html").write_text('<script src="/static/assets/index.js"></script>')
    assert config._default_static_dir() == str(src / "dist")
