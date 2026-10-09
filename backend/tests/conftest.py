import pyotp
import pytest
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.main import create_app
from app.models import User

PASSWORD = "correct horse battery"


@pytest.fixture
def app():
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", secret_key=security.generate_key(),
                        cookie_secure=False, max_failures_user=3, max_totp_attempts=3)
    app = create_app(settings)
    with app.state.session_factory() as db:
        db.add(User(username="admin", password_hash=security.hash_password(PASSWORD), role="admin"))
        db.add(User(username="oper", password_hash=security.hash_password(PASSWORD), role="operator"))
        db.commit()
    return app


@pytest.fixture
def client(app):
    return TestClient(app, base_url="http://testserver")


def fresh(app):
    return TestClient(app, base_url="http://testserver")


def login_and_enroll(client, username="admin"):
    """Полный первый вход: пароль → настройка TOTP → подтверждение. Возвращает (secret, ответ, resp)."""
    assert client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json() == {"next": "2fa_setup"}
    secret = client.post("/api/auth/2fa/setup").json()["secret"]
    resp = client.post("/api/auth/2fa/enable", json={"code": pyotp.TOTP(secret).now()})
    assert resp.status_code == 200, resp.text
    return secret, resp.json()


def csrf(data):
    return {"X-CSRF-Token": data["csrf"]}


