"""Сброс забытого пароля через привязанный Telegram: код приходит в бота, 2FA при входе остаётся."""
import json
import re

import httpx
import pyotp
import pytest
from sqlalchemy import select

from app.models import AuthSession, PasswordReset, User
from app.orchestrator import Orchestrator

from .conftest import PASSWORD, fresh, login_and_enroll

NEW = "fresh long passphrase 7"


@pytest.fixture
def bot(app):
    """Подменённый оркестратор: запоминает сообщения, которые центр просит отправить в Telegram."""
    sent = []

    def handler(request: httpx.Request):
        assert request.url.path == "/api/v1/notify/direct"
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"status": "sent"})

    settings = app.state.settings.model_copy(update={"orchestrator_url": "http://orch:4000", "orchestrator_token": "s3"})
    app.state.orchestrator = Orchestrator(settings, transport=httpx.MockTransport(handler))
    return sent


def link(app, username="admin", chat_id="555"):
    """Пользователь с включённой 2FA и привязанным Telegram; возвращает TOTP-секрет."""
    secret, _ = login_and_enroll(fresh(app), username)
    with app.state.session_factory() as db:
        db.scalar(select(User).where(User.username == username)).telegram_chat_id = chat_id
        db.commit()
    return secret


def code_from(msg):
    return re.search(r"\b(\d{6})\b", msg["text"]).group(1)


def test_reset_by_telegram_code_then_login_still_needs_2fa(app, bot):
    secret = link(app)
    c = fresh(app)
    r = c.post("/api/auth/reset/request", json={"username": "Admin "})
    assert r.status_code == 200 and "Telegram" in r.json()["detail"]
    assert bot[0]["chat_id"] == "555"
    code = code_from(bot[0])
    with app.state.session_factory() as db:
        row = db.scalar(select(PasswordReset))
        assert code not in row.code_hash                      # в базе только HMAC
    r = c.post("/api/auth/reset/confirm", json={"username": "admin", "code": code, "new_password": NEW})
    assert r.status_code == 200, r.text
    assert "изменён" in bot[-1]["text"]                        # уведомление о смене
    with app.state.session_factory() as db:
        assert db.scalars(select(AuthSession)).all() == []      # все сессии закрыты
    # код одноразовый
    assert c.post("/api/auth/reset/confirm", json={"username": "admin", "code": code,
                                                   "new_password": NEW + "x"}).status_code == 400
    # старый пароль не подходит; новый — только вместе с 2FA
    assert fresh(app).post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).status_code == 401
    d = fresh(app)
    assert d.post("/api/auth/login", json={"username": "admin", "password": NEW}).json() == {"next": "2fa"}
    future = pyotp.TOTP(secret).at(__import__("time").time() + 30)
    assert d.post("/api/auth/2fa/verify", json={"code": future}).status_code == 200


def test_reset_response_is_the_same_for_unknown_unlinked_and_linked(app, bot):
    link(app, "admin")
    login_and_enroll(fresh(app), "oper")                       # 2FA есть, Telegram не привязан
    answers = [fresh(app).post("/api/auth/reset/request", json={"username": u}).json()
               for u in ("admin", "oper", "ghost")]
    assert answers[0] == answers[1] == answers[2]
    assert [m["chat_id"] for m in bot] == ["555"]               # код ушёл только привязанному


def test_reset_needs_enabled_2fa(app, bot):
    with app.state.session_factory() as db:                     # Telegram привязан, но 2FA сброшена админом
        u = db.scalar(select(User).where(User.username == "oper"))
        u.telegram_chat_id = "777"
        db.commit()
    fresh(app).post("/api/auth/reset/request", json={"username": "oper"})
    assert bot == []


def test_wrong_code_attempts_and_expiry(app, bot):
    link(app)
    c = fresh(app)
    c.post("/api/auth/reset/request", json={"username": "admin"})
    code = code_from(bot[0])
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(2):  # в тестах блокировка после 3 неудач (max_failures_user=3)
        assert c.post("/api/auth/reset/confirm", json={"username": "admin", "code": wrong,
                                                       "new_password": NEW}).status_code == 400
    with app.state.session_factory() as db:
        assert db.scalar(select(PasswordReset)).attempts == 2
    # слабый пароль с верным кодом: 422, код не тратится
    assert c.post("/api/auth/reset/confirm", json={"username": "admin", "code": code,
                                                   "new_password": "short"}).status_code == 422
    with app.state.session_factory() as db:                     # код просрочен
        row = db.scalar(select(PasswordReset))
        row.expires_at = row.created_at
        db.commit()
    assert c.post("/api/auth/reset/confirm", json={"username": "admin", "code": code,
                                                   "new_password": NEW}).status_code == 400
    # третья неудача — логин заблокирован
    assert c.post("/api/auth/reset/request", json={"username": "admin"}).status_code == 429


def test_new_request_invalidates_old_code_and_is_throttled(app, bot):
    link(app)
    c = fresh(app)
    for _ in range(5):
        assert c.post("/api/auth/reset/request", json={"username": "admin"}).status_code == 200
    assert len(bot) == 3                                        # не больше 3 кодов в час
    first, last = code_from(bot[0]), code_from(bot[-1])
    if first != last:
        assert c.post("/api/auth/reset/confirm", json={"username": "admin", "code": first,
                                                       "new_password": NEW}).status_code == 400
    assert c.post("/api/auth/reset/confirm", json={"username": "admin", "code": last,
                                                   "new_password": NEW}).status_code == 200


def test_bot_unavailable_is_not_revealed(app):
    link(app)  # оркестратор не настроен — отправка не удаётся, ответ тот же
    r = fresh(app).post("/api/auth/reset/request", json={"username": "admin"})
    assert r.status_code == 200 and "Telegram" in r.json()["detail"]
