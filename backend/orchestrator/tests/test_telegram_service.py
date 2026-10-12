"""send_alert() подставляет событие атакующего (тип, IP, свойства) в HTML-сообщение Telegram
(parse_mode=HTML) — без экранирования это канал HTML-инъекции."""
import asyncio

from app.services import telegram_service as ts


class _FakeResponse:
    status_code = 200
    text = ""

    def json(self):
        return {"subscribers": []}


class _FakeAsyncClient:
    """Подмена httpx.AsyncClient: не ходит в сеть, запоминает отправленный payload."""
    sent: list[dict] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        _FakeAsyncClient.sent.append({"url": url, "json": json, "headers": headers})
        return _FakeResponse()

    async def get(self, url, params=None, headers=None):
        return _FakeResponse()


def test_send_alert_escapes_attacker_controlled_text(monkeypatch):
    monkeypatch.setattr(ts, "TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setattr(ts, "TELEGRAM_CHAT_ID", "12345")
    monkeypatch.setattr(ts.httpx, "AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.sent = []

    evil = "<b>pwn</b><script>alert(1)</script>"
    asyncio.run(ts.send_alert(evil, evil, {"command": evil}))

    assert len(_FakeAsyncClient.sent) == 1
    text = _FakeAsyncClient.sent[0]["json"]["text"]
    # Атакующий текст попадает в сообщение только в экранированном виде.
    assert "<script>" not in text
    assert "<b>pwn</b>" not in text
    assert "&lt;script&gt;" in text
    # Разметка самого шаблона (не от атакующего) остаётся настоящим HTML.
    assert "<b>НОВАЯ АТАКА В HONEYFORGE!</b>" in text


def test_send_alert_to_multiple_subscribers(monkeypatch):
    monkeypatch.setattr(ts, "TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setattr(ts.httpx, "AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.sent = []

    asyncio.run(ts.send_alert("alert", "1.2.3.4", {"info": "test"}, chat_ids=["1001", "1002"]))
    assert len(_FakeAsyncClient.sent) == 2
    cids = {s["json"]["chat_id"] for s in _FakeAsyncClient.sent}
    assert cids == {"1001", "1002"}


def test_send_alert_noop_without_token(monkeypatch):
    monkeypatch.setattr(ts, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(ts, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(ts.httpx, "AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.sent = []

    asyncio.run(ts.send_alert("command_executed", "203.0.113.1", {}))

    assert _FakeAsyncClient.sent == []


def test_bind_user_by_code_success(monkeypatch):
    class Resp:
        status_code = 200
        def json(self):
            return {"ok": True, "username": "admin", "role": "admin"}

    class Client:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def post(self, url, json=None, headers=None):
            assert "telegram/bind" in url
            assert json["code"] == "HF-123456"
            assert json["chat_id"] == "999"
            return Resp()

    monkeypatch.setattr(ts.httpx, "AsyncClient", Client)
    ok, info = asyncio.run(ts.bind_user_by_code("hf-123456", 999, "operator_tg"))
    assert ok is True
    assert "admin" in info


def test_bind_user_by_code_failure(monkeypatch):
    class Resp:
        status_code = 400
        def json(self):
            return {"detail": "Код не найден или истёк"}

    class Client:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def post(self, url, json=None, headers=None):
            return Resp()

    monkeypatch.setattr(ts.httpx, "AsyncClient", Client)
    ok, info = asyncio.run(ts.bind_user_by_code("HF-000000", 999))
    assert ok is False
    assert "Код не найден" in info


def test_check_user_auth(monkeypatch):
    class Resp:
        status_code = 200
        def json(self):
            return {"authenticated": True, "username": "soc_lead", "role": "admin"}

    class Client:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def post(self, url, json=None, headers=None):
            assert "check-auth" in url
            return Resp()

    monkeypatch.setattr(ts.httpx, "AsyncClient", Client)
    res = asyncio.run(ts.check_user_auth(777))
    assert res["authenticated"] is True
    assert res["username"] == "soc_lead"


def test_unbind_user(monkeypatch):
    class Resp:
        status_code = 200

    class Client:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def post(self, url, json=None, headers=None):
            assert "telegram/unbind" in url
            return Resp()

    monkeypatch.setattr(ts.httpx, "AsyncClient", Client)
    assert asyncio.run(ts.unbind_user(777)) is True


def test_unauthorized_user_blocked_from_protected_commands(monkeypatch):
    sent_messages = []

    async def fake_check_auth(cid):
        return {"authenticated": False}

    async def fake_tg_post(client, base, method, payload):
        sent_messages.append({"method": method, "payload": payload})

    monkeypatch.setattr(ts, "check_user_auth", fake_check_auth)
    monkeypatch.setattr(ts, "_tg_post", fake_tg_post)

    # Неавторизованный пользователь пробует нажать кнопку «📊 Статистика SOC»
    update = {
        "message": {
            "message_id": 1,
            "chat": {"id": 12345},
            "text": "📊 Статистика SOC",
            "from": {"id": 12345, "username": "unauth_user"},
        }
    }

    asyncio.run(ts._handle_telegram_update(None, "https://api.telegram.org", update))

    assert len(sent_messages) == 1
    msg = sent_messages[0]["payload"]
    assert "Доступ запрещён" in msg["text"]
    assert msg["reply_markup"] == ts.SOC_UNAUTH_KEYBOARD


def test_unauthorized_user_start_shows_unauth_keyboard(monkeypatch):
    sent_messages = []

    async def fake_check_auth(cid):
        return {"authenticated": False}

    async def fake_tg_post(client, base, method, payload):
        sent_messages.append({"method": method, "payload": payload})

    monkeypatch.setattr(ts, "check_user_auth", fake_check_auth)
    monkeypatch.setattr(ts, "_tg_post", fake_tg_post)

    update = {
        "message": {
            "message_id": 2,
            "chat": {"id": 12345},
            "text": "/start",
            "from": {"id": 12345, "username": "guest"},
        }
    }

    asyncio.run(ts._handle_telegram_update(None, "https://api.telegram.org", update))

    assert len(sent_messages) == 1
    msg = sent_messages[0]["payload"]
    assert msg["reply_markup"] == ts.SOC_UNAUTH_KEYBOARD
    assert "Добро пожаловать в HoneyForge SOC Bot" in msg["text"]


def test_send_message_is_plain_text_to_one_chat(monkeypatch):
    monkeypatch.setattr(ts, "TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setattr(ts.httpx, "AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.sent = []
    assert asyncio.run(ts.send_message("777", "<b>код 123456</b>")) is True
    (sent,) = _FakeAsyncClient.sent
    assert sent["json"] == {"chat_id": "777", "text": "<b>код 123456</b>"}  # без parse_mode: разметка не исполняется


def test_send_message_without_bot_token(monkeypatch):
    monkeypatch.setattr(ts, "TELEGRAM_BOT_TOKEN", "")
    assert asyncio.run(ts.send_message("777", "x")) is False


def test_direct_endpoint_requires_internal_token(monkeypatch):
    from fastapi.testclient import TestClient

    from app.api.v1 import notify

    monkeypatch.setenv("ORCH_TOKEN", "orch")
    sent = []

    async def fake_send(chat_id, text):
        sent.append((chat_id, text))
        return True

    monkeypatch.setattr(notify, "send_message", fake_send)
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(notify.router, prefix="/api/v1/notify")
    c = TestClient(app)
    body = {"chat_id": "777", "text": "код"}
    assert c.post("/api/v1/notify/direct", json=body).status_code == 401
    assert c.post("/api/v1/notify/direct", json=body, headers={"X-Internal-Token": "orch"}).json() == {"status": "sent"}
    assert c.post("/api/v1/notify/direct", json={"chat_id": "abc", "text": "x"},
                  headers={"X-Internal-Token": "orch"}).status_code == 422
    assert sent == [("777", "код")]
