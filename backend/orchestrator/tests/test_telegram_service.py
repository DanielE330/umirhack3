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
