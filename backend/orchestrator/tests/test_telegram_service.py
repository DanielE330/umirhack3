"""send_alert() подставляет событие атакующего (тип, IP, свойства) в HTML-сообщение Telegram
(parse_mode=HTML) — без экранирования это канал HTML-инъекции."""
import asyncio

from app.services import telegram_service as ts


class _FakeResponse:
    status_code = 200
    text = ""


class _FakeAsyncClient:
    """Подмена httpx.AsyncClient: не ходит в сеть, запоминает отправленный payload."""
    sent: list[dict] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None):
        _FakeAsyncClient.sent.append(json)
        return _FakeResponse()


def test_send_alert_escapes_attacker_controlled_text(monkeypatch):
    monkeypatch.setattr(ts, "TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setattr(ts, "TELEGRAM_CHAT_ID", "12345")
    monkeypatch.setattr(ts.httpx, "AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.sent = []

    evil = "<b>pwn</b><script>alert(1)</script>"
    asyncio.run(ts.send_alert(evil, evil, {"command": evil}))

    assert len(_FakeAsyncClient.sent) == 1
    text = _FakeAsyncClient.sent[0]["text"]
    # Атакующий текст попадает в сообщение только в экранированном виде.
    assert "<script>" not in text
    assert "<b>pwn</b>" not in text
    assert "&lt;script&gt;" in text
    # Разметка самого шаблона (не от атакующего) остаётся настоящим HTML.
    assert "<b>НОВАЯ АТАКА В HONEYFORGE!</b>" in text


def test_send_alert_noop_without_token(monkeypatch):
    monkeypatch.setattr(ts, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(ts, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(ts.httpx, "AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.sent = []

    asyncio.run(ts.send_alert("command_executed", "203.0.113.1", {}))

    assert _FakeAsyncClient.sent == []
