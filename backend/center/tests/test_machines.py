import json

import httpx
import pytest
from sqlalchemy import select

from app.models import AuditLog, Trap
from app.orchestrator import Orchestrator

from .conftest import fresh
from .test_center import admin, mk_trap  # noqa: F401  (фикстура и помощник)

MACHINE = {"vmid": 1100, "name": "edge-1", "type": "lxc", "status": "running", "cores": 1, "memory_mb": 1024,
           "disk_gb": 50, "ip": "10.20.0.10", "bridge": "vmbr1", "node": "daniel", "uptime": 5}


@pytest.fixture
def orch(app):
    """Подменённый оркестратор: запоминает запросы, отвечает как настоящий."""
    calls = []

    def handler(request: httpx.Request):
        calls.append((request.method, request.url.path, request.headers.get("x-internal-token"),
                      json.loads(request.content or b"null")))
        if request.method == "GET":
            return httpx.Response(200, json=[dict(MACHINE)])
        if request.method == "POST" and request.url.path.endswith("/machines/"):
            return httpx.Response(202, json={"vmid": 1101, "ip": "10.20.0.11", "status": "creating"})
        if request.url.path.endswith("/agents") and request.method == "POST":
            return httpx.Response(200, json={"status": "installed"})
        if "/agents/" in request.url.path:
            return httpx.Response(200, json={"status": "removed"})
        if request.url.path.startswith("/api/v1/notify"):
            return httpx.Response(200, json={"status": "sent"})
        if request.url.path.endswith("/9999") or "/9999/" in request.url.path:
            return httpx.Response(404, json={"detail": "Машина не найдена"})
        return httpx.Response(200, json={"status": "ok"})

    settings = app.state.settings.model_copy(update={"orchestrator_url": "http://orch:4000", "orchestrator_token": "s3"})
    app.state.orchestrator = Orchestrator(settings, transport=httpx.MockTransport(handler))
    return calls


def test_machines_require_login(app, orch):
    assert fresh(app).get("/api/machines").status_code == 401
    assert orch == []  # без входа до оркестратора не доходим


def test_list_merges_traps_of_machine(admin, orch):
    t = mk_trap(admin, name="ssh-bait")
    admin.patch(f"/api/traps/{t['id']}", json={"machine_vmid": 1100}, headers=admin.h)
    m = admin.get("/api/machines").json()[0]
    assert m["vmid"] == 1100 and m["agent"] == "never"
    assert [x["name"] for x in m["traps"]] == ["ssh-bait"]
    assert orch[0][2] == "s3"  # межсервисный токен передаётся


def test_create_sends_megabytes_and_audits(app, admin, orch):
    r = admin.post("/api/machines", json={"name": "edge-2", "memory_gb": 2}, headers=admin.h)
    assert r.status_code == 202 and r.json()["vmid"] == 1101
    assert orch[-1][3] == {"name": "edge-2", "type": "lxc", "cores": 1, "memory_mb": 2048, "disk_gb": 10}
    with app.state.session_factory() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "machine.create")) is not None


def test_bad_name_and_unknown_action_rejected(admin, orch):
    assert admin.post("/api/machines", json={"name": "bad name"}, headers=admin.h).status_code == 422
    assert admin.post("/api/machines/1100/destroy", headers=admin.h).status_code == 404
    assert orch == []


def test_delete_removes_machine_traps(app, admin, orch):
    t = mk_trap(admin, name="gone")
    admin.patch(f"/api/traps/{t['id']}", json={"machine_vmid": 1100}, headers=admin.h)
    assert admin.delete("/api/machines/1100", headers=admin.h).status_code == 200
    with app.state.session_factory() as db:
        assert db.scalar(select(Trap).where(Trap.name == "gone")) is None


def test_orchestrator_errors_are_passed_through(admin, orch):
    r = admin.post("/api/machines/9999/start", headers=admin.h)
    assert r.status_code == 404 and r.json()["detail"] == "Машина не найдена"


def test_not_configured_is_503(admin):
    assert admin.get("/api/machines").status_code == 503


def _paths(orch, method):
    return [c[1] for c in orch if c[0] == method]


def test_trap_on_machine_gets_agent_automatically(admin, orch):
    r = admin.post("/api/traps", json={"name": "auto", "machine_vmid": 1100}, headers=admin.h)
    body = r.json()
    assert r.status_code == 201 and body["agent"] == "installed"
    assert "token" not in body  # токен ушёл прямо в машину и нигде не показан
    call = [c for c in orch if c[1] == "/api/v1/machines/1100/agents"][0]
    assert call[3]["trap_id"] == body["id"] and call[3]["token"].startswith("hf_")


def test_trap_without_machine_shows_token_once(admin, orch):
    body = admin.post("/api/traps", json={"name": "manual"}, headers=admin.h).json()
    assert body["agent"] == "no-machine" and body["token"].startswith("hf_")
    assert _paths(orch, "POST") == []


def test_move_reissues_token_and_removes_old_agent(admin, orch):
    t = admin.post("/api/traps", json={"name": "mv", "machine_vmid": 1100}, headers=admin.h).json()
    first = [c[3]["token"] for c in orch if c[1].endswith("/agents")][0]
    r = admin.patch(f"/api/traps/{t['id']}", json={"machine_vmid": 1101}, headers=admin.h)
    assert r.json()["agent"] == "installed" and r.json()["machine_vmid"] == 1101
    assert f"/api/v1/machines/1100/agents/{t['id']}" in _paths(orch, "DELETE")
    second = [c[3]["token"] for c in orch if c[1] == "/api/v1/machines/1101/agents"][0]
    assert second != first


def test_delete_trap_removes_agent(admin, orch):
    t = admin.post("/api/traps", json={"name": "rm", "machine_vmid": 1100}, headers=admin.h).json()
    assert admin.delete(f"/api/traps/{t['id']}", headers=admin.h).status_code == 204
    assert f"/api/v1/machines/1100/agents/{t['id']}" in _paths(orch, "DELETE")


def test_reinstall_agent_endpoint(admin, orch):
    t = admin.post("/api/traps", json={"name": "re", "machine_vmid": 1100}, headers=admin.h).json()
    assert admin.post(f"/api/traps/{t['id']}/agent", headers=admin.h).json() == {"agent": "installed"}
    assert len([c for c in orch if c[1] == "/api/v1/machines/1100/agents"]) == 2


def test_honeytoken_event_is_sent_to_telegram(admin, orch):
    import time, uuid
    body = admin.post("/api/traps", json={"name": "ht"}, headers=admin.h).json()
    ev = {"uid": uuid.uuid4().hex, "ts": time.time(), "type": "honeytoken", "src_ip": "203.0.113.5",
          "command": "/root/.aws/credentials"}
    admin.post("/assets/v1/log", json={"events": [ev]}, headers={"Authorization": "Bearer " + body["token"]})
    sent = [c for c in orch if c[1] == "/api/v1/notify/"]
    assert sent and sent[0][3]["event_name"] == "honeytoken" and sent[0][3]["attacker_ip"] == "203.0.113.5"
