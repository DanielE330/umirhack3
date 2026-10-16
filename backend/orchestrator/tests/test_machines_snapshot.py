import sys
from unittest.mock import MagicMock

if "paramiko" not in sys.modules:
    sys.modules["paramiko"] = MagicMock()
if "proxmoxer" not in sys.modules:
    sys.modules["proxmoxer"] = MagicMock()

from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.api.v1 import machines

app = FastAPI()
app.include_router(machines.router, prefix="/api/v1/machines")
client = TestClient(app)
INTERNAL_HEADERS = {"X-Internal-Token": "orch-secret-token-change-me"}


class MockManager:
    def __init__(self):
        self.snapshots = []
        self.rolled_back = []

    def snapshot(self, vmid: int, name: str = "clean", description: str = ""):
        self.snapshots.append((vmid, name, description))

    def rollback(self, vmid: int, name: str = "clean"):
        self.rolled_back.append((vmid, name))

    def list_snapshots(self, vmid: int):
        return [{"name": "clean", "description": "baseline"}]

    def forensic_freeze(self, vmid: int, session_id: str):
        snap = f"forensic_{session_id}"
        self.snapshots.append((vmid, snap, f"Forensic freeze for session {session_id}"))
        return snap


def test_orchestrator_snapshot_and_rollback(monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "orch-secret-token-change-me")
    mock = MockManager()
    monkeypatch.setattr(machines, "manager", lambda: mock)

    # 1. Snapshot
    resp = client.post("/api/v1/machines/1100/snapshot?name=clean", headers=INTERNAL_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "created"
    assert (1100, "clean", "HoneyForge clean baseline") in mock.snapshots

    # 2. Rollback
    resp2 = client.post("/api/v1/machines/1100/rollback?name=clean", headers=INTERNAL_HEADERS)
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "restored"
    assert (1100, "clean") in mock.rolled_back

    # 3. Freeze
    resp_freeze = client.post("/api/v1/machines/1100/freeze?session_id=sess-99", headers=INTERNAL_HEADERS)
    assert resp_freeze.status_code == 200
    assert resp_freeze.json()["status"] == "frozen"
    assert (1100, "forensic_sess-99", "Forensic freeze for session sess-99") in mock.snapshots

    # 4. List snapshots
    resp3 = client.get("/api/v1/machines/1100/snapshots", headers=INTERNAL_HEADERS)
    assert resp3.status_code == 200
    assert resp3.json() == [{"name": "clean", "description": "baseline"}]


def test_proxmox_not_configured_returns_503(monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "orch-secret-token-change-me")
    monkeypatch.delenv("PROXMOX_PASSWORD", raising=False)
    monkeypatch.delenv("PROXMOX_TOKEN_NAME", raising=False)
    monkeypatch.delenv("PROXMOX_TOKEN_VALUE", raising=False)
    monkeypatch.setattr(machines, "_manager", None)

    resp = client.get("/api/v1/machines/", headers=INTERNAL_HEADERS)
    assert resp.status_code == 503
    assert "Учётные данные Proxmox не настроены" in resp.json()["detail"]


def test_proxmox_error_during_list_returns_503(monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "orch-secret-token-change-me")
    mock = MagicMock()
    mock.list_machines.side_effect = RuntimeError("Network timeout to node")
    monkeypatch.setattr(machines, "manager", lambda: mock)

    resp = client.get("/api/v1/machines/", headers=INTERNAL_HEADERS)
    assert resp.status_code == 503
    assert "Proxmox недоступен: Network timeout to node" in resp.json()["detail"]
