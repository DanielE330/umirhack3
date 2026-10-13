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

    # 3. List snapshots
    resp3 = client.get("/api/v1/machines/1100/snapshots", headers=INTERNAL_HEADERS)
    assert resp3.status_code == 200
    assert resp3.json() == [{"name": "clean", "description": "baseline"}]
