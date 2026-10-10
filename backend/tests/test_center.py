import time
import uuid

import pytest
from sqlalchemy import select

from app.models import Trap

from .conftest import csrf, fresh, login_and_enroll

PROFILE = {"name": "ssh-low", "level": "low", "services": [{"port": 2222, "proto": "banner", "banner": "SSH-2.0-OpenSSH_7.4"}]}


@pytest.fixture
def admin(app):
    c = fresh(app)
    _, data = login_and_enroll(c, "admin")
    c.h = csrf(data)
    return c


def mk_profile(admin, **over):
    r = admin.post("/api/profiles", json={**PROFILE, **over}, headers=admin.h)
    assert r.status_code == 201, r.text
    return r.json()


def mk_trap(admin, profile_id=None, name="t1"):
    r = admin.post("/api/traps", json={"name": name, "profile_id": profile_id}, headers=admin.h)
    assert r.status_code == 201, r.text
    return r.json()


def agent_headers(token):
    return {"Authorization": f"Bearer {token}"}


def event(**over):
    base = {"uid": uuid.uuid4().hex, "ts": time.time(), "type": "connect", "src_ip": "203.0.113.7", "src_port": 4444,
            "dst_port": 2222, "proto": "tcp"}
    return {**base, **over}


# --- профили ---
def test_profile_crud_and_validation(admin):
    p = mk_profile(admin)
    assert p["level"] == "low" and p["traps"] == 0
    assert admin.post("/api/profiles", json=PROFILE, headers=admin.h).status_code == 409  # дубль имени
    bad_low = {**PROFILE, "name": "x", "services": [{"port": 22, "proto": "ssh"}]}
    assert admin.post("/api/profiles", json=bad_low, headers=admin.h).status_code == 422  # Low не умеет ssh
    dup_ports = {**PROFILE, "name": "y", "services": [{"port": 1, "proto": "banner"}, {"port": 1, "proto": "banner"}]}
    assert admin.post("/api/profiles", json=dup_ports, headers=admin.h).status_code == 422
    bad_path = {**PROFILE, "name": "z", "decoys": {"honeytokens": [{"type": "file", "path": "/etc/../shadow"}]}}
    assert admin.post("/api/profiles", json=bad_path, headers=admin.h).status_code == 422
    upd = admin.put(f"/api/profiles/{p['id']}", json={**PROFILE, "description": "новое"}, headers=admin.h)
    assert upd.json()["description"] == "новое"
    assert admin.delete(f"/api/profiles/{p['id']}", headers=admin.h).status_code == 204


def test_profile_in_use_cannot_be_deleted(admin):
    p = mk_profile(admin)
    mk_trap(admin, p["id"])
    assert admin.delete(f"/api/profiles/{p['id']}", headers=admin.h).status_code == 409


def test_api_requires_login_and_csrf(app, admin):
    anon = fresh(app)
    assert anon.get("/api/profiles").status_code == 401
    assert anon.get("/api/events").status_code == 401
    assert admin.post("/api/profiles", json=PROFILE).status_code == 403  # без CSRF-токена


# --- ловушки и канал агента ---
def test_trap_token_shown_once_and_stored_hashed(app, admin):
    t = mk_trap(admin)
    assert t["token"].startswith("hf_") and t["status"] == "never"
    assert "token" not in admin.get("/api/traps").json()[0]
    with app.state.session_factory() as db:
        assert t["token"] not in db.scalar(select(Trap)).token_hash


def test_agent_manifest_heartbeat_and_commands(admin):
    p = mk_profile(admin)
    t = mk_trap(admin, p["id"])
    assert fresh(admin.app).get("/assets/v1/manifest.json").status_code == 404
    assert admin.get("/assets/v1/manifest.json", headers=agent_headers("hf_wrong")).status_code == 404

    admin.post(f"/api/traps/{t['id']}/command", json={"command": "restart"}, headers=admin.h)
    m = admin.get("/assets/v1/manifest.json?v=1.0", headers=agent_headers(t["token"])).json()
    assert m["state"] == "run" and m["cmds"] == ["restart"] and m["config"]["level"] == "low" and m["poll"] == 15
    again = admin.get("/assets/v1/manifest.json", headers=agent_headers(t["token"])).json()
    assert again["cmds"] == [] and again["rev"] == m["rev"]  # команда доставлена один раз, конфиг не менялся
    assert admin.get(f"/api/traps/{t['id']}").json()["status"] == "online"

    admin.patch(f"/api/traps/{t['id']}", json={"enabled": False}, headers=admin.h)
    assert admin.get("/assets/v1/manifest.json", headers=agent_headers(t["token"])).json()["state"] == "stop"


def test_trap_without_profile_is_idle(admin):
    t = mk_trap(admin)
    m = admin.get("/assets/v1/manifest.json", headers=agent_headers(t["token"])).json()
    assert m["state"] == "stop" and m["config"] is None


def test_ingest_idempotent_and_listed(admin):
    t = mk_trap(admin, mk_profile(admin)["id"])
    ev = event(type="auth_attempt", username="root", password="123456")
    h = agent_headers(t["token"])
    assert admin.post("/assets/v1/log", json={"events": [ev]}, headers=h).json() == {"ok": 1, "dup": 0}
    assert admin.post("/assets/v1/log", json={"events": [ev]}, headers=h).json() == {"ok": 0, "dup": 1}  # дослылка буфера
    items = admin.get("/api/events").json()["items"]
    assert len(items) == 1 and items[0]["username"] == "root" and items[0]["trap"] == "t1"


def test_ingest_rejects_garbage_and_unknown_token(admin):
    t = mk_trap(admin)
    h = agent_headers(t["token"])
    assert admin.post("/assets/v1/log", json={"events": [{"uid": "x"}]}, headers=h).status_code == 422
    assert admin.post("/assets/v1/log", json={"events": [event(type="evil")]}, headers=h).status_code == 422
    assert admin.post("/assets/v1/log", json={"events": []}, headers=agent_headers("hf_nope")).status_code == 404


def test_event_filters_and_pagination(admin):
    t = mk_trap(admin)
    h = agent_headers(t["token"])
    evs = [event(src_ip="198.51.100.1", type="connect") for _ in range(3)] + [event(src_ip="198.51.100.2", type="command", command="ls")]
    admin.post("/assets/v1/log", json={"events": evs}, headers=h)
    assert len(admin.get("/api/events?src_ip=198.51.100.1").json()["items"]) == 3
    assert len(admin.get("/api/events?type=command").json()["items"]) == 1
    assert len(admin.get("/api/events?q=ls").json()["items"]) == 1
    page = admin.get("/api/events?limit=2").json()
    assert len(page["items"]) == 2 and page["next_before_id"]
    rest = admin.get(f"/api/events?limit=2&before_id={page['next_before_id']}").json()
    assert len(rest["items"]) == 2 and rest["next_before_id"] is None
    assert admin.get("/api/events?type=bogus").status_code == 422


def test_bruteforce_alert_created_once(admin):
    t = mk_trap(admin)
    evs = [event(type="auth_attempt", username="root", password=str(i)) for i in range(6)]
    admin.post("/assets/v1/log", json={"events": evs}, headers=agent_headers(t["token"]))
    alerts = admin.get("/api/events?type=alert").json()["items"]
    assert len(alerts) == 1 and alerts[0]["data"]["rule"] == "bruteforce"
    admin.post("/assets/v1/log", json={"events": [event(type="auth_attempt")]}, headers=agent_headers(t["token"]))
    assert len(admin.get("/api/events?type=alert").json()["items"]) == 1


def test_stats_and_ioc_exports(admin):
    t = mk_trap(admin)
    evs = [event(type="auth_attempt", username="root", password="toor") for _ in range(2)] + [event(src_ip="2001:db8::1")]
    admin.post("/assets/v1/log", json={"events": evs}, headers=agent_headers(t["token"]))
    s = admin.get("/api/stats").json()
    assert s["total_24h"] == 3 and s["top_usernames"][0] == {"value": "root", "count": 2}
    assert s["traps"]["total"] == 1 and len(s["timeline"]) == 60
    csv_text = admin.get("/api/iocs.csv").text
    assert "203.0.113.7,2" in csv_text
    stix = admin.get("/api/iocs.stix.json").json()
    patterns = {o["pattern"] for o in stix["objects"]}
    assert "[ipv4-addr:value = '203.0.113.7']" in patterns and "[ipv6-addr:value = '2001:db8::1']" in patterns


def test_csv_export_neutralizes_formulas(admin):
    t = mk_trap(admin)
    admin.post("/assets/v1/log", json={"events": [event(type="command", command="=HYPERLINK(\"http://evil\")")]},
               headers=agent_headers(t["token"]))
    body = admin.get("/api/events/export.csv").text
    assert "'=HYPERLINK" in body


def test_deploy_artifact_rotates_token(admin):
    p = mk_profile(admin)
    t = mk_trap(admin, p["id"])
    r = admin.post(f"/api/traps/{t['id']}/deploy", json={"kind": "docker"}, headers=admin.h).json()
    assert "-p 2222:2222" in r["artifact"] and r["token"] in r["artifact"]
    assert admin.get("/assets/v1/manifest.json", headers=agent_headers(t["token"])).status_code == 404  # старый токен мёртв
    assert admin.get("/assets/v1/manifest.json", headers=agent_headers(r["token"])).status_code == 200


def test_offline_after_missed_beacons(app, admin):
    from datetime import timedelta
    from app.models import utcnow
    t = mk_trap(admin, mk_profile(admin)["id"])
    admin.get("/assets/v1/manifest.json", headers=agent_headers(t["token"]))
    with app.state.session_factory() as db:
        tr = db.scalar(select(Trap))
        tr.last_seen = utcnow() - timedelta(minutes=5)
        db.commit()
    assert admin.get("/api/traps").json()[0]["status"] == "offline"


# --- realtime ---
def test_websocket_streams_new_events(admin):
    t = mk_trap(admin)
    with admin.websocket_connect("/api/ws/events") as ws:
        admin.post("/assets/v1/log", json={"events": [event(type="command", command="whoami")]},
                   headers=agent_headers(t["token"]))
        msg = ws.receive_json()
        assert msg["type"] == "command" and msg["command"] == "whoami" and msg["trap"] == "t1"


def test_websocket_requires_session_and_same_origin(app, admin):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with fresh(app).websocket_connect("/api/ws/events"):
            pass
    with pytest.raises(WebSocketDisconnect):
        with admin.websocket_connect("/api/ws/events", headers={"origin": "https://evil.example"}):
            pass
