import base64
import hashlib

from app import geo
from app.models import Artifact, IpInfo

from .test_center import admin, agent_headers, event, mk_trap  # noqa: F401 — фикстура admin


def test_artifact_hash_and_download(admin, app):
    t = mk_trap(admin)
    body = b"#!/bin/sh\necho pwned\n"
    sha = hashlib.sha256(body).hexdigest()
    ev = event(type="payload", command="scp -t /tmp", data={"kind": "upload", "filename": "x.sh", "size": len(body),
                                                            "sha256": sha, "content_b64": base64.b64encode(body).decode()})
    r = admin.post("/assets/v1/log", json={"events": [ev, event(type="payload", data={"sha256": sha, "kind": "upload"})]},
                   headers=agent_headers(t["token"]))
    assert r.status_code == 200
    items = admin.get("/api/artifacts").json()["items"]
    assert len(items) == 1 and items[0]["sha256"] == sha and items[0]["seen_count"] == 2 and items[0]["has_content"]
    assert items[0]["trap"] == "t1" and items[0]["name"] == "x.sh"
    dl = admin.get(f"/api/artifacts/{sha}/download")
    assert dl.content == body and dl.headers["content-disposition"].startswith("attachment")
    # содержимое не раздувает ленту событий
    stored = admin.get("/api/events?type=payload").json()["items"][0]["data"]
    assert "content_b64" not in stored and stored["artifact"] == sha
    assert admin.get("/api/artifacts/" + "0" * 64 + "/download").status_code == 404
    with app.state.session_factory() as db:
        assert db.get(Artifact, sha).size == len(body)


def test_audit_log_admin_only(admin):
    mk_trap(admin)
    items = admin.get("/api/audit").json()["items"]
    assert any(i["action"].startswith("trap") for i in items) and items[0]["ts"].endswith("Z")
    assert admin.get("/api/audit?action=trap").json()["items"]
    assert admin.get("/api/audit?actor=nobody").json()["items"] == []


def test_geo_enrichment_and_stats(admin, app, monkeypatch):
    t = mk_trap(admin)
    monkeypatch.setattr(geo, "_fetch", lambda url, ips: {ip: {"query": ip, "country": "Germany", "countryCode": "DE",
                                                              "city": "Berlin", "as": "AS24940 Hetzner Online GmbH",
                                                              "asname": "HETZNER-AS"} for ip in ips})
    admin.post("/assets/v1/log", json={"events": [event(src_ip="8.8.8.8"), event(src_ip="10.1.2.3")]},
               headers=agent_headers(t["token"]))
    geo.enrich(app.state.session_factory, "http://geo.test", {"8.8.8.8", "10.1.2.3"})
    with app.state.session_factory() as db:
        assert db.get(IpInfo, "8.8.8.8").asn == "AS24940" and db.get(IpInfo, "10.1.2.3").country_code == "--"
    evs = admin.get("/api/events").json()["items"]
    by_ip = {e["src_ip"]: e["geo"] for e in evs}
    assert by_ip["8.8.8.8"]["country_code"] == "DE" and by_ip["8.8.8.8"]["org"] == "HETZNER-AS"
    s = admin.get("/api/stats").json()
    assert s["top_countries"] == [{"value": "Germany", "count": 1}] and s["top_asn"][0]["value"] == "AS24940"
    assert "DE,AS24940" in admin.get("/api/events/export.csv").text


def test_session_summary_filters_and_hourly_stats(admin):
    t = mk_trap(admin)
    now = __import__("time").time()
    evs = [event(session_id="s1", type="connect", ts=now - 30), event(session_id="s1", type="command", command="id", ts=now - 10),
           event(session_id="s1", type="auth_attempt", username="root", password="x", ts=now - 20),
           event(session_id="s2", type="connect")]
    admin.post("/assets/v1/log", json={"events": evs}, headers=agent_headers(t["token"]))
    s = admin.get("/api/sessions/s1").json()
    assert s["summary"]["events"] == 3 and s["summary"]["commands"] == 1 and s["summary"]["auth_attempts"] == 1
    assert 19 <= s["summary"]["duration_seconds"] <= 21 and s["is_human"] is None
    assert admin.get("/api/sessions/none").status_code == 404
    assert len(admin.get("/api/events?session_id=s1").json()["items"]) == 3
    assert admin.get("/api/events?min_score=50").json()["items"] == []
    st = admin.get("/api/stats").json()
    assert len(st["by_hour"]) == 24 and sum(h["n"] for h in st["by_hour"]) == 4
