"""Тесты сигнатурного и эвристического анализа HASSH и адаптивного тарпита."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from honeymind.analyzer import Analyzer
from honeymind.api import create_app
from honeymind.hassh import KNOWN_HASSH_DB, classify_hassh


def test_classify_known_botnet_mirai():
    res = classify_hassh("817027581fb1a4a44b82d470d0c35478")
    assert res.matched is True
    assert res.is_human is False
    assert res.category == "botnet"
    assert "Mirai" in res.client_name
    assert res.tarpit_mode == "strict"
    assert res.tarpit_delay_sec >= 1.5


def test_classify_known_bruteforcer_hydra():
    res = classify_hassh("061d491f618a80bb8b3684a0d9230554")
    assert res.matched is True
    assert res.is_human is False
    assert res.category == "bruteforce"
    assert "Hydra" in res.client_name
    assert res.tarpit_mode == "strict"
    assert res.tarpit_delay_sec >= 2.0


def test_classify_known_human_terminals():
    # OpenSSH
    openssh_res = classify_hassh("553dae556488d0fb06e0018f94ff8890")
    assert openssh_res.matched is True
    assert openssh_res.is_human is True
    assert openssh_res.tarpit_mode == "adaptive"
    assert openssh_res.tarpit_delay_sec <= 0.3

    # PuTTY
    putty_res = classify_hassh("c16428cf1b37c02b703d98bfb8f9e612")
    assert putty_res.matched is True
    assert putty_res.is_human is True
    assert putty_res.category == "human_terminal"


def test_heuristic_unknown_hassh_with_bot_banner():
    unknown_hash = "deadbeefcafebabe0123456789abcdef"
    res = classify_hassh(unknown_hash, client_str="SSH-2.0-Go")
    assert res.matched is False
    assert res.is_human is False
    assert res.category == "botnet"
    assert res.tarpit_mode == "strict"
    assert res.tarpit_delay_sec >= 2.0


def test_heuristic_unknown_hassh_with_weak_ciphers():
    unknown_hash = "11223344556677889900aabbccddeeff"
    raw = "diffie-hellman-group1-sha1;3des-cbc;hmac-sha1;none"
    res = classify_hassh(unknown_hash, hassh_raw=raw)
    assert res.matched is False
    assert res.is_human is False
    assert res.category == "legacy_scanner"
    assert res.tarpit_mode == "strict"


def test_heuristic_generic_unknown_client():
    unknown_hash = "99887766554433221100ffeeddccbbaa"
    raw = "curve25519-sha256;chacha20-poly1305@openssh.com;hmac-sha2-512-etm@openssh.com;none"
    res = classify_hassh(unknown_hash, hassh_raw=raw, client_str="SSH-2.0-CustomClient")
    assert res.matched is False
    assert res.is_human is None
    assert res.category == "unknown"
    assert res.tarpit_mode == "adaptive"


def test_analyzer_session_bot_attribution_by_hassh():
    analyzer = Analyzer()
    events = [
        {
            "type": "connect",
            "src_ip": "194.26.29.112",
            "data": {
                "hassh": "817027581fb1a4a44b82d470d0c35478",
                "client": "SSH-2.0-CustomMasquerade",
            },
        },
        {
            "type": "command",
            "command": "uname -a",
            "src_ip": "194.26.29.112",
        },
    ]

    res = analyzer.analyze_session(events)
    assert res["is_human"] is False
    assert res["human_method"] == "hassh"
    assert res["hassh"] == "817027581fb1a4a44b82d470d0c35478"
    assert res["hassh_profile"] is not None
    assert res["hassh_profile"]["matched"] is True
    assert "Mirai" in res["hassh_profile"]["client_name"]
    assert "[HASSH:" in res["summary"]


def test_analyzer_single_connect_verdict_with_hassh():
    analyzer = Analyzer()
    ev = {
        "type": "connect",
        "data": {
            "hassh": "061d491f618a80bb8b3684a0d9230554",
        },
    }
    v = analyzer.analyze_event(ev)
    assert v.source == "hassh"
    assert v.threat_score >= 35
    assert "hassh_bruteforce" in v.matched_rules
    assert "Hydra" in v.summary


def test_api_predict_hassh():
    app = create_app()
    client = TestClient(app)

    resp = client.post(
        "/predict/hassh",
        json={"hassh": "061d491f618a80bb8b3684a0d9230554"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] is True
    assert data["is_human"] is False
    assert data["category"] == "bruteforce"
    assert data["tarpit_mode"] == "strict"
    assert "Hydra" in data["client_name"]


def test_center_honeymind_client_classify_hassh():
    from backend.center.app.config import Settings
    from backend.center.app.honeymind import HoneyMind

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/predict/hassh"
        return httpx.Response(
            200,
            json={
                "hassh": "817027581fb1a4a44b82d470d0c35478",
                "matched": True,
                "client_name": "Go-SSH / Mirai IoT Botnet",
                "is_human": False,
                "category": "botnet",
                "tarpit_mode": "strict",
                "tarpit_delay_sec": 2.0,
            },
        )

    transport = httpx.MockTransport(handler)
    settings = Settings(honeymind_url="http://test-honeymind:8000")
    hm = HoneyMind(settings, transport=transport)

    res = hm.classify_hassh("817027581fb1a4a44b82d470d0c35478")
    assert res is not None
    assert res["matched"] is True
    assert res["category"] == "botnet"
    assert res["tarpit_delay_sec"] == 2.0
