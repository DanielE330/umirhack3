"""ML-часть: TF-IDF (символьные + словные n-граммы) → линейный классификатор / RandomForest.

Модель предсказывает КЛАСС команды; threat_score считается как ожидаемая тяжесть по вероятностям классов:
    score = Σ P(class) · severity(class)
Так балл получается плавным (неуверенная модель не выдаёт «ровно 95»), а класс остаётся объяснимым.

Целостность файла модели: joblib/pickle небезопасно загружать из недоверенного места, поэтому рядом лежит
<model>.sha256, и load() отказывается грузить файл, если хэш не совпал. Это защита от подмены файла, а не от
злоумышленника, который уже умеет писать и в .sha256 — модель должна лежать в read-only слое образа.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from .rules import CATEGORIES
from .textnorm import normalize

MODEL_VERSION = "honeymind-3"   # 3: сегменты цепочек, новые правила и деобфускация, обучение на 624 реальных командах


def build_pipeline(kind: str = "logreg", seed: int = 42) -> Pipeline:
    feats = FeatureUnion([
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, min_df=2, max_features=60000)),
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, min_df=1,
                                 token_pattern=r"[a-z0-9_./\-:+<>]+", max_features=40000)),
    ])
    if kind == "logreg":
        clf = LogisticRegression(C=20.0, max_iter=3000, class_weight="balanced", random_state=seed)
    elif kind == "rf":
        clf = RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample", n_jobs=-1,
                                     random_state=seed, min_samples_leaf=1)
    else:
        raise ValueError(f"unknown model kind: {kind}")
    return Pipeline([("feats", feats), ("clf", clf)])


def ml_text(cmd: str) -> str:
    return normalize(cmd).ml


@dataclass
class Prediction:
    probs: dict[str, float]
    category: str
    confidence: float
    expected_score: float


class ThreatModel:
    def __init__(self, pipeline: Pipeline, kind: str = "logreg", meta: dict | None = None):
        self.pipeline = pipeline
        self.kind = kind
        self.meta = meta or {}
        self.classes: list[str] = [str(c) for c in pipeline.named_steps["clf"].classes_]
        self._sev = np.array([CATEGORIES[c].severity for c in self.classes], dtype=float)

    @classmethod
    def train(cls, texts: list[str], labels: list[str], kind: str = "logreg", meta: dict | None = None) -> "ThreatModel":
        pipe = build_pipeline(kind)
        pipe.fit([ml_text(t) for t in texts], labels)
        return cls(pipe, kind, {**(meta or {}), "n_train": len(texts), "version": MODEL_VERSION})

    def predict_many(self, commands: list[str]) -> list[Prediction]:
        if not commands:
            return []
        P = self.pipeline.predict_proba([ml_text(c) for c in commands])
        out = []
        for row in P:
            k = int(np.argmax(row))
            out.append(Prediction(probs={c: float(p) for c, p in zip(self.classes, row)},
                                  category=self.classes[k], confidence=float(row[k]),
                                  expected_score=float(row @ self._sev)))
        return out

    def predict(self, command: str) -> Prediction:
        return self.predict_many([command])[0]

    # ───── сохранение / загрузка с проверкой хэша ─────
    def save(self, path: str | Path) -> str:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": self.pipeline, "kind": self.kind, "meta": self.meta}, path, compress=3)
        digest = _sha256(path)
        Path(str(path) + ".sha256").write_text(digest + "\n")
        return digest

    @classmethod
    def load(cls, path: str | Path, require_hash: bool = True) -> "ThreatModel":
        path = Path(path)
        sidecar = Path(str(path) + ".sha256")
        if require_hash:
            if not sidecar.exists():
                raise RuntimeError(f"нет {sidecar.name}: отказываюсь загружать pickle без контрольной суммы")
            if not hmac.compare_digest(_sha256(path), sidecar.read_text().strip()):
                raise RuntimeError("контрольная сумма модели не совпала — файл изменён")
        blob = joblib.load(path)
        return cls(blob["pipeline"], blob.get("kind", "logreg"), blob.get("meta"))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
