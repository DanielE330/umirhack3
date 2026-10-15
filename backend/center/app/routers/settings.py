"""Управление системными настройками платформы (пороги тревоги HoneyMind, спам-скор)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import User
from ..scoring import get_threat_alert_threshold, set_threat_alert_threshold

router = APIRouter(prefix="/api/settings", tags=["settings"])


class ThreatThresholdIn(BaseModel):
    threshold: int = Field(ge=0, le=100, description="Порог threat_score (0-100), выше которого отправляются алерты")


@router.get("/threat-threshold")
def get_threat_threshold(db: Session = Depends(get_db)):
    """Получить текущий порог опасности HoneyMind (спам-скор) для отправки алертов."""
    val = get_threat_alert_threshold(db)
    return {
        "threshold": val,
        "min": 0,
        "max": 100,
        "default": 60,
        "presets": [
            {"label": "Низкий (максимум алертов)", "value": 40},
            {"label": "Стандартный (баланс)", "value": 60},
            {"label": "Высокий (серьёзные угрозы)", "value": 75},
            {"label": "Критический (только эксплойты)", "value": 90},
        ],
    }


@router.put("/threat-threshold")
def update_threat_threshold(
    body: ThreatThresholdIn,
    request: Request,
    user: User = Depends(auth.require_perm("settings.manage")),
    db: Session = Depends(get_db),
):
    """Обновить порог опасности HoneyMind (спам-скор). Требуется право settings.manage."""
    old_val = get_threat_alert_threshold(db)
    new_val = set_threat_alert_threshold(body.threshold, db, user.username)
    auth.audit(db, user.username, "threat_threshold.update", f"Порог тревоги изменён с {old_val} на {new_val}", auth.client_ip(request))
    db.commit()
    return {
        "status": "ok",
        "threshold": new_val,
        "previous": old_val,
    }
