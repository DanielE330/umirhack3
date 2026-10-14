"""Внутренние API-эндпоинты (межсервисные, защищены X-Internal-Token)."""
from __future__ import annotations

import hmac
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import auth, security
from ..config import Settings
from ..db import get_db
from ..models import Event, SessionAssessment, Trap, User, utcnow

router = APIRouter(prefix="/api/internal", tags=["internal"], include_in_schema=False)


def require_internal_token(request: Request, x_internal_token: str | None = Header(None)) -> None:
    """Только межсервисный токен (ORCH_TOKEN). HF_SECRET_KEY сюда не годится: это ключ шифрования TOTP."""
    s: Settings = auth.settings_of(request)
    if not s.orchestrator_token or not hmac.compare_digest(x_internal_token or "", s.orchestrator_token):
        raise HTTPException(401, "Неверный внутренний токен")


class TelegramLoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    chat_id: str = Field(min_length=1, max_length=64)
    tg_username: str | None = None


class TelegramBindIn(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    chat_id: str = Field(min_length=1, max_length=64)
    username: str | None = None


class TelegramCheckIn(BaseModel):
    chat_id: str = Field(min_length=1, max_length=64)


class TelegramUnbindIn(BaseModel):
    chat_id: str = Field(min_length=1, max_length=64)


@router.post("/telegram/login", dependencies=[Depends(require_internal_token)])
def login_telegram(body: TelegramLoginIn, db: Session = Depends(get_db)):
    """Прямая авторизация оператора через Telegram по логину и паролю."""
    clean_username = body.username.strip().lower()
    user = db.scalar(select(User).where(User.username == clean_username, User.is_active == True))
    if not user or not security.verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Неверный логин или пароль")

    # Если chat_id был привязан к другому, отвязываем старого
    other = db.scalar(select(User).where(User.telegram_chat_id == body.chat_id, User.id != user.id))
    if other:
        other.telegram_chat_id = None
        other.telegram_username = None

    user.telegram_chat_id = body.chat_id
    user.telegram_username = body.tg_username.lstrip("@") if body.tg_username else None
    user.telegram_link_code = None
    user.telegram_link_expires = None
    auth.audit(db, user.username, "telegram.direct_login", f"chat_id={body.chat_id}")
    db.commit()

    return {"ok": True, "username": user.username, "role": user.role}


@router.post("/telegram/bind", dependencies=[Depends(require_internal_token)])
def bind_telegram(body: TelegramBindIn, db: Session = Depends(get_db)):
    """Привязка Telegram-аккаунта по одноразовому коду."""
    clean_code = body.code.strip().upper()
    user = db.scalar(select(User).where(User.telegram_link_code == clean_code))
    if not user:
        raise HTTPException(404, "Код привязки не найден или неверен")

    if user.telegram_link_expires and user.telegram_link_expires < utcnow():
        raise HTTPException(400, "Срок действия кода привязки истёк")

    if not user.is_active:
        raise HTTPException(403, "Учётная запись оператора отключена")

    # Если этот chat_id уже был привязан к другому пользователю, отвязываем старого
    other = db.scalar(select(User).where(User.telegram_chat_id == body.chat_id, User.id != user.id))
    if other:
        other.telegram_chat_id = None
        other.telegram_username = None

    user.telegram_chat_id = body.chat_id
    user.telegram_username = body.username.lstrip("@") if body.username else None
    user.telegram_link_code = None
    user.telegram_link_expires = None
    auth.audit(db, user.username, "telegram.bind", f"chat_id={body.chat_id}, tg_username={body.username}")
    db.commit()

    return {"ok": True, "username": user.username, "role": user.role}


@router.post("/telegram/check-auth", dependencies=[Depends(require_internal_token)])
def check_telegram_auth(body: TelegramCheckIn, db: Session = Depends(get_db)):
    """Проверка прав и роли пользователя Telegram."""
    user = db.scalar(select(User).where(User.telegram_chat_id == body.chat_id, User.is_active == True))
    if not user:
        return {"authenticated": False}

    return {
        "authenticated": True,
        "username": user.username,
        "role": user.role,
        "telegram_username": user.telegram_username,
    }


@router.post("/telegram/unbind", dependencies=[Depends(require_internal_token)])
def unbind_telegram_by_chat_id(body: TelegramUnbindIn, db: Session = Depends(get_db)):
    """Отвязка Telegram по chat_id."""
    user = db.scalar(select(User).where(User.telegram_chat_id == body.chat_id))
    if user:
        user.telegram_chat_id = None
        user.telegram_username = None
        auth.audit(db, user.username, "telegram.unbind_by_chat", f"chat_id={body.chat_id}")
        db.commit()
    return {"ok": True}


@router.get("/telegram/subscribers", dependencies=[Depends(require_internal_token)])
def get_telegram_subscribers(db: Session = Depends(get_db)):
    """Список chat_id всех активных операторов для рассылки алертов."""
    users = db.scalars(select(User).where(User.is_active == True, User.telegram_chat_id.is_not(None))).all()
    return {
        "subscribers": [
            {"chat_id": u.telegram_chat_id, "username": u.username, "role": u.role}
            for u in users
            if u.telegram_chat_id
        ]
    }


@router.get("/stats", dependencies=[Depends(require_internal_token)])
def get_internal_stats(db: Session = Depends(get_db)):
    """Сводная статистика за 24ч для Telegram-бота."""
    now = utcnow()
    day = now - timedelta(hours=24)
    total_events = db.scalar(select(func.count(Event.id)).where(Event.ts >= day)) or 0
    alerts_count = db.scalar(select(func.count(Event.id)).where(Event.ts >= day, Event.type.in_(["alert", "honeytoken"]))) or 0
    auth_attempts = db.scalar(select(func.count(Event.id)).where(Event.ts >= day, Event.type == "auth_attempt")) or 0
    high_threats = db.scalar(select(func.count(Event.id)).where(Event.ts >= day, Event.threat_score >= 70)) or 0
    traps_count = db.scalar(select(func.count(Trap.id))) or 0

    top_ips_stmt = (
        select(Event.src_ip, func.count().label("n"))
        .where(Event.ts >= day, Event.src_ip != "", Event.type != "alert")
        .group_by(Event.src_ip)
        .order_by(func.count().desc())
        .limit(5)
    )
    top_ips = [{"ip": ip, "count": n} for ip, n in db.execute(top_ips_stmt).all()]

    top_pwd_stmt = (
        select(Event.password, func.count().label("n"))
        .where(Event.ts >= day, Event.password != "")
        .group_by(Event.password)
        .order_by(func.count().desc())
        .limit(3)
    )
    top_pwds = [row[0] for row in db.execute(top_pwd_stmt).all()]

    top_usr_stmt = (
        select(Event.username, func.count().label("n"))
        .where(Event.ts >= day, Event.username != "")
        .group_by(Event.username)
        .order_by(func.count().desc())
        .limit(3)
    )
    top_usrs = [row[0] for row in db.execute(top_usr_stmt).all()]

    return {
        "total_24h": total_events,
        "alerts_24h": alerts_count,
        "auth_attempts_24h": auth_attempts,
        "high_threats_24h": high_threats,
        "traps_total": traps_count,
        "top_ips": top_ips,
        "top_passwords": top_pwds,
        "top_usernames": top_usrs,
    }


@router.get("/events/latest", dependencies=[Depends(require_internal_token)])
def get_internal_latest_events(limit: int = 5, db: Session = Depends(get_db)):
    """Последние атаки для отображения в Telegram."""
    stmt = (
        select(Event)
        .order_by(Event.id.desc())
        .limit(min(15, limit))
    )
    events = db.scalars(stmt).all()
    return [
        {
            "id": e.id,
            "type": e.type,
            "src_ip": e.src_ip,
            "ts": e.ts.strftime("%H:%M:%S UTC") if e.ts else "",
            "detail": e.command or e.username or (e.data.get("rule") if e.data else "") or "—",
            "threat_score": e.threat_score,
            "category": e.category,
        }
        for e in events
    ]


@router.get("/ip/{ip}", dependencies=[Depends(require_internal_token)])
def get_internal_ip_intel(ip: str, db: Session = Depends(get_db)):
    """Досье на IP-адрес для SOC-аналитика."""
    clean_ip = ip.strip()
    total_events = db.scalar(select(func.count(Event.id)).where(Event.src_ip == clean_ip)) or 0
    if total_events == 0:
        return {"found": False, "ip": clean_ip}

    max_threat = db.scalar(select(func.max(Event.threat_score)).where(Event.src_ip == clean_ip))
    first_seen = db.scalar(select(func.min(Event.ts)).where(Event.src_ip == clean_ip))
    last_seen = db.scalar(select(func.max(Event.ts)).where(Event.src_ip == clean_ip))

    cmd_stmt = (
        select(Event.command, func.count().label("n"))
        .where(Event.src_ip == clean_ip, Event.command != "")
        .group_by(Event.command)
        .order_by(func.count().desc())
        .limit(3)
    )
    cmds = [row[0] for row in db.execute(cmd_stmt).all()]

    user_stmt = (
        select(Event.username, func.count().label("n"))
        .where(Event.src_ip == clean_ip, Event.username != "")
        .group_by(Event.username)
        .order_by(func.count().desc())
        .limit(3)
    )
    users = [row[0] for row in db.execute(user_stmt).all()]

    last_event = db.scalar(
        select(Event).where(Event.src_ip == clean_ip).order_by(Event.id.desc()).limit(1)
    )

    return {
        "found": True,
        "ip": clean_ip,
        "total_events": total_events,
        "max_threat": max_threat,
        "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if first_seen else None,
        "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if last_seen else None,
        "commands": cmds,
        "usernames": users,
        "last_type": last_event.type if last_event else None,
        "last_detail": (last_event.command or last_event.username or "") if last_event else "",
    }


@router.get("/session/{session_id}/artifacts", dependencies=[Depends(require_internal_token)])
def get_internal_session_artifacts(session_id: str, request: Request, db: Session = Depends(get_db)):
    """Выгрузка сгенерированных правил (Sigma, YARA) и отчётов по сессии для Telegram-бота."""
    from ..scoring import _event_payload
    a = db.get(SessionAssessment, session_id)
    res_data = (a.result or {}) if a and a.result and isinstance(a.result, dict) else {}
    rules = res_data.get("detection_rules")
    reports = res_data.get("dual_loop_report")
    intent = res_data.get("intent_prediction")

    honeymind = getattr(request.app.state, "honeymind", None)
    if (not rules or not reports) and honeymind:
        rows = db.scalars(select(Event).where(Event.session_id == session_id).order_by(Event.ts)).all()
        events = [_event_payload({
            "type": r.type, "command": r.command, "username": r.username, "password": r.password,
            "session_id": r.session_id, "ts": r.ts.isoformat() + "Z" if r.ts else "", "data": r.data,
        }) for r in rows]
        if events:
            if not rules:
                rules = honeymind.export_detection_rules(events, session_id=session_id) or {}
            if not reports:
                reports = honeymind.generate_report(events=events) or {}
            if a and rules and reports:
                if not a.result or not isinstance(a.result, dict):
                    a.result = {}
                a.result["detection_rules"] = rules
                a.result["dual_loop_report"] = reports
                db.commit()

    return {
        "session_id": session_id,
        "is_human": a.is_human if a else None,
        "human_probability": a.human_probability if a else None,
        "human_reason": a.human_reason if a else None,
        "threat_score": a.threat_score if a else None,
        "sigma_yaml": (rules or {}).get("sigma_yaml"),
        "yara_rule": (rules or {}).get("yara_rule"),
        "executive_brief": (reports or {}).get("executive_markdown") or (reports or {}).get("executive_brief_markdown"),
        "technical_dfir": (reports or {}).get("technical_markdown") or (reports or {}).get("technical_dfir_markdown"),
        "intent_prediction": intent,
    }

