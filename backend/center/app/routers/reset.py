"""Сброс забытого пароля через привязанный Telegram (вместо почты).

Код из 6 цифр приходит от бота в привязанный чат; в базе — только HMAC кода. Ответ на запрос кода
одинаковый для любых логинов, отправка идёт в фоне: по ответу и времени не понять, есть ли такой
пользователь и привязан ли у него Telegram. Вход после сброса по-прежнему требует 2FA.
"""
from __future__ import annotations

import hmac
import secrets
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import auth, security
from ..db import get_db
from ..models import PasswordReset, User, utcnow
from .users import check_password_policy

router = APIRouter(prefix="/api/auth/reset", tags=["auth"])
SENT = "Если к учётной записи привязан Telegram, код отправлен туда"
BAD_CODE = "Код неверен или устарел"


class ResetRequestIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class ResetConfirmIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=1, max_length=16)
    new_password: str = Field(min_length=1, max_length=256)


def _send(request: Request, chat_id: str, text: str, username: str, ip: str) -> None:
    """Сообщение оператору через бота оркестратора; неудача только пишется в аудит."""
    try:
        request.app.state.orchestrator.request("POST", "/direct", {"chat_id": chat_id, "text": text},
                                               timeout=20, base="/api/v1/notify")
    except HTTPException as e:
        with request.app.state.session_factory() as db:
            auth.audit(db, username, "password.reset_send_fail", str(e.detail), ip)
            db.commit()


def _can_reset(user: User | None) -> bool:
    # без включённой 2FA сброс через Telegram дал бы вход по одному Telegram (например, после сброса 2FA админом)
    return bool(user and user.is_active and user.telegram_chat_id and user.totp_enabled)


@router.post("/request")
def request_code(body: ResetRequestIn, request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    s = auth.settings_of(request)
    ip = auth.client_ip(request)
    username = body.username.strip().lower()
    if auth.is_locked(db, s, username, ip):
        raise HTTPException(429, auth.LOCKED_ERROR)

    user = db.scalar(select(User).where(User.username == username))
    if not _can_reset(user):
        auth.audit(db, username, "password.reset_ignored", ip=ip)
        db.commit()
        return {"ok": True, "detail": SENT}

    now = utcnow()
    recent = db.scalar(select(func.count()).select_from(PasswordReset).where(
        PasswordReset.user_id == user.id, PasswordReset.created_at > now - timedelta(hours=1)))
    if recent >= s.reset_max_per_hour:
        auth.audit(db, username, "password.reset_throttled", ip=ip)
        db.commit()
        return {"ok": True, "detail": SENT}

    # прежние коды перестают действовать: работает только последний
    db.execute(update(PasswordReset).where(PasswordReset.user_id == user.id, PasswordReset.used_at.is_(None))
               .values(used_at=now))
    code = f"{secrets.randbelow(10**6):06d}"
    db.add(PasswordReset(user_id=user.id, code_hash=auth.vault_of(request).recovery_hash(code),
                         expires_at=now + timedelta(minutes=s.reset_code_minutes)))
    auth.audit(db, username, "password.reset_request", ip=ip)
    db.commit()
    text = (f"HoneyForge: код сброса пароля для «{user.username}»: {code}\n"
            f"Действует {s.reset_code_minutes} минут. Если сброс запрашивали не вы — не вводите код "
            f"и сообщите администратору (запрос с адреса {ip}).")
    background.add_task(_send, request, user.telegram_chat_id, text, username, ip)
    return {"ok": True, "detail": SENT}


@router.post("/confirm")
def confirm(body: ResetConfirmIn, request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    s = auth.settings_of(request)
    ip = auth.client_ip(request)
    username = body.username.strip().lower()
    if auth.is_locked(db, s, username, ip):
        raise HTTPException(429, auth.LOCKED_ERROR)

    user = db.scalar(select(User).where(User.username == username))
    reset = None
    if _can_reset(user):
        reset = db.scalar(select(PasswordReset).where(
            PasswordReset.user_id == user.id, PasswordReset.used_at.is_(None),
            PasswordReset.expires_at > utcnow()).order_by(PasswordReset.id.desc()))
    digest = auth.vault_of(request).recovery_hash(body.code.strip())
    if reset is None or reset.attempts >= s.reset_max_attempts or not hmac.compare_digest(reset.code_hash, digest):
        if reset is not None:
            reset.attempts += 1
        auth.record_failure(db, username, ip)
        auth.audit(db, username, "password.reset_fail", ip=ip)
        db.commit()
        raise HTTPException(400, BAD_CODE)

    check_password_policy(body.new_password, user.username, s.min_password_length)  # код не тратится
    user.password_hash = security.hash_password(body.new_password)
    reset.used_at = utcnow()
    auth.revoke_user_sessions(db, user.id)
    auth.clear_user_failures(db, username)
    auth.audit(db, username, "password.reset", ip=ip)
    db.commit()
    background.add_task(_send, request, user.telegram_chat_id,
                        f"HoneyForge: пароль учётной записи «{user.username}» изменён (адрес {ip}). "
                        f"Все сеансы завершены. Если это были не вы — срочно сообщите администратору.",
                        username, ip)
    return {"ok": True}
