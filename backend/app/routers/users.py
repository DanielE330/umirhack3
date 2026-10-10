"""Управление операторами (только admin). Саморегистрации нет."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth, security
from ..db import get_db
from ..models import User

router = APIRouter(prefix="/api/users", tags=["users"])

_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def check_password_policy(password: str, username: str, min_length: int) -> None:
    if len(password) < min_length:
        raise HTTPException(422, f"Пароль короче {min_length} символов")
    if len(password) > 128:
        raise HTTPException(422, "Пароль длиннее 128 символов")
    if username in password.lower():
        raise HTTPException(422, "Пароль не должен содержать логин")


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: str = Field(default="operator", pattern="^(admin|operator)$")


class UserPatch(BaseModel):
    is_active: bool | None = None
    role: str | None = Field(default=None, pattern="^(admin|operator)$")


def _view(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active,
            "totp_enabled": u.totp_enabled, "created_at": u.created_at.isoformat()}


@router.get("")
def list_users(_: User = Depends(auth.require_role("admin")), db: Session = Depends(get_db)):
    return [_view(u) for u in db.scalars(select(User).order_by(User.id))]


@router.post("", status_code=201)
def create_user(body: UserIn, request: Request, admin: User = Depends(auth.require_role("admin")),
                db: Session = Depends(get_db)):
    username = body.username.strip().lower()
    if not _USERNAME.match(username):
        raise HTTPException(422, "Логин: 3–64 символа, a-z, 0-9, точка, дефис, подчёркивание")
    check_password_policy(body.password, username, auth.settings_of(request).min_password_length)
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(409, "Логин занят")
    user = User(username=username, password_hash=security.hash_password(body.password), role=body.role)
    db.add(user)
    auth.audit(db, admin.username, "user.create", f"{username} ({body.role})", auth.client_ip(request))
    db.commit()
    return _view(user)


def _target(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    return user


@router.patch("/{user_id}")
def patch_user(user_id: int, body: UserPatch, request: Request,
               admin: User = Depends(auth.require_role("admin")), db: Session = Depends(get_db)):
    user = _target(db, user_id)
    if user.id == admin.id:
        raise HTTPException(409, "Нельзя менять собственную роль и блокировать себя")
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.is_active is False or body.role is not None:
        auth.revoke_user_sessions(db, user.id)
    auth.audit(db, admin.username, "user.update", f"{user.username}: {body.model_dump(exclude_none=True)}",
               auth.client_ip(request))
    db.commit()
    return _view(user)


@router.post("/{user_id}/reset-2fa")
def reset_2fa(user_id: int, request: Request, admin: User = Depends(auth.require_role("admin")),
              db: Session = Depends(get_db)):
    """Потеря телефона и резервных кодов: сброс 2FA, при следующем входе пользователь настроит её заново."""
    user = _target(db, user_id)
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.last_totp_step = 0
    for rc in list(user.recovery_codes):
        db.delete(rc)
    auth.revoke_user_sessions(db, user.id)
    auth.audit(db, admin.username, "user.reset_2fa", user.username, auth.client_ip(request))
    db.commit()
    return _view(user)
