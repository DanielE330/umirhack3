"""Внутренние API-эндпоинты (межсервисные, защищены X-Internal-Token)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth, security
from ..config import Settings
from ..db import get_db
from ..models import User, utcnow

router = APIRouter(prefix="/api/internal", tags=["internal"], include_in_schema=False)


def require_internal_token(request: Request, x_internal_token: str | None = Header(None)) -> None:
    s: Settings = auth.settings_of(request)
    valid_tokens = {t for t in [s.orchestrator_token, s.secret_key] if t}
    if not x_internal_token or x_internal_token not in valid_tokens:
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
    user = db.scalar(select(User).where(User.username == body.username, User.is_active == True))
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
