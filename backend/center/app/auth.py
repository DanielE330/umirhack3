"""Логика входа: сессии, лимит попыток, аудит, зависимости FastAPI."""
from __future__ import annotations

import hmac
import ipaddress
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import security
from .config import Settings
from .db import get_db
from .models import AuditLog, AuthSession, LoginFailure, User, utcnow

GENERIC_LOGIN_ERROR = "Неверный логин, пароль или код"
LOCKED_ERROR = "Слишком много попыток. Повторите позже"


def cookie_name(settings: Settings, kind: str) -> str:
    """`__Host-` требует Secure, поэтому на http (локальная разработка) префикса нет."""
    return f"{'__Host-' if settings.cookie_secure else ''}hf_{kind}"


def settings_of(request: Request) -> Settings:
    return request.app.state.settings


def vault_of(request: Request) -> security.Vault:
    return request.app.state.vault


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    trusted = settings_of(request).trusted_proxy_set
    if peer not in trusted:
        return peer
    forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    for hop in reversed(forwarded):  # справа налево: первый, кто не наш прокси
        if hop not in trusted:
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                break
    return peer


def audit(db: Session, actor: str, action: str, detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(actor=actor[:64], action=action, detail=detail[:500], ip=ip[:64]))


# --- лимит попыток ---
def _failures(db: Session, key: str, settings: Settings) -> int:
    since = utcnow() - timedelta(minutes=settings.lockout_minutes)
    return db.scalar(select(func.count()).select_from(LoginFailure)
                     .where(LoginFailure.key == key, LoginFailure.ts >= since)) or 0


def is_locked(db: Session, settings: Settings, username: str, ip: str) -> bool:
    return (_failures(db, f"user:{username}", settings) >= settings.max_failures_user
            or _failures(db, f"ip:{ip}", settings) >= settings.max_failures_ip)


def record_failure(db: Session, username: str, ip: str) -> None:
    db.add(LoginFailure(key=f"user:{username}"))
    db.add(LoginFailure(key=f"ip:{ip}"))


def clear_user_failures(db: Session, username: str) -> None:
    db.execute(delete(LoginFailure).where(LoginFailure.key == f"user:{username}"))


# --- сессии ---
def create_session(db: Session, request: Request, user: User, stage: str) -> tuple[str, AuthSession]:
    s = settings_of(request)
    token = security.new_token()
    now = utcnow()
    life = timedelta(minutes=s.pre_auth_minutes) if stage == "pre" else timedelta(hours=s.session_absolute_hours)
    sess = AuthSession(token_hash=security.token_hash(token), user_id=user.id, stage=stage,
                       csrf=security.new_token(), created_at=now, last_seen=now, expires_at=now + life,
                       ip=client_ip(request), user_agent=request.headers.get("user-agent", "")[:255])
    db.add(sess)
    db.flush()
    return token, sess


def set_session_cookie(response: Response, settings: Settings, kind: str, token: str, max_age: int) -> None:
    response.set_cookie(cookie_name(settings, kind), token, max_age=max_age, httponly=True,
                        secure=settings.cookie_secure, samesite="strict", path="/")


def clear_cookie(response: Response, settings: Settings, kind: str) -> None:
    response.delete_cookie(cookie_name(settings, kind), path="/", secure=settings.cookie_secure,
                           httponly=True, samesite="strict")


def revoke_user_sessions(db: Session, user_id: int) -> None:
    db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))


def load_session_token(db: Session, s: Settings, token: str | None, stage: str) -> AuthSession | None:
    if not token:
        return None
    sess = db.scalar(select(AuthSession).where(AuthSession.token_hash == security.token_hash(token)))
    if sess is None or sess.stage != stage:
        return None
    now = utcnow()
    idle_limit = sess.last_seen + timedelta(minutes=s.session_idle_minutes)
    if now >= sess.expires_at or (stage == "full" and now >= idle_limit) or not sess.user.is_active:
        db.delete(sess)
        db.commit()
        return None
    if stage == "full":
        sess.last_seen = now
        db.commit()
    return sess


def _load_session(db: Session, request: Request, kind: str, stage: str) -> AuthSession | None:
    s = settings_of(request)
    return load_session_token(db, s, request.cookies.get(cookie_name(s, kind)), stage)


# --- зависимости ---
def pre_session(request: Request, db: Session = Depends(get_db)) -> AuthSession:
    sess = _load_session(db, request, "pre", "pre")
    if sess is None:
        raise HTTPException(401, "Сначала введите логин и пароль")
    return sess


def current_session(request: Request, db: Session = Depends(get_db)) -> AuthSession:
    sess = _load_session(db, request, "session", "full")
    if sess is None:
        raise HTTPException(401, "Требуется вход")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent, sess.csrf):
            raise HTTPException(403, "Неверный CSRF-токен")
    return sess


def current_user(sess: AuthSession = Depends(current_session)) -> User:
    return sess.user


def require_role(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Недостаточно прав")
        return user
    return dep
