"""Вход: пароль → (настройка TOTP при первом входе) → код 2FA → полная сессия."""
from __future__ import annotations

from datetime import timedelta
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import auth, security
from ..db import get_db
from ..models import AuthSession, RecoveryCode, User, utcnow
from .users import check_password_policy

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class CodeIn(BaseModel):
    code: str = Field(min_length=1, max_length=32)


def _upgrade(db: Session, request: Request, response: Response, pre: AuthSession, user: User) -> AuthSession:
    """Промежуточная сессия заменяется новой полной (новый токен — защита от фиксации сессии)."""
    s = auth.settings_of(request)
    db.delete(pre)
    token, sess = auth.create_session(db, request, user, "full")
    auth.set_session_cookie(response, s, "session", token, s.session_absolute_hours * 3600)
    auth.clear_cookie(response, s, "pre")
    return sess


def _user_info(user: User, csrf: str) -> dict:
    return {
        "username": user.username,
        "role": user.role,
        "csrf": csrf,
        "telegram_linked": bool(user.telegram_chat_id),
        "telegram_username": user.telegram_username,
    }


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    s = auth.settings_of(request)
    ip = auth.client_ip(request)
    username = body.username.strip().lower()

    if auth.is_locked(db, s, username, ip):
        auth.audit(db, username, "login.locked", ip=ip)
        db.commit()
        raise HTTPException(429, auth.LOCKED_ERROR)

    user = db.scalar(select(User).where(User.username == username))
    ok = security.verify_password(body.password, user.password_hash if user else None)
    if not (ok and user and user.is_active):
        auth.record_failure(db, username, ip)
        auth.audit(db, username, "login.fail", "пароль", ip)
        db.commit()
        raise HTTPException(401, auth.GENERIC_LOGIN_ERROR)

    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(body.password)
    token, _ = auth.create_session(db, request, user, "pre")
    auth.set_session_cookie(response, s, "pre", token, s.pre_auth_minutes * 60)
    auth.audit(db, username, "login.password_ok", ip=ip)
    db.commit()
    return {"next": "2fa" if user.totp_enabled else "2fa_setup"}


@router.post("/2fa/setup")
def totp_setup(request: Request, pre: AuthSession = Depends(auth.pre_session), db: Session = Depends(get_db)):
    user = pre.user
    if user.totp_enabled:
        raise HTTPException(409, "2FA уже настроена")
    secret = security.new_totp_secret()
    user.totp_secret_enc = auth.vault_of(request).encrypt(secret)  # новый секрет при каждом вызове, пока не подтверждён
    db.commit()
    uri = security.provisioning_uri(secret, user.username, auth.settings_of(request).totp_issuer)
    return {"secret": secret, "otpauth_uri": uri, "qr": security.qr_data_uri(uri)}


def _check_code(request: Request, db: Session, pre: AuthSession, user: User, code: str) -> bool:
    """Проверяет TOTP или резервный код. Неудачи считаются и в лимите, и в счётчике промежуточной сессии."""
    s = auth.settings_of(request)
    ip = auth.client_ip(request)
    vault = auth.vault_of(request)
    ok = False

    if auth.is_locked(db, s, user.username, ip):
        raise HTTPException(429, auth.LOCKED_ERROR)

    if user.totp_secret_enc and security.looks_like_recovery(code) and user.totp_enabled:
        digest = vault.recovery_hash(code)
        rc = db.scalar(select(RecoveryCode).where(RecoveryCode.user_id == user.id,
                                                  RecoveryCode.code_hash == digest,
                                                  RecoveryCode.used_at.is_(None)))
        if rc:
            rc.used_at = utcnow()
            auth.audit(db, user.username, "2fa.recovery_used", ip=ip)
            ok = True
    elif user.totp_secret_enc:
        step = security.verify_totp(vault.decrypt(user.totp_secret_enc), code, user.last_totp_step)
        if step is not None:
            user.last_totp_step = step
            ok = True

    if not ok:
        pre.totp_attempts += 1
        auth.record_failure(db, user.username, ip)
        auth.audit(db, user.username, "login.fail", "2fa", ip)
        if pre.totp_attempts >= s.max_totp_attempts:
            db.delete(pre)  # перебор кода: придётся заново вводить пароль
        db.commit()
        raise HTTPException(401, auth.GENERIC_LOGIN_ERROR)
    return True


@router.post("/2fa/enable")
def totp_enable(body: CodeIn, request: Request, response: Response,
                pre: AuthSession = Depends(auth.pre_session), db: Session = Depends(get_db)):
    """Подтверждение первой настройки TOTP: включает 2FA, выдаёт резервные коды (один раз) и полную сессию."""
    user = pre.user
    if user.totp_enabled:
        raise HTTPException(409, "2FA уже настроена")
    if not user.totp_secret_enc:
        raise HTTPException(409, "Сначала запросите настройку 2FA")
    if security.looks_like_recovery(body.code):
        raise HTTPException(401, auth.GENERIC_LOGIN_ERROR)
    # TOTP-ветка _check_code: пока 2FA не включена, резервные коды не принимаются
    _check_code(request, db, pre, user, body.code)

    s = auth.settings_of(request)
    vault = auth.vault_of(request)
    codes = [security.new_recovery_code() for _ in range(s.recovery_codes_count)]
    for rc in list(user.recovery_codes):
        db.delete(rc)
    for c in codes:
        db.add(RecoveryCode(user_id=user.id, code_hash=vault.recovery_hash(c)))
    user.totp_enabled = True
    auth.clear_user_failures(db, user.username)
    sess = _upgrade(db, request, response, pre, user)
    auth.audit(db, user.username, "2fa.enabled", ip=auth.client_ip(request))
    auth.audit(db, user.username, "login.ok", ip=auth.client_ip(request))
    db.commit()
    return {**_user_info(user, sess.csrf), "recovery_codes": codes}


@router.post("/2fa/verify")
def totp_verify(body: CodeIn, request: Request, response: Response,
                pre: AuthSession = Depends(auth.pre_session), db: Session = Depends(get_db)):
    user = pre.user
    if not user.totp_enabled:
        raise HTTPException(409, "Сначала настройте 2FA")
    _check_code(request, db, pre, user, body.code)
    auth.clear_user_failures(db, user.username)
    sess = _upgrade(db, request, response, pre, user)
    auth.audit(db, user.username, "login.ok", ip=auth.client_ip(request))
    db.commit()
    return _user_info(user, sess.csrf)


@router.get("/me")
def me(sess: AuthSession = Depends(auth.current_session)):
    return _user_info(sess.user, sess.csrf)


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


@router.post("/password")
def change_password(body: PasswordIn, request: Request, sess: AuthSession = Depends(auth.current_session),
                    db: Session = Depends(get_db)):
    """Смена своего пароля: нужен текущий пароль; остальные сессии пользователя закрываются, эта остаётся."""
    s = auth.settings_of(request)
    ip = auth.client_ip(request)
    user = sess.user
    if auth.is_locked(db, s, user.username, ip):
        raise HTTPException(429, auth.LOCKED_ERROR)
    if not security.verify_password(body.current_password, user.password_hash):
        auth.record_failure(db, user.username, ip)
        auth.audit(db, user.username, "password.fail", ip=ip)
        db.commit()
        raise HTTPException(403, "Неверный текущий пароль")  # не 401: сессия жива, панель не должна выкидывать на вход
    check_password_policy(body.new_password, user.username, s.min_password_length)
    if body.new_password == body.current_password:
        raise HTTPException(422, "Новый пароль совпадает с текущим")
    user.password_hash = security.hash_password(body.new_password)
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id, AuthSession.id != sess.id))
    auth.audit(db, user.username, "password.change", ip=ip)
    db.commit()
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, response: Response, sess: AuthSession = Depends(auth.current_session),
           db: Session = Depends(get_db)):
    s = auth.settings_of(request)
    auth.audit(db, sess.user.username, "logout", ip=auth.client_ip(request))
    db.delete(sess)
    db.commit()
    auth.clear_cookie(response, s, "session")
    return {"ok": True}


@router.post("/me/telegram/code")
def generate_telegram_link_code(request: Request, sess: AuthSession = Depends(auth.current_session),
                                db: Session = Depends(get_db)):
    """Генерирует одноразовый 6-значный код (HF-XXXXXX) для привязки Telegram-аккаунта."""
    user = sess.user
    code = f"HF-{secrets.token_hex(3).upper()}"
    user.telegram_link_code = code
    user.telegram_link_expires = utcnow() + timedelta(minutes=15)
    db.commit()

    s = auth.settings_of(request)
    bot = s.telegram_bot_username.lstrip("@")
    return {
        "code": code,
        "bot_username": bot,
        "link": f"https://t.me/{bot}?start={code}" if bot else None,
        "expires_in": 900,
    }


@router.delete("/me/telegram")
def unlink_telegram(request: Request, sess: AuthSession = Depends(auth.current_session),
                    db: Session = Depends(get_db)):
    """Отвязывает Telegram-аккаунт от профиля оператора/админа."""
    user = sess.user
    user.telegram_chat_id = None
    user.telegram_username = None
    user.telegram_link_code = None
    user.telegram_link_expires = None
    auth.audit(db, user.username, "telegram.unlink", ip=auth.client_ip(request))
    db.commit()
    return {"ok": True}

