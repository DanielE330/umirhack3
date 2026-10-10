"""Криптографические примитивы входа: пароли, токены, TOTP, резервные коды."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

import pyotp
import segno
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet

_hasher = PasswordHasher()  # argon2id, параметры по умолчанию argon2-cffi (RFC 9106, low-memory)
# Хэш заведомо неизвестного пароля: проверяем его для несуществующих логинов, чтобы время ответа не выдавало,
# есть ли такой пользователь.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))

TOTP_STEP = 30
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


# --- пароли ---
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Всегда выполняет argon2-проверку (по заглушке, если пользователя нет)."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# --- токены сессий ---
def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 бит


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --- шифрование секретов в БД ---
class Vault:
    def __init__(self, secret_key: str):
        if not secret_key:
            raise RuntimeError("HF_SECRET_KEY не задан (python -m app.cli gen-key)")
        self._fernet = Fernet(secret_key.encode())
        # Отдельный ключ для HMAC резервных кодов, производный от основного.
        self._mac_key = hashlib.sha256(b"honeyforge-recovery-mac:" + secret_key.encode()).digest()

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def recovery_hash(self, code: str) -> str:
        return hmac.new(self._mac_key, normalize_recovery(code).encode(), hashlib.sha256).hexdigest()


def generate_key() -> str:
    return Fernet.generate_key().decode()


# --- TOTP ---
def new_totp_secret() -> str:
    return pyotp.random_base32(32)  # 160 бит


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret, interval=TOTP_STEP).provisioning_uri(name=username, issuer_name=issuer)


def qr_data_uri(uri: str) -> str:
    return segno.make(uri, error="m").svg_data_uri(scale=6, border=2)


def verify_totp(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Проверяет 6-значный код с допуском ±1 шаг. Возвращает номер шага при успехе, иначе None.
    Код, чей шаг не больше `last_step`, отвергается: один код нельзя использовать дважды."""
    code = (code or "").strip()
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret, interval=TOTP_STEP)
    current = int((now if now is not None else time.time()) // TOTP_STEP)
    matched: int | None = None
    for step in (current - 1, current, current + 1):  # без раннего выхода: время не зависит от совпадения
        if hmac.compare_digest(totp.at(step * TOTP_STEP), code) and step > last_step:
            matched = step
    return matched


# --- резервные коды ---
def normalize_recovery(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def new_recovery_code() -> str:
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))  # ~60 бит
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def looks_like_recovery(code: str) -> bool:
    return len(normalize_recovery(code)) == 12

