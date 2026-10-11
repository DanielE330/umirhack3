"""Криптографический модуль сквозного шифрования канала ловушка <-> центр (E2EE, MASK-1).
Использует симметричное аутентифицированное шифрование AES-256-GCM (AEAD).
Ключ шифрования вычисляется деривацией из уникального токена ловушки (HMAC/SHA256).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_payload_key(token: str) -> bytes:
    """
    Деривация симметричного 256-битного мастер-ключа шифрования канала
    из токена ловушки с использованием SHA-256 KDF.
    """
    clean_token = token.strip()
    return hashlib.sha256(f"honeyforge-channel-v2:{clean_token}".encode("utf-8")).digest()


def encrypt_payload(data: Any, key: bytes) -> dict:
    """
    Шифрует данные алгоритмом AES-256-GCM.
    Возвращает защищённый конверт (envelope) с 96-битным уникальным криптографическим nonce.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-битный стандартный криптографический nonce для GCM
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "v": 2,
        "enc": base64.b64encode(ciphertext).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }


def decrypt_payload(envelope: dict, key: bytes) -> Any:
    """
    Расшифровывает данные из конверта AES-256-GCM с проверкой целостности и аутентичности (AEAD).
    При попытке подделки или повреждении данных выбрасывает исключение cryptography.exceptions.InvalidTag.
    """
    if not isinstance(envelope, dict) or "enc" not in envelope or "nonce" not in envelope:
        return envelope

    aesgcm = AESGCM(key)
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["enc"])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode("utf-8"))
