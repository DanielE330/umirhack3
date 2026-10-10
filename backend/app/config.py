from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HF_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://honeyforge:honeyforge@db:5432/honeyforge"
    # Ключ Fernet (base64, 32 байта): шифрует TOTP-секреты и подписывает хэши резервных кодов.
    # Сгенерировать: python -m app.cli gen-key
    secret_key: str = ""

    cookie_secure: bool = True          # False только для локальной разработки по http
    session_idle_minutes: int = 30
    session_absolute_hours: int = 8
    pre_auth_minutes: int = 5           # время на ввод кода после пароля

    max_failures_user: int = 5          # неудачных попыток на логин за окно
    max_failures_ip: int = 20           # неудачных попыток с одного IP за окно
    lockout_minutes: int = 15
    max_totp_attempts: int = 5          # неверных кодов на одну промежуточную сессию

    min_password_length: int = 12
    totp_issuer: str = "HoneyForge"
    recovery_codes_count: int = 8

    public_url: str = "https://localhost:8443"   # адрес центра для артефактов развёртывания
    default_beacon_seconds: int = 15
    alert_threshold: int = 5                  # попыток входа с одного IP на ловушку за окно -> алерт
    alert_window_seconds: int = 60
    max_batch_events: int = 500
    max_body_bytes: int = 1_000_000

    trusted_proxies: str = "127.0.0.1,::1"   # от них верим X-Forwarded-For (Nginx)
    docs_enabled: bool = False               # /docs и /openapi.json

    # Оркестратор Proxmox (отдельный сервис): адрес во внутренней сети и межсервисный токен
    orchestrator_url: str = ""
    orchestrator_token: str = ""

    @property
    def trusted_proxy_set(self) -> set[str]:
        return {p.strip() for p in self.trusted_proxies.split(",") if p.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
