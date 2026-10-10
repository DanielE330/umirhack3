# HoneyForge — umirhack3

Кейс III Межрегионального хакатона UmirHack (условие: `docs/HoneyForge_МАДРИГАЛ_ТЗ.pdf`). Платформа ловушек-приманок (honeypot): центр управления хранит профили и ловушки, выдаёт агентам конфигурацию и собирает их телеметрию. Агент запускает на хосте-приманке low/medium-сервисы (баннер, SSH, HTTP) и отправляет события в центр по замаскированному каналу. Оркестратор создаёт машины-ловушки в Proxmox в изолированной подсети.

## Архитектура

```
 оператор (браузер)                         атакующий
        │ :4000                                 │ порты сервисов ловушки
        ▼                                       ▼
 ┌──────────────┐  /api/v1/*, /docs   ┌─────────────────┐   агент netsvc (DMZ, vmbr1 10.20.0.0/24)
 │ proxy (Caddy)├────────────────────►│  orchestrator   │   │
 │    :4000     │                     │  :4000 (внутр.) │   │ GET  /assets/v1/manifest.json
 └──────┬───────┘                     └──┬────────┬─────┘   │ POST /assets/v1/log
        │ всё остальное                   │        │ Proxmox API (токен/пароль, пул honeyforge)
        ▼                                 │        ▼
 ┌──────────────┐  X-Internal-Token       │   ┌─────────┐
 │    center    ├────────────────────────►│   │ Proxmox │ ── LXC/KVM ловушки на vmbr1
 │ :4000 (внутр)│◄────────────────────────┼───┴─────────┴──── агенты ходят в центр через HF_PUBLIC_URL
 └──────┬───────┘                         │
        ▼                                 ▼
 ┌──────────────────────────────────────────┐
 │ db: PostgreSQL 17 (базы honeyforge и     │
 │ orchestrator, вторая — infra/initdb)     │
 └──────────────────────────────────────────┘
```

- `proxy` (Caddy, `infra/Caddyfile`): единственный опубликованный порт 4000. `/api/v1/*`, `/docs`, `/openapi.json`, `/redoc` → оркестратор, остальное → центр.
- `center` ↔ PostgreSQL (база `honeyforge`); `orchestrator` ↔ PostgreSQL (база `orchestrator`).
- Центр вызывает оркестратор по `HF_ORCHESTRATOR_URL` с заголовком `X-Internal-Token` (`ORCH_TOKEN`).
- Агенты в DMZ ходят в центр через `HF_PUBLIC_URL` на `/assets/v1/*` с Bearer-токеном ловушки.

## Структура репозитория

```
backend/
  center/         центр управления: FastAPI-приложение (app/), тесты, Dockerfile, отдельный compose центра
  orchestrator/   сервис управления машинами в Proxmox: FastAPI (app/), Dockerfile, dev-compose, скрипты БД
agent/            агент ловушки: пакет netsvc (low/medium-сервисы, буфер, канал в центр) и тесты
frontend/         веб-интерфейс (статические HTML/JS/CSS), его отдаёт центр по / и /static/*
infra/            весь стек: docker-compose.yml, Caddyfile, .env.example, initdb/ (SQL первого запуска)
docs/             условие кейса (pdf), планы, ресёрч, задачи (tasks/)
```

## Сервисы

| Сервис | Назначение | Порт | Технологии |
|---|---|---|---|
| proxy | единый вход, маршрутизация на center/orchestrator | 4000 (наружу) | Caddy 2 |
| center (`backend/center`) | вход с 2FA, профили, ловушки, события, алерты, IoC, канал агентов, прокси к оркестратору | 4000 (внутри сети) | Python 3.12, FastAPI, SQLAlchemy, psycopg, pyotp, cryptography |
| frontend (`frontend/`) | веб-интерфейс оператора (вход, панель) | отдаётся центром | HTML, JS, CSS без сборки |
| orchestrator (`backend/orchestrator`) | создание/управление LXC/KVM-ловушками в Proxmox, статистика, приём телеметрии `/api/v1/analytics/track` | 4000 (внутри сети) | Python 3.11, FastAPI, SQLAlchemy async, asyncpg, proxmoxer, docker SDK |
| db | PostgreSQL центра и оркестратора | 5432 (внутри сети) | PostgreSQL 17 |
| agent (`agent/`) | сервисы-приманки на хосте, отправка событий | порты из профиля | Python 3, asyncio, asyncssh, setproctitle |

## Запуск

### Весь стек (infra)

```sh
cd infra
cp .env.example .env
# заполнить .env, затем:
docker compose up -d --build
docker compose exec center python -m app.cli create-admin admin   # первый администратор (пароль спросит)
```

Интерфейс: `http://<хост>:4000`. Обязательные переменные в `infra/.env`:

| Переменная | Как получить |
|---|---|
| `HF_SECRET_KEY` | `cd backend/center && python -m app.cli gen-key` (печатает готовую строку `HF_SECRET_KEY=...`) или после сборки `docker compose run --rm center python -m app.cli gen-key` |
| `HF_DB_PASSWORD` | любой длинный пароль: `python3 -c "import secrets;print(secrets.token_urlsafe(24))"` |
| `ORCH_TOKEN` | `python3 -c "import secrets;print(secrets.token_urlsafe(32))"` |
| `HF_PUBLIC_URL` | адрес центра, доступный агентам из DMZ (например `http://192.168.1.122:4000`) |
| `PROXMOX_TOKEN_NAME` + `PROXMOX_TOKEN_VALUE` или `PROXMOX_PASSWORD` | API-токен Proxmox (Datacenter → Permissions → API Tokens); без них `/api/machines` вернёт 503, остальное работает |

`HF_COOKIE_SECURE=false` нужен, пока вход идёт по http без TLS.

### Только центр (локально, SQLite)

```sh
cd backend/center
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
export HF_DATABASE_URL=sqlite+pysqlite:////tmp/hf.db HF_COOKIE_SECURE=false HF_PUBLIC_URL=http://127.0.0.1:4100
export $(.venv/bin/python -m app.cli gen-key)
.venv/bin/python -m app.cli create-admin admin
.venv/bin/uvicorn app.main:create_app --factory --port 4100
```

Веб-интерфейс берётся из `frontend/` в корне репозитория (переопределяется `HF_STATIC_DIR`). Без оркестратора раздел машин отвечает 503.
Отдельный compose центра с PostgreSQL: `backend/center/docker-compose.yml` (`.env` рядом, см. `backend/center/.env.example`).

### Агент

На машинах-ловушках из Proxmox агент ставится **автоматически**: оператор создаёт машину и добавляет в неё ловушку в панели, центр выпускает токен и передаёт его оркестратору, оркестратор через хост Proxmox (`infra/proxmox/hf-agent-ctl`) кладёт свежий код агента и включает экземпляр `systemd-journal-helper@<id>` внутри машины. Токен нигде не показывается. От создания машины до агента «на связи» — около 30 секунд.

Ручной запуск (ловушка без машины, например на своём хосте):

```sh
cd agent
pip install -r requirements.txt
HF_CENTER_URL=http://<центр>:4000 HF_TRAP_TOKEN=<токен из «Подключить агента»> python3 -m netsvc
```

### Тесты

```sh
cd backend/center && .venv/bin/python -m pytest -q   # центр
cd agent && .venv/bin/python -m pytest -q            # агент (venv: pip install -r requirements-dev.txt)
```

У оркестратора автотестов нет.

## Переменные окружения

### Центр (`backend/center/app/config.py`, префикс `HF_`, читается и из `.env`)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `HF_DATABASE_URL` | `postgresql+psycopg://honeyforge:honeyforge@db:5432/honeyforge` | строка подключения SQLAlchemy |
| `HF_SECRET_KEY` | пусто | ключ Fernet: шифрует TOTP-секреты, подписывает хэши резервных кодов |
| `HF_COOKIE_SECURE` | `true` | флаг Secure у cookie сессии; `false` только для http |
| `HF_SESSION_IDLE_MINUTES` | `30` | таймаут бездействия сессии |
| `HF_SESSION_ABSOLUTE_HOURS` | `8` | максимальная длительность сессии |
| `HF_PRE_AUTH_MINUTES` | `5` | время на ввод кода 2FA после пароля |
| `HF_MAX_FAILURES_USER` | `5` | неудачных входов на логин за окно до блокировки |
| `HF_MAX_FAILURES_IP` | `20` | неудачных входов с одного IP за окно |
| `HF_LOCKOUT_MINUTES` | `15` | окно и длительность блокировки |
| `HF_MAX_TOTP_ATTEMPTS` | `5` | неверных кодов на одну промежуточную сессию |
| `HF_MIN_PASSWORD_LENGTH` | `12` | минимальная длина пароля пользователя |
| `HF_TOTP_ISSUER` | `HoneyForge` | имя в приложении-аутентификаторе |
| `HF_RECOVERY_CODES_COUNT` | `8` | число резервных кодов 2FA |
| `HF_PUBLIC_URL` | `https://localhost:8443` | адрес центра, который попадает в артефакты развёртывания агента |
| `HF_DEFAULT_BEACON_SECONDS` | `15` | интервал опроса агентом, если профиль не задал свой |
| `HF_ALERT_THRESHOLD` | `5` | попыток входа с одного IP на ловушку за окно → событие `alert` |
| `HF_ALERT_WINDOW_SECONDS` | `60` | окно правила алерта |
| `HF_MAX_BATCH_EVENTS` | `500` | максимум событий в одном пакете агента |
| `HF_MAX_BODY_BYTES` | `1000000` | максимальный размер тела `/assets/v1/log` |
| `HF_TRUSTED_PROXIES` | `127.0.0.1,::1` | адреса, от которых доверяется `X-Forwarded-For` (в infra — `172.31.40.10`, Caddy) |
| `HF_DOCS_ENABLED` | `false` | включает `/docs` и `/openapi.json` центра |
| `HF_STATIC_DIR` | пусто → ищется `frontend/` вверх от кода (в образе `/srv/frontend`) | папка веб-интерфейса |
| `HF_ORCHESTRATOR_URL` | пусто | адрес оркестратора (в infra `http://orchestrator:4000`) |
| `HF_ORCHESTRATOR_TOKEN` | пусто | межсервисный токен (в infra = `ORCH_TOKEN`) |

Только в compose (`infra/docker-compose.yml`): `HF_DB_PASSWORD` — пароль пользователя `honeyforge` в PostgreSQL.

### Оркестратор (`backend/orchestrator/app`)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `ORCH_TOKEN` | пусто → все защищённые эндпоинты отвечают 401 | межсервисный токен, сверяется с `X-Internal-Token` |
| `DATABASE_URL` | `postgresql+asyncpg://admin:password123@localhost:5432/honeyforge` | БД телеметрии/статистики (в infra — база `orchestrator`) |
| `PROXMOX_HOST` | `192.168.1.94` | адрес Proxmox |
| `PROXMOX_PORT` | `8006` | порт API Proxmox |
| `PROXMOX_USER` | `root@pam` | пользователь (для токена — `honeyforge@pve`) |
| `PROXMOX_PASSWORD` | пусто | пароль, если не задан токен |
| `PROXMOX_TOKEN_NAME`, `PROXMOX_TOKEN_VALUE` | пусто | API-токен Proxmox |
| `PROXMOX_NODE` | первый узел кластера | узел Proxmox |
| `PROXMOX_STORAGE` | `hdd` | хранилище дисков |
| `PROXMOX_BRIDGE` | `vmbr1` | мост DMZ для ловушек |
| `PROXMOX_NETWORK` | `10.20.0.0/24` | подсеть, из которой выдаются IP |
| `PROXMOX_GATEWAY` | `10.20.0.1` | шлюз DMZ |
| `PROXMOX_NAMESERVER` | `1.1.1.1` | DNS для машин |
| `PROXMOX_TEMPLATE_LXC` | `9101` | VMID шаблона LXC (Ubuntu 24.04 с предустановленным агентом, см. `infra/proxmox/README.md`) |
| `PROXMOX_TEMPLATE_KVM` | пусто (KVM недоступен) | VMID шаблона KVM |
| `PROXMOX_POOL` | пусто (в infra `honeyforge`) | пул, в который попадают машины |
| `PVE_SSH_HOST` | `PROXMOX_HOST` | хост Proxmox для включения агентов |
| `PVE_SSH_KEY` | `/run/hf-secrets/pve_agent_ed25519` | ключ, которому на хосте разрешена только `hf-agent-ctl` (в infra монтируется из `infra/secrets/`, не в git) |
| `PVE_SSH_KNOWN_HOSTS` | `/run/hf-secrets/known_hosts` | ключ хоста Proxmox; если файл есть — подмена хоста отвергается |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | пусто (уведомления выключены) | бот и чат для алертов |
| `TELEGRAM_PROXY` | пусто | `socks5://…` или `http://…`, если Telegram заблокирован (на стенде — общий VPN-прокси `192.168.1.101:1080`) |

### Агент (`agent/netsvc/__main__.py`)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `HF_CENTER_URL` | обязательна | адрес центра |
| `HF_TRAP_TOKEN` | обязательна | токен ловушки (на машинах Proxmox подставляется автоматически) |
| `HF_STATE_DIR` | `/var/tmp/.cache-netsvc` | буфер событий (SQLite) и состояние |
| `HF_CA_FILE` | пусто (системные CA) | свой корневой сертификат центра |
| `HF_INSECURE_TLS` | — | `1` отключает проверку сертификата (только демо) |
| `HF_PROCESS_NAME` | `systemd-journal-helper` | имя процесса |
| `HF_BIND` | `0.0.0.0` | адрес прослушивания сервисов |
| `HF_PORT_OFFSET` | `0` | сдвиг портов сервисов |
| `HF_LOG` | `WARNING` | уровень логирования |

## API

Защита: **сессия** — cookie после пароля и TOTP; для изменяющих методов (не GET/HEAD/OPTIONS) нужен заголовок `X-CSRF-Token`. **оператор** — роль `admin` или `operator`, **admin** — только `admin`. **Межсервисный токен** — заголовок `X-Internal-Token` = `ORCH_TOKEN`. **Bearer ловушки** — `Authorization: Bearer <токен ловушки>`, при неверном токене ответ 404.

### Центр

| Метод и путь | Назначение | Защита |
|---|---|---|
| `POST /api/auth/login` | пароль → `next: 2fa_setup / 2fa_verify` | нет (блокировки по логину и IP) |
| `POST /api/auth/2fa/setup`, `/2fa/enable`, `/2fa/verify` | настройка и ввод TOTP, резервные коды | промежуточная сессия |
| `GET /api/auth/me`, `POST /api/auth/logout` | текущий пользователь (+ CSRF-токен), выход | сессия + CSRF |
| `GET/POST /api/users`, `PATCH /api/users/{id}`, `POST /api/users/{id}/reset-2fa` | пользователи | admin + CSRF |
| `GET /api/profiles`, `GET /api/profiles/{id}` | профили ловушек | сессия |
| `POST/PUT/DELETE /api/profiles[/{id}]` | CRUD профилей | оператор + CSRF |
| `GET /api/traps`, `GET /api/traps/{id}` | ловушки со статусом online/offline/never | сессия |
| `POST /api/traps`, `PATCH/DELETE /api/traps/{id}` | регистрация, привязка к профилю и машине, вкл/выкл; при `machine_vmid` агент включается/переносится/выключается автоматически (поле `agent`: `installed`/`queued`/`error: …`, токен в ответе только если авто-установки не было) | оператор + CSRF |
| `POST /api/traps/{id}/agent` | переустановить агента в машине ловушки (новый токен, никому не показывается) | оператор + CSRF |
| `POST /api/traps/{id}/command` | команда агенту `restart` / `refresh` | оператор + CSRF |
| `POST /api/traps/{id}/deploy` | новый токен + артефакт `docker` (команда `docker run`) или `script` | оператор + CSRF |
| `GET /api/machines` | машины из оркестратора + состояние агентов | сессия |
| `POST /api/machines`, `POST /api/machines/{vmid}/{action}`, `PUT/DELETE /api/machines/{vmid}` | создание, start/shutdown/reboot/stop, ресурсы, удаление (через оркестратор) | оператор + CSRF |
| `GET /api/events` | события с фильтрами trap_id, type, src_ip, since, until, q | сессия |
| `GET /api/events/export.csv` | выгрузка событий в CSV | сессия |
| `GET /api/stats` | сводка для панели | сессия |
| `GET /api/iocs.csv`, `GET /api/iocs.stix.json` | IoC в CSV и STIX | сессия |
| `WS /api/ws/events` | поток новых событий | cookie полной сессии, Origin = Host |
| `GET /api/health` | проверка живости | нет |
| `GET /assets/v1/manifest.json?v=<версия>` | конфигурация по профилю + команды; служит heartbeat | Bearer ловушки |
| `POST /assets/v1/log` | пакет событий агента | Bearer ловушки |

### Оркестратор (снаружи доступен через proxy по тем же путям)

| Метод и путь | Назначение | Защита |
|---|---|---|
| `GET/POST /api/v1/machines/`, `POST /api/v1/machines/{vmid}/{action}`, `PUT/DELETE /api/v1/machines/{vmid}` | машины Proxmox с тегом `honeyforge` | межсервисный токен |
| `POST /api/v1/machines/{vmid}/agents`, `DELETE /api/v1/machines/{vmid}/agents/{trap_id}` | включить/выключить агента ловушки в машине (пока машина создаётся — в очередь) | межсервисный токен |
| `POST /api/v1/notify/` | отправить алерт центра в Telegram | межсервисный токен |
| `GET /api/v1/events/` | лента событий из своей БД | нет |
| `GET/POST /api/v1/traps/`, `POST /api/v1/traps/proxmox`, `DELETE /api/v1/traps/{container_id}`, `POST /api/v1/traps/{container_id}/stop` | docker-ловушки (нужен Docker-сокет, в infra не смонтирован) и создание в Proxmox | межсервисный токен |
| `GET /api/v1/stats/` | статистика по своей БД | нет |
| `POST /api/v1/analytics/track` | приём телеметрии под видом веб-аналитики | нет |
| `GET /`, `/docs` | статус, Swagger | нет |

## Ловушки и маскировка канала

Уровни (`level` в профиле, `backend/center/app/schemas.py`):

- **Low** — только `banner`: открытый порт с баннером, фиксируются подключение и первые байты (`agent/netsvc/traps/banner.py`).
- **Medium** — `ssh` (asyncssh: перехват логинов/паролей, поддельная оболочка и ФС, файлы-honeytoken; `traps/ssh.py`) и `http` (админка с формой входа, 404 как у Apache, URL-honeytoken; `traps/http.py`).
- **High** — не реализовано в агенте. Оркестратор создаёт LXC/KVM из шаблона в DMZ, но запись сессии (ввод/вывод, файлы) нет.

Маскировка канала агент → центр:

- **MASK-1 TLS**: агент работает по https с проверкой сертификата, свой CA — `HF_CA_FILE` (`agent/netsvc/center.py`). В текущем стенде Caddy слушает http (`auto_https off` в `infra/Caddyfile`), TLS на стенде не включён.
- **MASK-2 неприметный endpoint**: `/assets/v1/manifest.json` и `/assets/v1/log` как у CDN, при неверном токене ответ 404 (`backend/center/app/routers/agent_api.py`); роутер скрыт из OpenAPI.
- **MASK-3 разделение интерфейсов**: ловушки в отдельной подсети `vmbr1` 10.20.0.0/24 (`proxmox_manager.py`). Отдельного mgmt-интерфейса у агента нет.
- **MASK-4 скрытность агента**: процесс `systemd-journal-helper` (setproctitle, задаётся в профиле), пакет `netsvc`, состояние в `/var/tmp/.cache-netsvc`, без строк «honeypot/C2» (`agent/netsvc/__main__.py`).
- **MASK-5**: джиттер интервала опроса (`jittered` в `agent/netsvc/core.py`), случайный паддинг тела, один браузерный User-Agent на запуск (`center.py`).

## Соответствие ТЗ

| Требование | Статус | Где |
|---|---|---|
| FR-C1 CRUD профилей | сделано | `backend/center/app/routers/profiles.py`, `schemas.py` |
| FR-C2 регистрация ловушек, статусы | сделано | `routers/traps.py`, `services.py` (`trap_status`) |
| FR-C3 конфигурация агенту, приём телеметрии | сделано | `routers/agent_api.py` |
| FR-C4 события в PostgreSQL с фильтрами | сделано | `routers/events.py`, `models.py` |
| FR-C5 аутентификация и роли | сделано: пароль + TOTP, резервные коды, сессии, CSRF, роли admin/operator, блокировки | `auth.py`, `routers/auth.py`, `routers/users.py` |
| FR-C6 оркестратор одной кнопкой | сделано: машина в Proxmox (клон шаблона в DMZ) + автоматическое включение агента каждой ловушки | `backend/orchestrator/app/api/v1/machines.py`, `services/agent_installer.py`, `infra/proxmox/hf-agent-ctl`, `center/app/routers/traps.py` |
| FR-C7 алерты и экспорт IoC | сделано: ≥N попыток входа за окно → `alert`, IoC CSV/STIX; `alert` и `honeytoken` уходят в Telegram | `services.py` (`_make_alerts`), `routers/events.py`, `routers/agent_api.py`, `orchestrator/app/api/v1/notify.py` |
| FR-A1 low и medium | сделано | `agent/netsvc/traps/` |
| FR-A2 логирование активности | сделано: connect, auth_attempt, command, http_request, payload, honeytoken, session_end | `agent/netsvc/emitter.py`, `traps/` |
| FR-A3 телеметрия и обновление конфигурации | сделано | `agent/netsvc/core.py` |
| FR-A4 буферизация при потере связи | сделано: SQLite-буфер, досылка с экспоненциальной задержкой | `agent/netsvc/buffer.py`, `core.py` |
| FR-A5 high-interaction | нет (только создание машин в Proxmox) | `backend/orchestrator/app/services/proxmox_manager.py` |
| FR-A6 honeytokens | сделано: файлы в SSH-ФС, URL в HTTP | `traps/ssh.py`, `traps/http.py` |
| MASK-1 TLS | частично (агент поддерживает, на стенде http) | `agent/netsvc/center.py`, `infra/Caddyfile` |
| MASK-2 неприметный endpoint | сделано | `routers/agent_api.py` |
| MASK-3 разделение интерфейсов | сделано: DMZ `vmbr1` с файрволом — из ловушки доступен только канал агента к центру | `infra/proxmox/hf-dmz-fw.sh`, `proxmox_manager.py` |
| MASK-4 скрытность агента | сделано | `agent/netsvc/__main__.py` |
| MASK-5 джиттер и рандомизация | сделано | `agent/netsvc/core.py`, `center.py` |
| MASK-6 анти-фингерпринтинг | частично: реалистичные баннеры SSH/HTTP, 404 как у Apache, правдоподобные ФС/`uname`/`ps` | `traps/ssh.py`, `traps/http.py` |
| MASK-7 mTLS, pinning, ротация | частично: свой CA (`HF_CA_FILE`), перевыпуск токена при deploy; mTLS нет | `center.py`, `routers/traps.py` |

## Безопасность и сеть

- Ловушки создаются только на мосту `vmbr1`, подсеть `10.20.0.0/24`, шлюз `10.20.0.1` (DMZ), с тегом `honeyforge`; оркестратор управляет только машинами с этим тегом (`NotOurMachine`).
- Машины кладутся в пул Proxmox `honeyforge`; оркестратор входит API-токеном `honeyforge@pve` с правами только на этот пул, шаблон, хранилище `hdd` и мост `vmbr1` — prod-машины ему не видны. Роли и ACL — в `infra/proxmox/README.md`.
- Агентов включает отдельный ключ, которому на хосте Proxmox разрешена ровно одна команда (`hf-agent-ctl`) и только с адреса сервера центра; команда работает только с запущенными машинами с тегом `honeyforge`.
- Изоляция DMZ проверена изнутри ловушки: закрыты домашняя сеть, Proxmox, prod, Tailscale; открыт только канал агента к центру и интернет через NAT.
- Наружу публикуется только proxy :4000; center, orchestrator, db — во внутренней сети compose `172.31.40.0/24`. Центр доверяет `X-Forwarded-For` только от `172.31.40.10` (Caddy).
- Управляющие эндпоинты оркестратора закрыты `ORCH_TOKEN`; без токена — 401 на всё.
- Секреты (`HF_SECRET_KEY`, `HF_DB_PASSWORD`, `ORCH_TOKEN`, `PROXMOX_*`) только в `.env`, файл в `.gitignore`. Токены ловушек хранятся в БД в виде хэша. TOTP-секреты зашифрованы Fernet.
- Ответы центра: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, CSP для страниц, `Cache-Control: no-store` для API.

## Известные ограничения

- TLS на стенде выключен (`auto_https off`, `HF_COOKIE_SECURE=false`).
- Оркестратор подключается к Proxmox без проверки сертификата (`verify_ssl=False`).
- `/api/v1/stats/` и `/api/v1/analytics/track` оркестратора открыты без авторизации и проброшены наружу через proxy; телеметрию агенты шлют в центр, не сюда.
- High-interaction и запись сессий не реализованы; mTLS не реализован.
- Нет Dockerfile агента, хотя ручной артефакт `docker` ссылается на образ `honeyforge-agent:latest` (на машинах Proxmox агент ставится без Docker).
- Поддельная консоль SSH выполняет только по одной простой команде в строке: цепочки (`;`, `&&`, `|`) не разбираются.
- Автоматическое включение агентов работает только для LXC-машин из шаблона с предустановленным агентом (`9101`).
- Docker-ловушки оркестратора (`/api/v1/traps/`) требуют Docker-сокет; он смонтирован только в `backend/orchestrator/docker-compose.yml`, в infra — нет.
- Автотестов оркестратора нет.
