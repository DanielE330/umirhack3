# Схема базы данных центра

PostgreSQL, база `honeyforge` (SQLite — для локального запуска). Таблицы создаются при старте центра (`app/db.py: init_db`),
модели — `backend/center/app/models.py`. Оркестратор ведёт собственную базу `orchestrator` (телеметрия и статистика).

```mermaid
erDiagram
    users ||--o{ recovery_codes : "резервные коды 2FA"
    users ||--o{ auth_sessions : "сессии"
    users ||--o{ password_resets : "сброс пароля через Telegram"
    profiles ||--o{ traps : "конфигурация ловушки"
    traps ||--o{ events : "события"
    traps ||--o{ session_assessments : "оценка сессий"
    traps ||--o{ artifacts : "где файл виден впервые"
    events }o..o{ ip_info : "src_ip, геолокация и ASN"
    events }o..o{ artifacts : "data.sha256"
    audit_log }o..o{ users : "actor, по логину"

    users {
        int id PK
        string username UK
        string password_hash
        string role "admin | operator"
        bool is_active
        text totp_secret_enc "Fernet"
        bool totp_enabled
        string telegram_chat_id UK
        string telegram_username
    }
    recovery_codes { int id PK  int user_id FK  string code_hash  datetime used_at }
    auth_sessions { int id PK  string token_hash UK  int user_id FK  string stage "pre | full"  string csrf  datetime expires_at }
    login_failures { int id PK  string key "user:логин | ip:адрес"  datetime ts }
    password_resets { int id PK  int user_id FK  string code_hash  datetime expires_at  int attempts }
    audit_log { int id PK  datetime ts  string actor  string action  text detail  string ip }
    profiles {
        int id PK
        string name UK
        string level "low | medium"
        json services "порт, протокол, баннер"
        json decoys "учётки, honeytokens, hostname"
        json logging
        json masking "интервал, джиттер, имя процесса"
    }
    traps {
        int id PK
        string name UK
        int profile_id FK
        string token_hash UK "токен агента, только хэш"
        bool enabled
        string host
        string agent_version
        datetime last_seen "heartbeat"
        int machine_vmid "машина в Proxmox"
    }
    events {
        int id PK
        string uid UK "идемпотентность дослылки"
        int trap_id FK
        datetime ts
        string type "connect, auth_attempt, command, http_request, payload, honeytoken, session_end, alert"
        string src_ip
        int dst_port
        string session_id
        string username
        string password
        text command
        json data
        int threat_score "HoneyMind"
        string category
    }
    session_assessments { string session_id PK  int trap_id FK  bool is_human  float human_probability }
    ip_info { string ip PK  string country_code  string country  string city  string asn  string org  datetime fetched_at }
    artifacts {
        string sha256 PK
        int size
        string name
        string kind "upload | write | download"
        int first_trap_id FK
        string src_ip
        int seen_count
        blob content "до 64 КБ"
    }
    roles { int id PK  string name UK  string title  json permissions "флаги доступа"  bool is_system }
    users }o--|| roles : "role (слаг)"
    trap_ideas { int id PK  string author  string title  string status }
```

## Поток данных

1. Оператор создаёт `profiles` и `traps` (токен агента показывается один раз, в БД лежит только SHA-256).
2. Агент раз в `beacon_interval` (с джиттером) читает `/assets/v1/manifest.json` — это heartbeat (`traps.last_seen`) и выдача конфигурации по профилю.
3. События агента (`/assets/v1/log`, шифруются AES-256-GCM) попадают в `events`. Дубликаты отсекаются по `uid`.
4. В той же транзакции: правило алерта (≥N попыток входа за окно → событие `alert`), файлы (`data.sha256`) → `artifacts`.
5. Фоном: геолокация/ASN → `ip_info`, оценка HoneyMind → поля `threat_score`/`category`, итог сессии → `session_assessments`.
6. Центр публикует событие в WebSocket `/api/ws/events` (лента панели), алерты и honeytoken уходят в Telegram.
