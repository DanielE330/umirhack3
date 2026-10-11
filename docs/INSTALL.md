# Установка HoneyForge

Полная инструкция: от чистого Proxmox до первой пойманной атаки, плюс обновление, удаление и типовые проблемы.
Краткий обзор архитектуры и API — в корневом `README.md`, детали хоста Proxmox — в `infra/proxmox/README.md`.

## 1. Что из чего состоит

| Где | Что | Как ставится |
|---|---|---|
| Хост Proxmox VE 8/9 | DMZ-мост `vmbr1` с файрволом, пул/роли/API-токен оркестратора, шаблон ловушек (LXC Ubuntu 24.04 с агентом), `hf-agent-ctl` | `infra/proxmox/hf-proxmox.sh install` |
| Сервер центра (любой Linux с Docker; на стенде — CT 102 в Proxmox) | proxy (Caddy :4000), center, orchestrator, PostgreSQL | `docker compose` из `infra/` |
| Машины-ловушки | агент `netsvc` под видом `systemd-journal-helper` | автоматически: оркестратор клонирует шаблон, центр включает агента |

```
 оператор ──:4000──► proxy ─► center ◄─► db
                          └─► orchestrator ──API-токен──► Proxmox API (пул honeyforge)
                                           └──SSH-ключ──► hf-agent-ctl на хосте ─► pct exec в ловушку
 атакующий ──► ловушка в DMZ 10.20.0.0/24 ──(только центр:4000)──► center /assets/v1/*
```

Из DMZ закрыты все частные сети, Tailscale и сам хост Proxmox; открыт только канал агента к центру и интернет через NAT.

## 2. Требования

**Хост Proxmox**
- Proxmox VE 8 или 9, доступ root по SSH.
- Хранилище для дисков ловушек (по умолчанию `hdd`, если есть, иначе `local-lvm`); скрипт сам разрешит на нём типы `rootdir,images`.
- Хранилище для образов (`local`, тип `vztmpl`) — туда скачается `ubuntu-24.04-standard`, если его нет.
- Выход в интернет с хоста (скачать образ и пакеты `python3-asyncssh`, `python3-setproctitle` в шаблон).
- Свободные: имя моста `vmbr1`, подсеть `10.20.0.0/24`, VMID `9101` и VMID от `1100` (всё меняется параметрами).

**Сервер центра**
- Docker + Docker Compose v2, 2 ГБ ОЗУ, порт 4000.
- Должен быть доступен по сети:
  - с хоста Proxmox — по этому адресу ходят агенты из DMZ (`--center-ip`);
  - и сам должен видеть хост Proxmox: API `:8006` и SSH `:22`.
- Если центр — LXC в Proxmox, у него нужен `nesting=1` (Docker внутри CT).

**Рабочая машина** — git, rsync, ssh.

## 3. Подготовка хоста Proxmox

С рабочей машины, из корня репозитория:

```sh
rsync -aR --exclude __pycache__ infra/proxmox agent/netsvc root@<proxmox>:/root/honeyforge/
ssh -t root@<proxmox> /root/honeyforge/infra/proxmox/hf-proxmox.sh install --center-ip <IP центра>
```

Скрипт идёт по шагам и печатает, что сделал (≈3–5 минут, дольше всего — сборка шаблона):

1. **DMZ.** Мост `vmbr1` (`10.20.0.1/24`, без физического порта) в `/etc/network/interfaces` между маркерами `# >>> honeyforge dmz >>>`. Бэкап — `interfaces.bak-hf-*`.
   - Файрвол `/usr/local/sbin/hf-dmz-fw.sh` вызывается из `post-up`/`pre-down`, его параметры — в `/etc/default/hf-dmz`.
   - Включается `net.ipv4.ip_forward`.
2. **Хранилище.** Добавляет типы `rootdir,images`, если их не было. Что добавлено, запоминается для отката.
3. **Доступ оркестратора.**
   - Пул `honeyforge`, роли `HoneyForgeTraps` и `HoneyForgeTemplate`, пользователь `honeyforge@pve` с API-токеном `orchestrator`.
   - ACL выдаются только на пул, хранилище, мост и аудит ноды — prod-машины токену не видны.
4. **Агент на хосте.** `/usr/local/sbin/hf-agent-ctl` и архив кода агента `/usr/local/share/hf-agent/netsvc.tgz`.
5. **Шаблон `9101`.** Собирается из `ubuntu-24.04-standard`:
   - ставятся Python-пакеты, агент в `/usr/lib/systemd-journal-helper`, юнит `systemd-journal-helper@.service`;
   - настоящий sshd выключается, root блокируется;
   - стираются логи, кэши apt, `machine-id`, ключи хоста;
   - сеть переводится на dhcp, `pct template`.
6. **SSH-ключ оркестратора.** Генерируется ed25519 и пишется в `authorized_keys` хоста в виде
   `restrict,from="<центр>",command="/usr/local/sbin/hf-agent-ctl" … hf-orchestrator`:
   ключ работает только с адреса центра и только для этой команды.
   Рядом создаётся `known_hosts` с ключами хоста.

Параметры (полный список — `hf-proxmox.sh --help`):

| Параметр | По умолчанию | Когда менять |
|---|---|---|
| `--center-ip` | — (обязателен в первый раз) | адрес центра, видимый из DMZ |
| `--center-port` | `4000` | если proxy центра на другом порту |
| `--orch-from` | = `--center-ip` | центр ходит на хост с другого адреса (другая сеть, Tailscale) |
| `--orch-pubkey FILE` | генерируется | уже есть ключ оркестратора |
| `--pve-ip` | адрес хоста на `--wan` | центр видит хост по другому адресу |
| `--node` | `hostname` | имя ноды отличается |
| `--storage` | `hdd` / `local-lvm` | другое хранилище для ловушек |
| `--bridge`, `--network`, `--gateway` | `vmbr1`, `10.20.0.0/24`, `10.20.0.1` | заняты |
| `--wan` | интерфейс маршрута по умолчанию | NAT наружу через другой мост |
| `--template-id`, `--template-disk` | `9101`, `8` ГБ | VMID занят / нужен больший диск |
| `--pool` | `honeyforge` | — |
| `--ostemplate VOLID`, `--ostemplate-storage` | ищется/скачивается в `local` | свой образ |
| `--build-ip` | `.250` в DMZ | адрес занят |
| `--rebuild-template` | — | пересобрать шаблон (например, после смены пакетов) |
| `--rotate-token` | — | перевыпустить API-токен |

Параметры запоминаются в `/etc/honeyforge/proxmox.conf`; повторный `install` без аргументов берёт их оттуда и пропускает готовое.

Проверка: `hf-proxmox.sh status` — список компонентов с ✓/✗ и число ловушек на ноде.

## 4. Сервер центра

```sh
git clone https://github.com/DanielE330/umirhack3.git /opt/honeyforge   # или rsync с рабочей машины
cd /opt/honeyforge/infra
cp .env.example .env
mkdir -p secrets && chmod 700 secrets
```

**Ключи оркестратора** — с хоста Proxmox в `infra/secrets/`:

```sh
scp root@<proxmox>:/root/honeyforge-secrets/{pve_agent_ed25519,known_hosts} /opt/honeyforge/infra/secrets/
chmod 600 /opt/honeyforge/infra/secrets/*
ssh root@<proxmox> rm /root/honeyforge-secrets/pve_agent_ed25519   # приватный ключ на хосте больше не нужен
```

**`.env`.** Блок Proxmox целиком берётся из `/root/honeyforge-secrets/proxmox.env` на хосте:
`PROXMOX_*`, `PVE_SSH_HOST`, `HF_PUBLIC_URL`. Остальное:

| Переменная | Как получить |
|---|---|
| `HF_SECRET_KEY` | `docker compose run --rm center python -m app.cli gen-key` (печатает готовую строку) |
| `HF_DB_PASSWORD` | `python3 -c "import secrets;print(secrets.token_urlsafe(24))"` |
| `ORCH_TOKEN` | `python3 -c "import secrets;print(secrets.token_urlsafe(32))"` |
| `HF_COOKIE_SECURE` | `false`, пока вход по http |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_PROXY` | необязательно, см. раздел 6 |

`HF_PUBLIC_URL` должен указывать на тот же адрес и порт, что `--center-ip`/`--center-port`, иначе файрвол DMZ не пропустит агентов.

**Запуск и первый администратор:**

```sh
docker compose up -d --build
curl -s http://127.0.0.1:4000/api/health                       # {"status":"ok"}
docker compose exec center python -m app.cli create-admin admin # пароль от 12 символов, без логина внутри
```

Открыть `http://<центр>:4000`, войти. При первом входе отсканировать QR в приложении-аутентификаторе и сохранить резервные коды.
Остальных пользователей — вкладка «Пользователи» или `python -m app.cli create-user <логин> --role operator`.

## 5. Первая ловушка

1. **Профили** → «Создать профиль». Например, уровень `medium` с сервисами `ssh` и `http` — поддельная оболочка, админка, honeytoken-файлы и URL.
2. **Контейнеры** → «+ Новый контейнер» → выбрать типы ловушек (профили с непересекающимися портами) → «Создать в Proxmox».
   - Оркестратор клонирует шаблон в DMZ: IP от `10.20.0.10`, по умолчанию 1 ядро, 1 ГБ ОЗУ, 10 ГБ.
   - Центр выпускает токены, а `hf-agent-ctl` включает агентов в машине.
   - Через ~30 секунд ловушки в карточке контейнера — «на связи». Токен никому не показывается.
   - Добавить ловушку в уже созданный контейнер — «Добавить ловушку» в его карточке; повторить установку — «Переустановить агента».
3. Проверка с хоста Proxmox (или любой машины, видящей DMZ):
   ```sh
   ssh admin@10.20.0.10      # ввести пару паролей, выполнить id, ls, cat honeytoken
   curl http://10.20.0.10/
   ```
   События появятся в «Обзоре» сразу. 5+ попыток входа за минуту с одного IP дают событие `alert` (и сообщение в Telegram, если настроен).

## 6. Telegram (необязательно)

Создать бота у @BotFather, узнать `chat_id` (например, через `getUpdates`), записать в `.env`:
`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. Если Telegram заблокирован — `TELEGRAM_PROXY=socks5://хост:порт`. Затем `docker compose up -d orchestrator`.

Проверка:
```sh
docker exec hf-orchestrator python -W ignore -c "import os,httpx; t=os.environ['TELEGRAM_BOT_TOKEN']; print(httpx.get(f'https://api.telegram.org/bot{t}/getMe', proxy=os.environ['TELEGRAM_PROXY'] or None, timeout=15).json()['ok'])"
```

## 7. Обновление

**Центр и оркестратор:**
```sh
rsync -az --delete --exclude .git --exclude .venv --exclude __pycache__ --exclude .pytest_cache --exclude .claude --exclude knowledge --exclude node_modules --exclude dist \
  --filter 'P infra/.env' --filter 'P infra/secrets/' ./ root@<центр>:/opt/honeyforge/
ssh root@<центр> 'cd /opt/honeyforge/infra && docker compose up -d --build'
```
Фильтры `P` обязательны, иначе `--delete` сотрёт `.env` и ключи. Фронтенд (React + Vite) собирается при сборке образа центра (стадия Node в `backend/center/Dockerfile`) — после правок `frontend/` пересобрать `center`; `node_modules/` и `dist/` на сервер копировать не нужно.

**Агент в ловушках:**
```sh
rsync -aR --exclude __pycache__ infra/proxmox agent/netsvc root@<proxmox>:/root/honeyforge/
ssh root@<proxmox> /root/honeyforge/infra/proxmox/hf-proxmox.sh update-agent
```
Затем у нужных ловушек в панели нажать «Переустановить агента» (или `POST /api/traps/{id}/agent`): новый код кладётся в машину при каждой установке.

**Шаблон:** `hf-proxmox.sh install --rebuild-template` — уже созданные машины не меняются.

## 8. Удаление

**Хост Proxmox:**
```sh
ssh -t root@<proxmox> /root/honeyforge/infra/proxmox/hf-proxmox.sh uninstall   # --yes — без вопроса
```

Скрипт сначала покажет список и спросит `yes`, затем удалит:
- машины с тегом `honeyforge` и шаблон с тегом `honeyforge-template`;
- пользователя `honeyforge@pve` с токеном, роли, пул и ACL;
- ключ `hf-orchestrator`, `hf-agent-ctl`, архив агента;
- мост и файрвол DMZ.

Мост остаётся, если к нему подключены машины без тега. Типы содержимого хранилища возвращаются, только если на нём не осталось дисков.
`ip_forward` и скачанный образ Ubuntu не трогаются — они могут быть нужны другим. В конце удаляются `/etc/honeyforge` и `/root/honeyforge-secrets`.

**Центр:**
```sh
cd /opt/honeyforge/infra && docker compose down -v   # -v удаляет и базу (события, пользователи)
rm -rf /opt/honeyforge
```

## 9. Ловушка без Proxmox (вручную)

Агент можно запустить на любом Linux-хосте с Python 3:

```sh
cd agent && pip install -r requirements.txt
HF_CENTER_URL=http://<центр>:4000 HF_TRAP_TOKEN=<токен> python3 -m netsvc
```

Токен — кнопка «Подключить агента» у ловушки без машины (`POST /api/traps/{id}/deploy`). Переменные агента — в `README.md`.

## 10. Типовые проблемы

| Симптом | Причина | Что делать |
|---|---|---|
| `install`: `мост vmbr1 уже есть и не принадлежит HoneyForge` | имя занято чужим мостом | `--bridge vmbr2 --network 10.21.0.0/24 --gateway 10.21.0.1`, те же значения в `.env` центра |
| `install`: `из шаблона нет интернета` | нет NAT/маршрута наружу | проверить `--wan`, `iptables -t nat -L POSTROUTING`, DNS 1.1.1.1 доступен |
| `install`: `VMID 9101 занят чужим гостем` | — | `--template-id <свободный>`, то же в `PROXMOX_TEMPLATE_LXC` |
| `proxmox.env` без `PROXMOX_TOKEN_VALUE` | токен выпущен раньше, Proxmox не хранит значение | `install --rotate-token`, обновить `.env`, `docker compose up -d orchestrator` |
| `/api/machines` → 503 | нет `PROXMOX_TOKEN_*` в `.env` или Proxmox недоступен | проверить `.env`, `docker compose logs orchestrator` |
| Клон: `content type 'rootdir' is not available` | хранилище без типа | `install` ещё раз (добавит) или `pvesm set <st> --content …,rootdir,images` |
| Агент: `error: not a honeyforge machine` / `machine is not running` / `agent is not preinstalled` | машина без тега, выключена или из старого шаблона | создать машину заново из шаблона `install` |
| Агент «never»/«offline» | агент не достучался до центра | `HF_PUBLIC_URL` = `--center-ip:--center-port`; на хосте `journalctl -t hf-agent-ctl`; в машине `systemctl status systemd-journal-helper@<id>` |
| SSH оркестратора: `Permission denied` | центр ходит с другого адреса, чем `from=` | `install --orch-from <адрес центра, как его видит хост>` |
| Вход в панель: 429 | 5 неверных паролей / 20 с IP за 15 минут | подождать или `docker compose exec -T db psql -U honeyforge -d honeyforge -c "DELETE FROM login_failures"` |
| Потерян телефон с 2FA | — | другой admin: «Пользователи» → «Сбросить 2FA» |
| Панель старая после обновления | кэш браузера | Ctrl+Shift+R |

Логи:
- центр — `docker compose logs -f center` (и `orchestrator`, `proxy`);
- хост Proxmox — `journalctl -t hf-agent-ctl`, `pct list`, `hf-proxmox.sh status`.

## 11. Безопасность стенда

- Наружу публикуется только proxy `:4000`. Секреты — только в `infra/.env` и `infra/secrets/` (оба в `.gitignore`).
- TLS на стенде выключен (`auto_https off`, `HF_COOKIE_SECURE=false`). Для боевого использования включить TLS в Caddy и выставить `HF_COOKIE_SECURE=true`.
- Оркестратор ходит в Proxmox без проверки сертификата (`verify_ssl=False`); ограничение — права токена только на пул ловушек.
- Ключ оркестратора на хосте Proxmox ограничен одной командой и адресом центра; `hf-agent-ctl` работает только с запущенными машинами с тегом `honeyforge`.
