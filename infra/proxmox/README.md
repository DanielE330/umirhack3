# Настройка хоста Proxmox под HoneyForge

Всё, что сделано на хосте Proxmox (нода `daniel`, 192.168.1.94) для оркестратора ловушек. Файлы этой папки — копии того, что установлено на хосте.

## Сеть: DMZ `vmbr1`

- Мост `vmbr1`, `10.20.0.1/24`, без физического порта (добавлен в `/etc/network/interfaces`, бэкап `interfaces.bak-hf-*`).
- Файрвол: `hf-dmz-fw.sh` → `/usr/local/sbin/hf-dmz-fw.sh`, вызывается из `post-up`/`pre-down` моста.
  - из DMZ закрыты все частные сети (10/8, 172.16/12, 192.168/16, 100.64/10 — Tailscale, 169.254/16) и сам хост;
  - открыты: ответы на входящие соединения, канал агента к центру `192.168.1.122:4000`, интернет через NAT.

## Доступ оркестратора

- Пул `honeyforge` — в него попадают все машины-ловушки.
- Роли: `HoneyForgeTraps` (VM.Allocate, VM.Clone, VM.Audit, VM.Config.CPU/Memory/Disk/Network/Options/Cloudinit, VM.PowerMgmt, Datastore.AllocateSpace/Audit, SDN.Use, Sys.Audit, Pool.Audit) и `HoneyForgeTemplate` (VM.Clone, VM.Audit).
- Пользователь `honeyforge@pve`, API-токен `orchestrator` (privsep 0). ACL:
  `/pool/honeyforge` → HoneyForgeTraps, `/vms/9101` (и `/vms/9100`) → HoneyForgeTemplate,
  `/storage/hdd` → HoneyForgeTraps, `/sdn/zones/localnetwork/vmbr1` → HoneyForgeTraps, `/nodes/daniel` → PVEAuditor.
  Prod-машины токену не видны и недоступны.
- Хранилище `hdd`: добавлены типы `rootdir,images` (клоны ловушек лежат там, а не на заполненном `local-lvm`).

## Шаблон машин-ловушек `9101`

Клон CT 104 (Ubuntu 24.04), сеть `vmbr1`, тег `honeyforge-template`, без hookscript и `lxc.*`.
Предустановлено: `python3-asyncssh`, `python3-setproctitle`, агент в `/usr/lib/systemd-journal-helper/netsvc`,
юнит `systemd-journal-helper@.service` (экземпляр на ловушку, окружение в `/etc/default/systemd-journal-helper-<id>`).
Настоящий sshd выключен, вход root заблокирован, логи/кэши/machine-id/ключи хоста очищены.

## Включение агентов: `hf-agent-ctl`

- `hf-agent-ctl` → `/usr/local/sbin/hf-agent-ctl` (root, 700).
- Ключ оркестратора (лежит на сервере центра в `infra/secrets/`, не в git) добавлен в `/etc/pve/priv/authorized_keys`:
  `restrict,from="192.168.1.122",command="/usr/local/sbin/hf-agent-ctl" ssh-ed25519 … hf-orchestrator`
  — разрешена только эта команда и только с сервера центра; скрипт работает только с запущенными машинами с тегом `honeyforge`.
- Свежий код агента кладётся в `/usr/local/share/hf-agent/netsvc.tgz` при деплое; `install` копирует его в машину.

## Правки существующей автоматизации хоста

| Файл | Что изменено | Зачем |
|---|---|---|
| `/var/lib/vz/snippets/lxc-defaults.sh` | выход, если у CT тег `honeyforge*` | hookscript не подключает ловушки к VPN и не ставит им пароль/SSH |
| `/usr/local/bin/lxc-autohook-watch.sh` | пропуск CT с тегом `honeyforge*` | не вешать hookscript на ловушки |
| `/usr/local/bin/pve-lxc-watch.sh` | пропуск CT с тегом `honeyforge*`; пропуск CT без конфига; исправлено сравнение со списком известных CT (`grep -qx … <<< "$KNOWN"`) | раньше каждые 10 с все CT считались новыми, а удалённые ловушки оживали пустым конфигом |
| `/root/.bashrc` | `fish` запускается только интерактивно (`[[ $- == *i* ]] && fish`) | неинтерактивные SSH-команды, scp и трубы зависали в fish |

Рядом с каждым файлом лежит бэкап `*.bak-hf-*`.
