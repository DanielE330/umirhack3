#!/bin/bash
# Поднять весь HoneyForge (хост Proxmox + центр со всем docker-compose стеком) ОДНОЙ командой
# с рабочей машины — на любом свежем Proxmox VE 8/9, по SSH root:
#
#   cd <репозиторий>
#   ./infra/proxmox/hf-deploy.sh root@<proxmox> --center-ip 192.168.1.50
#
# Копирует репозиторий на хост в /root/honeyforge и запускает там
# infra/proxmox/hf-proxmox.sh bootstrap с переданными флагами (--help — там же).
# Повторный запуск безопасен (копирует код заново, но не трогает секреты и БД) —
# так же можно обновлять код: hf-deploy.sh root@<proxmox> update-app.
set -euo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

die() { printf '\033[31mошибка:\033[0m %s\n' "$*" >&2; exit 1; }

HOST="${1:-}"
[ -n "$HOST" ] || die "использование: $0 root@<proxmox> [update-app|uninstall|status] [--center-ip IP ...] (см. hf-proxmox.sh --help)"
shift
[[ "$HOST" == *@* ]] || HOST="root@$HOST"

CMD=bootstrap
case "${1:-}" in
  install|bootstrap|update-app|uninstall|status|update-agent) CMD="$1"; shift ;;
esac

printf '\033[1;34m==>\033[0m %s\n' "Копирую репозиторий на $HOST:/root/honeyforge"
rsync -az --delete \
  --exclude .git --exclude .venv --exclude __pycache__ --exclude .pytest_cache \
  --exclude .claude --exclude knowledge --exclude node_modules --exclude dist \
  --filter 'P infra/.env' --filter 'P infra/secrets/' \
  "$REPO/" "$HOST:/root/honeyforge/"

printf '\033[1;34m==>\033[0m %s\n' "Запускаю: hf-proxmox.sh $CMD"
# shellcheck disable=SC2029
ssh -t "$HOST" "cd /root/honeyforge && infra/proxmox/hf-proxmox.sh $CMD $(printf '%q ' "$@")"
