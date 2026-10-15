#!/bin/sh
# HoneyForge: одобрить в Headscale маршрут к DMZ ловушек (10.20.0.0/24),
# который уже анонсирован хостом Proxmox (узел "proxmox" в tailnet, команда
# `tailscale set --advertise-routes=10.20.0.0/24` на нём уже выполнена).
#
# Запускать НА СЕРВЕРЕ HEADSCALE (там, где установлен `headscale`), от root.
# Ничего не меняет в самих ловушках — только открывает вам доступ к их
# подсети через Tailscale, изоляция ловушек от домашней сети (hf-dmz-fw.sh
# на Proxmox) при этом не трогается.
set -eu

NODE="proxmox"
PREFIX="10.20.0.0/24"

echo "=== узлы ==="
headscale nodes list

echo
echo "=== маршруты (как есть) ==="
headscale routes list

ROUTE_ID=""

# 1) пробуем JSON-вывод (разные версии headscale называют флаг по-разному)
for JSONCMD in "headscale routes list -o json" "headscale routes list --output json"; do
  OUT=$($JSONCMD 2>/dev/null) || continue
  [ -n "$OUT" ] || continue
  ROUTE_ID=$(printf '%s' "$OUT" | python3 - "$NODE" "$PREFIX" <<'PYEOF'
import json, sys
node, prefix = sys.argv[1], sys.argv[2]
try:
    rows = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in rows:
    n = r.get("node") or {}
    name = n.get("givenName") or n.get("name") or n.get("hostname") or ""
    p = (r.get("prefix") or r.get("Prefix") or "").strip()
    if node in name and p == prefix:
        print(r.get("id") or r.get("ID") or "")
        break
PYEOF
  ) || true
  [ -n "$ROUTE_ID" ] && break
done

# 2) запасной вариант — парсим обычную текстовую таблицу
if [ -z "$ROUTE_ID" ]; then
  ROUTE_ID=$(headscale routes list 2>/dev/null | awk -v n="$NODE" -v p="$PREFIX" \
    '$0 ~ n && $0 ~ p {print $1; exit}')
fi

if [ -z "$ROUTE_ID" ]; then
  echo
  echo "Не удалось определить ID автоматически (другой формат вывода headscale)."
  echo "Возьмите его из таблицы выше — строка с узлом '$NODE' и подсетью $PREFIX — и выполните:"
  echo "  headscale routes enable -r <ID>"
  exit 1
fi

echo
echo "=== включаю маршрут ID=$ROUTE_ID ($PREFIX, узел $NODE) ==="
headscale routes enable -r "$ROUTE_ID"

echo
echo "=== готово, проверка ==="
headscale routes list
