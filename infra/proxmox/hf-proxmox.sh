#!/bin/bash
# Установка и удаление HoneyForge на хосте Proxmox (всё, что описано в infra/proxmox/README.md).
# Запускается на хосте Proxmox от root. Рядом нужен весь репозиторий (не только эта папка) —
# bootstrap/update-app собирают образы из backend/, frontend/, honeymind/, install/uninstall/status
# достаточно agent/netsvc. Проще всего — одной командой с рабочей машины через infra/proxmox/hf-deploy.sh
# (копирует репозиторий и запускает этот скрипт за вас):
#
#   ./infra/proxmox/hf-deploy.sh root@<proxmox> --center-ip 192.168.1.50
#
# Вручную — то же самое в два шага:
#
#   cd <репозиторий> && rsync -aR --exclude __pycache__ --exclude .git --exclude node_modules \
#     --exclude frontend/dist --exclude .venv infra agent backend frontend honeymind root@<proxmox>:/root/honeyforge/
#   ssh root@<proxmox> /root/honeyforge/infra/proxmox/hf-proxmox.sh bootstrap --center-ip 192.168.1.50
#
# Команды:
#   bootstrap     ВСЁ ОДНОЙ КОМАНДОЙ: готовит хост (как install), затем сам создаёт отдельный LXC-контейнер
#                 (docker.io + docker compose) со всем стеком — center/orchestrator/db/honeymind/proxy —
#                 копирует туда код, секреты Proxmox, генерирует infra/.env, создаёт первого admin
#                 (пароль печатается один раз) и HTTPS для панели на отдельном порту (ниже). --center-ip
#                 здесь — свободный адрес в ЛОКАЛЬНОЙ сети (не в DMZ) для этого нового контейнера.
#   install       Только хост Proxmox: DMZ-мост с файрволом, пул/роли/пользователь/API-токен,
#                 шаблон ловушек, hf-agent-ctl, ключ оркестратора. Центр поднимаете сами (см. docs/INSTALL.md)
#                 или на другом сервере — используйте, если bootstrap не подходит (центр не на этом хосте).
#   update-app    Перекопировать код в контейнер центра (из bootstrap) и пересобрать docker compose.
#   admin-tls     Отдельно включить/обновить HTTPS для панели (если выключали --no-admin-tls при bootstrap
#                 или меняете --admin-tls-port).
#   uninstall     удаляет всё перечисленное, включая машины-ловушки, шаблон и контейнер центра (если был bootstrap).
#   status        что из этого сейчас есть на хосте.
#   update-agent  только обновить код агента (/usr/local/share/hf-agent/netsvc.tgz) — для новых установок агентов.
#
# HTTPS для панели (только bootstrap/admin-tls): т.к. порт --center-port (4000) внутри HoneyForge
# намеренно работает по голому HTTP (туда же ходят агенты-ловушки из DMZ, своя защита от утечки
# панели в их сторону — ломать нельзя), bootstrap поднимает ОТДЕЛЬНЫЙ systemd-сервис
# honeyforge-tls-admin: stunnel слушает TLS на --admin-tls-port (4443) и перенаправляет на
# 127.0.0.1:--center-port. Сертификат самоподписанный (ECDSA, IP в SAN, 10 лет) — браузер один раз
# спросит подтверждение. Полностью отдельно от docker compose — переживает update-app и перезапуски.
#
# Повторный запуск любой команды безопасен: готовое пропускается, секреты не перегенерируются.
# Параметры (сохраняются в /etc/honeyforge/proxmox.conf и подхватываются при следующих запусках):
#   --center-ip IP        bootstrap: адрес нового контейнера центра в локальной сети (обязателен)
#                          install: адрес центра, до которого агенты ходят из DMZ (обязателен)
#   --center-port N       порт центра (4000)
#   --center-vmid N       VMID контейнера центра (9200)
#   --center-cores N      ядра контейнера центра (2)      --center-memory МБ   ОЗУ (2048)
#   --center-disk ГБ      диск контейнера центра (20)      --center-storage     хранилище (как у ловушек)
#   --center-bridge NAME  мост для контейнера центра (по умолчанию = --wan)
#   --center-gateway IP   шлюз локальной сети для контейнера центра (автоопределение)
#   --admin-tls-port N    порт HTTPS для панели (4443, самоподписанный, см. выше) --no-admin-tls  выключить
#   --orch-from IP        откуда оркестратор ходит по SSH на хост (по умолчанию = --center-ip)
#   --orch-pubkey FILE    свой публичный ключ оркестратора (иначе ключ генерируется в /root/honeyforge-secrets/)
#   --pve-ip IP           адрес хоста Proxmox для центра (по умолчанию — адрес на --wan)
#   --node NAME           нода Proxmox (hostname)
#   --storage NAME        хранилище машин-ловушек (hdd/local-lvm/local-zfs/local-btrfs/local — первое, что есть)
#   --bridge NAME         мост DMZ (vmbr1)        --wan NAME         мост с выходом в интернет (из маршрута по умолчанию)
#   --network CIDR        подсеть DMZ (10.20.0.0/24)  --gateway IP   адрес хоста в DMZ (10.20.0.1)
#   --template-id N       VMID шаблона (9101)     --pool NAME        пул (honeyforge)
#   --ostemplate VOLID    образ Ubuntu 24.04 (по умолчанию ищется/скачивается в --ostemplate-storage, local)
#   --template-disk GB    диск шаблона (8)        --build-ip IP      адрес шаблона на время сборки (.250 в DMZ)
#   --rebuild-template    пересобрать шаблон      --rotate-token     перевыпустить API-токен оркестратора
#   --yes                 не спрашивать подтверждение при uninstall
set -euo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
STATE_DIR=/etc/honeyforge
STATE=$STATE_DIR/proxmox.conf
SECRETS=/root/honeyforge-secrets
IFACES=/etc/network/interfaces
FW=/usr/local/sbin/hf-dmz-fw.sh
FW_CONF=/etc/default/hf-dmz
CTL=/usr/local/sbin/hf-agent-ctl
PKG_DIR=/usr/local/share/hf-agent
PKG=$PKG_DIR/netsvc.tgz
SYSCTL=/etc/sysctl.d/99-honeyforge.conf
USER_CFG=/etc/pve/user.cfg
MARK_BEGIN="# >>> honeyforge dmz >>>"
MARK_END="# <<< honeyforge dmz <<<"
PVE_USER=honeyforge@pve
TOKEN_NAME=orchestrator
KEY_COMMENT=hf-orchestrator
TAG=honeyforge
TAG_TPL=honeyforge-template
TAG_CENTER=honeyforge-center
ROLE_TRAPS=HoneyForgeTraps
ROLE_TPL=HoneyForgeTemplate
PRIVS_TRAPS="Datastore.AllocateSpace,Datastore.Audit,Pool.Audit,SDN.Use,Sys.Audit,VM.Allocate,VM.Audit,VM.Clone,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.PowerMgmt"
PRIVS_TPL="VM.Audit,VM.Clone"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mошибка:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- параметры ----------
CENTER_IP=""; CENTER_PORT=4000; ORCH_FROM=""; ORCH_PUBKEY=""; PVE_IP=""; NODE=""; STORAGE=""
BRIDGE=vmbr1; WAN_IF=""; DMZ_NET=10.20.0.0/24; DMZ_GW=10.20.0.1; TEMPLATE_ID=9101; POOL=honeyforge
OSTEMPLATE=""; OST_STORAGE=local; TEMPLATE_DISK=8; BUILD_IP=""
STORAGE_ADDED_CONTENT=""
REBUILD_TEMPLATE=0; ROTATE_TOKEN=0; YES=0
CENTER_VMID=9200; CENTER_CORES=2; CENTER_MEMORY=2048; CENTER_DISK=20
CENTER_STORAGE=""; CENTER_BRIDGE=""; CENTER_GW=""; CENTER_PREFIX=""
ADMIN_PASSWORD=""
ADMIN_TLS=1; ADMIN_TLS_PORT=4443

# shellcheck disable=SC1090
[ -r "$STATE" ] && . "$STATE"

CMD="${1:-}"; [ $# -gt 0 ] && shift
while [ $# -gt 0 ]; do
  case "$1" in
    --center-ip) CENTER_IP="$2"; shift ;;
    --center-port) CENTER_PORT="$2"; shift ;;
    --center-vmid) CENTER_VMID="$2"; shift ;;
    --center-cores) CENTER_CORES="$2"; shift ;;
    --center-memory) CENTER_MEMORY="$2"; shift ;;
    --center-disk) CENTER_DISK="$2"; shift ;;
    --center-storage) CENTER_STORAGE="$2"; shift ;;
    --center-bridge) CENTER_BRIDGE="$2"; shift ;;
    --center-gateway) CENTER_GW="$2"; shift ;;
    --center-prefix) CENTER_PREFIX="$2"; shift ;;
    --admin-tls-port) ADMIN_TLS_PORT="$2"; shift ;;
    --no-admin-tls) ADMIN_TLS=0 ;;
    --orch-from) ORCH_FROM="$2"; shift ;;
    --orch-pubkey) ORCH_PUBKEY="$2"; shift ;;
    --pve-ip) PVE_IP="$2"; shift ;;
    --node) NODE="$2"; shift ;;
    --storage) STORAGE="$2"; shift ;;
    --bridge) BRIDGE="$2"; shift ;;
    --wan) WAN_IF="$2"; shift ;;
    --network) DMZ_NET="$2"; shift ;;
    --gateway) DMZ_GW="$2"; shift ;;
    --template-id) TEMPLATE_ID="$2"; shift ;;
    --pool) POOL="$2"; shift ;;
    --ostemplate) OSTEMPLATE="$2"; shift ;;
    --ostemplate-storage) OST_STORAGE="$2"; shift ;;
    --template-disk) TEMPLATE_DISK="$2"; shift ;;
    --build-ip) BUILD_IP="$2"; shift ;;
    --rebuild-template) REBUILD_TEMPLATE=1 ;;
    --rotate-token) ROTATE_TOKEN=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) die "неизвестный параметр: $1 (см. --help)" ;;
  esac
  shift
done

is_ip() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o; for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done
}

init_defaults() {
  [ -n "$NODE" ] || NODE=$(hostname)
  [ -d "/etc/pve/nodes/$NODE" ] || die "нода $NODE не найдена в /etc/pve/nodes (укажите --node)"
  [ -n "$WAN_IF" ] || WAN_IF=$(ip route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
  [ -n "$WAN_IF" ] || WAN_IF=vmbr0
  if [ -z "$STORAGE" ]; then
    # hdd — диск этого стенда; local-lvm/local-zfs/local-btrfs — что ставит инсталлятор PVE по умолчанию
    # в зависимости от выбранной ФС; local есть всегда (каталоговое хранилище, тоже умеет rootdir,images)
    local cand
    for cand in hdd local-lvm local-zfs local-btrfs local; do
      storage_exists "$cand" && { STORAGE=$cand; break; }
    done
  fi
  [ -n "$ORCH_FROM" ] || ORCH_FROM="$CENTER_IP"
  [ -n "$PVE_IP" ] || PVE_IP=$(ip -4 -o addr show dev "$WAN_IF" 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}' || true)
  DMZ_PREFIX="${DMZ_NET#*/}"
  [ -n "$BUILD_IP" ] || BUILD_IP="${DMZ_GW%.*}.250"
}

save_state() {
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  {
    echo "# HoneyForge на этом хосте Proxmox: параметры установки (пишет hf-proxmox.sh)"
    for v in CENTER_IP CENTER_PORT ORCH_FROM PVE_IP NODE STORAGE BRIDGE WAN_IF DMZ_NET DMZ_GW TEMPLATE_ID POOL \
             OST_STORAGE TEMPLATE_DISK STORAGE_ADDED_CONTENT \
             CENTER_VMID CENTER_CORES CENTER_MEMORY CENTER_DISK CENTER_STORAGE CENTER_BRIDGE CENTER_GW CENTER_PREFIX \
             ADMIN_TLS_PORT; do
      printf '%s=%q\n' "$v" "${!v}"
    done
  } > "$STATE"
  chmod 600 "$STATE"
}

need_tools() {
  [ "$(id -u)" -eq 0 ] || die "запускать от root на хосте Proxmox"
  for t in pveum pct pvesm pveam pvesh ifreload iptables awk tar openssl; do
    command -v "$t" >/dev/null || die "нет команды $t — это точно хост Proxmox VE?"
  done
}

# ---------- хранилище ----------
storage_exists() { grep -qE "^[a-z]+: $1\$" /etc/pve/storage.cfg; }
storage_content() {
  awk -v s="$1" '$0 ~ "^[a-z]+: "s"$" {f=1; next} f && /^[a-z]/ {f=0} f && $1=="content" {print $2}' /etc/pve/storage.cfg
}

# ---------- гости ----------
# Конфиги гостей локальной ноды: "<vmid> <lxc|qemu> <путь>"
guests() {
  local f
  for f in /etc/pve/lxc/*.conf; do [ -e "$f" ] && echo "$(basename "$f" .conf) lxc $f"; done
  for f in /etc/pve/qemu-server/*.conf; do [ -e "$f" ] && echo "$(basename "$f" .conf) qemu $f"; done
  return 0
}
# Тег проверяется только в основной секции конфига (до первого снапшота)
has_tag() {
  awk -v t="$2" '/^\[/ {exit} /^tags:/ {sub(/^tags:[ \t]*/, ""); n = split($0, a, /[ ;,]/); for (i = 1; i <= n; i++) if (a[i] == t) f = 1}
                 END {exit !f}' "$1"
}
guest_conf() { ls /etc/pve/nodes/*/lxc/"$1".conf /etc/pve/nodes/*/qemu-server/"$1".conf 2>/dev/null | head -1 || true; }

# ---------- сеть DMZ ----------
# Блок моста в interfaces: строки "auto BR", "iface BR ..." и их продолжения с отступом
bridge_stanza() {
  awk -v br="$1" '
    /^[ \t]*(auto|allow-hotplug)[ \t]/ && NF==2 && $2==br {print; next}
    /^[ \t]*iface[ \t]/ {f=($2==br)}
    /^[^ \t]/ && !/^[ \t]*iface[ \t]/ {f=0}
    f {print}' "$IFACES"
}
bridge_is_ours() { grep -q "hf-dmz-fw.sh" <<< "$(bridge_stanza "$BRIDGE")"; }

remove_bridge_stanza() {
  local tmp; tmp=$(mktemp)
  # Комментарий "# HoneyForge DMZ" удаляется, только если сразу за ним идёт блок этого моста
  awk -v br="$BRIDGE" -v mb="$MARK_BEGIN" -v me="$MARK_END" '
    $0==mb || $0==me {next}
    held != "" { if (!(($1=="auto" || $1=="allow-hotplug" || $1=="iface") && $2==br)) print held; held="" }
    /^# HoneyForge DMZ/ {held=$0; next}
    /^[ \t]*(auto|allow-hotplug)[ \t]/ && NF==2 && $2==br {next}
    /^[ \t]*iface[ \t]/ {f=($2==br); if (f) next}
    /^[^ \t]/ {f=0}
    f {next}
    {print}
    END { if (held != "") print held }' "$IFACES" | cat -s | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' > "$tmp"
  cat "$tmp" > "$IFACES"; rm -f "$tmp"
}

install_network() {
  say "DMZ: мост $BRIDGE ($DMZ_GW/$DMZ_PREFIX), файрвол, NAT через $WAN_IF"
  install -m 755 "$HERE/hf-dmz-fw.sh" "$FW"
  cat > "$FW_CONF" <<EOF
# HoneyForge DMZ: параметры $FW (пишет hf-proxmox.sh)
NET=$DMZ_NET
CENTER=$CENTER_IP
CPORT=$CENTER_PORT
BRIDGE=$BRIDGE
WAN=$WAN_IF
EOF
  echo "net.ipv4.ip_forward=1" > "$SYSCTL"
  sysctl -q -p "$SYSCTL"

  if grep -qE "^[ \t]*iface[ \t]+$BRIDGE([ \t]|\$)" "$IFACES"; then
    bridge_is_ours || die "мост $BRIDGE уже есть и не принадлежит HoneyForge — укажите другой --bridge"
    ok "мост $BRIDGE уже настроен"
  else
    cp -a "$IFACES" "$IFACES.bak-hf-$(date +%Y%m%d%H%M%S)"
    cat >> "$IFACES" <<EOF

$MARK_BEGIN
# HoneyForge DMZ: изолированная сеть ловушек (без физического порта)
auto $BRIDGE
iface $BRIDGE inet static
	address $DMZ_GW/$DMZ_PREFIX
	bridge-ports none
	bridge-stp off
	bridge-fd 0
	post-up $FW up
	pre-down $FW down
$MARK_END
EOF
    ifreload -a
    ok "мост $BRIDGE добавлен в $IFACES (бэкап рядом)"
  fi
  ip link show "$BRIDGE" >/dev/null 2>&1 || die "мост $BRIDGE не поднялся (ifreload -a)"
  "$FW" up
  ok "файрвол DMZ: открыт только $CENTER_IP:$CENTER_PORT и интернет"
}

# ---------- хранилище ----------
install_storage() {
  say "Хранилище $STORAGE"
  storage_exists "$STORAGE" || die "хранилища $STORAGE нет (укажите --storage)"
  local cur missing="" t
  cur=$(storage_content "$STORAGE")
  for t in rootdir images; do
    [[ ",$cur," == *",$t,"* ]] || missing="${missing:+$missing,}$t"
  done
  if [ -n "$missing" ]; then
    pvesm set "$STORAGE" --content "${cur:+$cur,}$missing"
    STORAGE_ADDED_CONTENT=$(echo "${STORAGE_ADDED_CONTENT:+$STORAGE_ADDED_CONTENT,}$missing" | tr ',' '\n' | sort -u | paste -sd,)
    ok "добавлены типы содержимого: $missing"
  else
    ok "типы rootdir,images уже разрешены"
  fi
}

# ---------- права оркестратора ----------
install_access() {
  say "Пул $POOL, роли, пользователь $PVE_USER и API-токен"
  grep -q "^pool:$POOL:" "$USER_CFG" || pveum pool add "$POOL" --comment "HoneyForge: машины-ловушки (оркестратор)"
  if grep -q "^role:$ROLE_TRAPS:" "$USER_CFG"; then pveum role modify "$ROLE_TRAPS" --privs "$PRIVS_TRAPS"
  else pveum role add "$ROLE_TRAPS" --privs "$PRIVS_TRAPS"; fi
  if grep -q "^role:$ROLE_TPL:" "$USER_CFG"; then pveum role modify "$ROLE_TPL" --privs "$PRIVS_TPL"
  else pveum role add "$ROLE_TPL" --privs "$PRIVS_TPL"; fi
  grep -q "^user:$PVE_USER:" "$USER_CFG" || pveum user add "$PVE_USER" --comment "HoneyForge orchestrator (только API-токен)"

  TOKEN_VALUE=""
  if grep -q "^token:$PVE_USER!$TOKEN_NAME:" "$USER_CFG"; then
    if [ "$ROTATE_TOKEN" = 1 ]; then
      pveum user token remove "$PVE_USER" "$TOKEN_NAME"
    else
      ok "токен $PVE_USER!$TOKEN_NAME уже есть (новое значение — с --rotate-token)"
    fi
  fi
  if ! grep -q "^token:$PVE_USER!$TOKEN_NAME:" "$USER_CFG"; then
    TOKEN_VALUE=$(pveum user token add "$PVE_USER" "$TOKEN_NAME" --privsep 0 --comment "HoneyForge orchestrator" \
                    --output-format json | grep -oE '"value" *: *"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/' || true)
    [ -n "$TOKEN_VALUE" ] || die "не удалось получить значение API-токена"
    ok "выпущен токен $PVE_USER!$TOKEN_NAME"
  fi

  pveum acl modify "/pool/$POOL" --users "$PVE_USER" --roles "$ROLE_TRAPS"
  pveum acl modify "/storage/$STORAGE" --users "$PVE_USER" --roles "$ROLE_TRAPS"
  pveum acl modify "/sdn/zones/localnetwork/$BRIDGE" --users "$PVE_USER" --roles "$ROLE_TRAPS"
  pveum acl modify "/nodes/$NODE" --users "$PVE_USER" --roles PVEAuditor
  ok "права: пул, хранилище, мост $BRIDGE, аудит ноды — prod-машины токену не видны"
}

# ---------- код агента и hf-agent-ctl ----------
install_agent_pkg() {
  [ -d "$REPO/agent/netsvc" ] || die "нет кода агента в $REPO/agent/netsvc (скопируйте его вместе с infra/proxmox)"
  mkdir -p "$PKG_DIR"
  tar -C "$REPO/agent" --exclude __pycache__ --exclude '*.pyc' --owner=0 --group=0 -czf "$PKG.new" netsvc
  chmod 600 "$PKG.new"; mv "$PKG.new" "$PKG"
  ok "код агента → $PKG"
}

install_ctl() {
  say "hf-agent-ctl и код агента"
  install -m 700 -o root -g root "$HERE/hf-agent-ctl" "$CTL"
  ok "$CTL"
  install_agent_pkg
}

# ---------- шаблон машин-ловушек ----------
BUILDING=""
CENTER_BUILDING=""
cleanup_build() {
  if [ -n "$BUILDING" ]; then
    warn "сборка шаблона прервана — удаляю недособранный CT $BUILDING"
    pct stop "$BUILDING" >/dev/null 2>&1 || true
    pct destroy "$BUILDING" --purge 1 >/dev/null 2>&1 || true
  fi
  if [ -n "$CENTER_BUILDING" ]; then
    warn "создание контейнера центра прервано — удаляю недособранный CT $CENTER_BUILDING"
    pct stop "$CENTER_BUILDING" >/dev/null 2>&1 || true
    pct destroy "$CENTER_BUILDING" --purge 1 >/dev/null 2>&1 || true
  fi
}
trap cleanup_build EXIT

resolve_ostemplate() {
  if [ -n "$OSTEMPLATE" ]; then echo "$OSTEMPLATE"; return; fi
  local v name
  v=$(pveam list "$OST_STORAGE" 2>/dev/null | awk '/ubuntu-24\.04-standard/ {print $1}' | sort -V | tail -1 || true)
  if [ -z "$v" ]; then
    pveam update >/dev/null
    name=$(pveam available --section system | awk '/ubuntu-24\.04-standard/ {print $2}' | sort -V | tail -1)
    [ -n "$name" ] || die "в pveam нет образа ubuntu-24.04-standard (укажите --ostemplate)"
    pveam download "$OST_STORAGE" "$name" >&2
    v="$OST_STORAGE:vztmpl/$name"
  fi
  echo "$v"
}

install_template() {
  say "Шаблон машин-ловушек $TEMPLATE_ID"
  local conf; conf=$(guest_conf "$TEMPLATE_ID")
  if [ -n "$conf" ]; then
    has_tag "$conf" "$TAG_TPL" || die "VMID $TEMPLATE_ID занят чужим гостем (укажите --template-id)"
    if [ "$REBUILD_TEMPLATE" = 1 ]; then
      grep -q "^template: 1" "$conf" || pct stop "$TEMPLATE_ID" >/dev/null 2>&1 || true
      pct destroy "$TEMPLATE_ID" --purge 1
      ok "старый шаблон удалён"
    elif grep -q "^template: 1" "$conf"; then
      ok "шаблон уже есть (пересобрать — --rebuild-template)"
      pveum acl modify "/vms/$TEMPLATE_ID" --users "$PVE_USER" --roles "$ROLE_TPL"
      return
    else
      warn "CT $TEMPLATE_ID с тегом $TAG_TPL найден, но сборка не завершена (не template) — пересобираю"
      pct stop "$TEMPLATE_ID" >/dev/null 2>&1 || true
      pct destroy "$TEMPLATE_ID" --purge 1
    fi
  fi

  local ost; ost=$(resolve_ostemplate)
  BUILDING=$TEMPLATE_ID
  pct create "$TEMPLATE_ID" "$ost" --hostname web-prod-01 --ostype ubuntu --arch amd64 \
    --cores 1 --memory 1024 --swap 512 --rootfs "$STORAGE:$TEMPLATE_DISK" \
    --net0 "name=eth0,bridge=$BRIDGE,ip=$BUILD_IP/$DMZ_PREFIX,gw=$DMZ_GW,type=veth" \
    --nameserver 1.1.1.1 --unprivileged 1 --features nesting=1 --tags "$TAG_TPL" \
    --description "HoneyForge: шаблон машин-ловушек" >/dev/null
  ok "CT $TEMPLATE_ID создан из $ost"
  pct start "$TEMPLATE_ID"

  local i
  for i in $(seq 60); do
    pct exec "$TEMPLATE_ID" -- getent hosts archive.ubuntu.com >/dev/null 2>&1 && break
    [ "$i" = 60 ] && die "из шаблона нет интернета (DMZ NAT через $WAN_IF?)"
    sleep 2
  done

  local apt=(env DEBIAN_FRONTEND=noninteractive apt-get -q -o Dpkg::Use-Pty=0)
  pct exec "$TEMPLATE_ID" -- "${apt[@]}" update >/dev/null
  pct exec "$TEMPLATE_ID" -- "${apt[@]}" install -y --no-install-recommends python3 python3-asyncssh python3-setproctitle python3-cryptography >/dev/null
  ok "python3-asyncssh, python3-setproctitle, python3-cryptography"

  # Агент: код + юнит-экземпляр на каждую ловушку (окружение кладёт hf-agent-ctl)
  local unit; unit=$(mktemp)
  cat > "$unit" <<'EOF'
[Unit]
Description=Journal Helper Service (%i)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/default/systemd-journal-helper-%i
Environment=HF_STATE_DIR=/var/lib/systemd/journal-helper/%i
WorkingDirectory=/usr/lib/systemd-journal-helper
ExecStart=/usr/bin/python3 -W ignore -m netsvc
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  pct exec "$TEMPLATE_ID" -- mkdir -p /usr/lib/systemd-journal-helper /var/lib/systemd/journal-helper
  pct push "$TEMPLATE_ID" "$PKG" /tmp/.jh.tgz
  pct exec "$TEMPLATE_ID" -- sh -c 'tar -xzf /tmp/.jh.tgz --no-same-owner -C /usr/lib/systemd-journal-helper && rm -f /tmp/.jh.tgz'
  pct push "$TEMPLATE_ID" "$unit" /etc/systemd/system/systemd-journal-helper@.service --perms 644
  rm -f "$unit"
  pct exec "$TEMPLATE_ID" -- systemctl daemon-reload
  ok "агент в /usr/lib/systemd-journal-helper, юнит systemd-journal-helper@.service"

  # Настоящий sshd выключен (порт 22 занимает агент), root заблокирован, следы сборки стёрты
  pct exec "$TEMPLATE_ID" -- sh -c '
    systemctl disable --now ssh.service ssh.socket >/dev/null 2>&1 || true
    passwd -l root >/dev/null
    apt-get clean; rm -rf /var/lib/apt/lists/*
    find /var/log -type f -exec truncate -s 0 {} +
    rm -f /root/.bash_history /etc/ssh/ssh_host_*
    rm -rf /tmp/* /var/tmp/* /var/tmp/.[!.]* 2>/dev/null
    : > /etc/machine-id; rm -f /var/lib/dbus/machine-id'
  ok "sshd выключен, root заблокирован, логи/кэши/machine-id/ключи хоста очищены"

  pct shutdown "$TEMPLATE_ID" --timeout 60 || pct stop "$TEMPLATE_ID"
  pct set "$TEMPLATE_ID" --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp,type=veth"
  pct template "$TEMPLATE_ID"
  BUILDING=""
  pveum acl modify "/vms/$TEMPLATE_ID" --users "$PVE_USER" --roles "$ROLE_TPL"
  ok "CT $TEMPLATE_ID превращён в шаблон, оркестратору разрешено только клонирование"
}

# ---------- SSH-ключ оркестратора ----------
authorized_keys() { readlink -f /root/.ssh/authorized_keys; }

install_orch_key() {
  say "Узкий SSH-доступ оркестратора (только hf-agent-ctl, только с $ORCH_FROM)"
  local ak pub existing tmp
  ak=$(authorized_keys); touch "$ak"
  mkdir -p "$SECRETS"; chmod 700 "$SECRETS"
  existing=$(grep -E " $KEY_COMMENT\$" "$ak" | head -1 || true)
  if [ -n "$ORCH_PUBKEY" ]; then
    pub=$(awk '{print $1" "$2; exit}' "$ORCH_PUBKEY")
  elif [ -n "$existing" ]; then
    pub=$(grep -oE '(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/=]+' <<< "$existing" | head -1)
  else
    rm -f "$SECRETS/pve_agent_ed25519" "$SECRETS/pve_agent_ed25519.pub"
    ssh-keygen -q -t ed25519 -N '' -C "$KEY_COMMENT" -f "$SECRETS/pve_agent_ed25519"
    pub=$(awk '{print $1" "$2}' "$SECRETS/pve_agent_ed25519.pub")
    ok "сгенерирован ключ $SECRETS/pve_agent_ed25519"
  fi
  [ -n "$pub" ] || die "не удалось прочитать публичный ключ оркестратора"
  mkdir -p "$STATE_DIR"; cp -a "$ak" "$STATE_DIR/authorized_keys.bak"
  tmp=$(mktemp)
  { grep -vE " $KEY_COMMENT\$" "$ak" || true
    echo "restrict,from=\"$ORCH_FROM\",command=\"$CTL\" $pub $KEY_COMMENT"; } > "$tmp"
  cat "$tmp" > "$ak"; rm -f "$tmp"
  ok "ключ в $ak"

  # known_hosts для оркестратора: подмена хоста Proxmox будет отвергнута
  : > "$SECRETS/known_hosts"
  local k
  for k in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
    [ -r "$k" ] && echo "$PVE_IP $(awk '{print $1" "$2}' "$k")" >> "$SECRETS/known_hosts"
  done
  ok "known_hosts для $PVE_IP"
}

write_env() {
  local envf=$SECRETS/proxmox.env old=""
  [ -z "$TOKEN_VALUE" ] && [ -r "$envf" ] && old=$(sed -n 's/^PROXMOX_TOKEN_VALUE=//p' "$envf")
  local tv=${TOKEN_VALUE:-$old}
  {
    echo "# Добавить в infra/.env центра (сгенерировано hf-proxmox.sh на $NODE)"
    echo "HF_PUBLIC_URL=http://$CENTER_IP:$CENTER_PORT"
    echo "PROXMOX_HOST=$PVE_IP"
    echo "PROXMOX_USER=$PVE_USER"
    echo "PROXMOX_PASSWORD="
    echo "PROXMOX_TOKEN_NAME=$TOKEN_NAME"
    if [ -n "$tv" ]; then echo "PROXMOX_TOKEN_VALUE=$tv"
    else echo "# PROXMOX_TOKEN_VALUE — токен выпущен раньше, Proxmox не хранит значение; новое: install --rotate-token"; fi
    echo "PROXMOX_POOL=$POOL"
    echo "PROXMOX_TEMPLATE_LXC=$TEMPLATE_ID"
    echo "PROXMOX_STORAGE=$STORAGE"
    echo "PROXMOX_BRIDGE=$BRIDGE"
    echo "PROXMOX_NETWORK=$DMZ_NET"
    echo "PROXMOX_GATEWAY=$DMZ_GW"
    echo "PVE_SSH_HOST=$PVE_IP"
  } > "$envf"
  chmod 600 "$envf"
}

provision_host() {
  need_tools
  is_ip "$CENTER_IP" || die "укажите адрес центра: --center-ip <IP> (до него агенты ходят из DMZ)"
  init_defaults
  is_ip "$PVE_IP" || die "не удалось определить адрес хоста на $WAN_IF (укажите --pve-ip)"
  say "Установка HoneyForge: нода $NODE, центр $CENTER_IP:$CENTER_PORT, хранилище $STORAGE, шаблон $TEMPLATE_ID"
  install_network
  install_storage
  save_state
  install_access
  save_state
  install_ctl
  install_template
  install_orch_key
  write_env
  save_state
}

cmd_install() {
  provision_host
  local files="$SECRETS/known_hosts"
  [ -f "$SECRETS/pve_agent_ed25519" ] && files="$SECRETS/pve_agent_ed25519 $files"
  cat <<EOF

$(say "Готово. Подключение центра:")
  1. Файлы оркестратора → infra/secrets/ на сервере центра (scp с хоста Proxmox):
       scp $files root@<центр>:/opt/honeyforge/infra/secrets/
       (pve_agent_ed25519 здесь нет — значит ключ уже был и лежит на центре)
  2. Переменные из $SECRETS/proxmox.env → infra/.env центра, затем:
       docker compose up -d orchestrator center
  3. После копирования приватный ключ на хосте больше не нужен: rm $SECRETS/pve_agent_ed25519

  Центр поднимаете сами на отдельном сервере. Если вместо этого хотите, чтобы центр со всем стеком
  (docker compose: center/orchestrator/db/honeymind/proxy) поднялся сам прямо на этом хосте Proxmox
  в отдельном LXC-контейнере — заново запустите с командой bootstrap вместо install.
EOF
}

# ---------- контейнер центра (bootstrap) ----------
init_center_defaults() {
  [ -n "$CENTER_BRIDGE" ] || CENTER_BRIDGE="$WAN_IF"
  [ -n "$CENTER_STORAGE" ] || CENTER_STORAGE="$STORAGE"
  [ -n "$CENTER_PREFIX" ] || CENTER_PREFIX=$(ip -4 -o addr show dev "$CENTER_BRIDGE" 2>/dev/null \
    | awk '{split($4,a,"/"); print a[2]; exit}' || true)
  [ -n "$CENTER_PREFIX" ] || CENTER_PREFIX=24
  [ -n "$CENTER_GW" ] || CENTER_GW=$(ip route show default dev "$CENTER_BRIDGE" 2>/dev/null \
    | awk '{for(i=1;i<NF;i++) if($i=="via"){print $(i+1); exit}}' || true)
  [ -n "$CENTER_GW" ] || die "не удалось определить шлюз локальной сети на $CENTER_BRIDGE (укажите --center-gateway)"
}

install_docker_in_center() {
  local apt=(env DEBIAN_FRONTEND=noninteractive apt-get -q -o Dpkg::Use-Pty=0)
  pct exec "$CENTER_VMID" -- "${apt[@]}" update >/dev/null
  pct exec "$CENTER_VMID" -- "${apt[@]}" install -y --no-install-recommends docker.io docker-compose-v2 openssl curl >/dev/null
  pct exec "$CENTER_VMID" -- systemctl enable --now docker >/dev/null
}

create_center_ct() {
  say "Контейнер центра $CENTER_VMID: $CENTER_IP/$CENTER_PREFIX на $CENTER_BRIDGE, $CENTER_CORES ядра, ${CENTER_MEMORY}МБ, ${CENTER_DISK}ГБ"
  local conf; conf=$(guest_conf "$CENTER_VMID")
  if [ -n "$conf" ]; then
    has_tag "$conf" "$TAG_CENTER" || die "VMID $CENTER_VMID занят чужим гостем (укажите --center-vmid)"
    [ "$(pct status "$CENTER_VMID" | awk '{print $2}')" = running ] || pct start "$CENTER_VMID"
    if pct exec "$CENTER_VMID" -- command -v docker >/dev/null 2>&1; then
      ok "контейнер уже есть и запущен"
      return
    fi
    warn "CT $CENTER_VMID есть, но Docker не установлен (прерванная сборка) — доустанавливаю"
    install_docker_in_center
    ok "Docker установлен и запущен в CT $CENTER_VMID"
    return
  fi
  local ost; ost=$(resolve_ostemplate)
  CENTER_BUILDING=$CENTER_VMID
  pct create "$CENTER_VMID" "$ost" --hostname honeyforge-center --ostype ubuntu --arch amd64 \
    --cores "$CENTER_CORES" --memory "$CENTER_MEMORY" --swap 512 --rootfs "$CENTER_STORAGE:$CENTER_DISK" \
    --net0 "name=eth0,bridge=$CENTER_BRIDGE,ip=$CENTER_IP/$CENTER_PREFIX,gw=$CENTER_GW,type=veth" \
    --nameserver 1.1.1.1 --unprivileged 1 --features nesting=1 --tags "$TAG_CENTER" --onboot 1 \
    --description "HoneyForge: центр, оркестратор, БД (docker compose)" >/dev/null
  ok "CT $CENTER_VMID создан из $ost"
  pct start "$CENTER_VMID"

  local i
  for i in $(seq 60); do
    pct exec "$CENTER_VMID" -- getent hosts archive.ubuntu.com >/dev/null 2>&1 && break
    [ "$i" = 60 ] && die "у контейнера центра нет интернета (шлюз $CENTER_GW на $CENTER_BRIDGE доступен?)"
    sleep 2
  done
  install_docker_in_center
  CENTER_BUILDING=""
  ok "Docker установлен и запущен в CT $CENTER_VMID"
}

deploy_app_source() {
  say "Копирую код приложения в CT $CENTER_VMID"
  { [ -d "$REPO/backend" ] && [ -d "$REPO/frontend" ] && [ -d "$REPO/infra" ]; } \
    || die "рядом со скриптом нет полного репозитория (backend/frontend/infra) — скопируйте его целиком, не только infra/proxmox (см. --help)"
  local tgz; tgz=$(mktemp)
  tar -C "$REPO" --exclude __pycache__ --exclude '*.pyc' --exclude node_modules \
    --exclude frontend/dist --exclude infra/secrets --exclude infra/.env --exclude .venv \
    -czf "$tgz" backend frontend honeymind infra
  pct push "$CENTER_VMID" "$tgz" /tmp/.hf-app.tgz
  rm -f "$tgz"
  pct exec "$CENTER_VMID" -- sh -c 'mkdir -p /opt/honeyforge && tar -xzf /tmp/.hf-app.tgz -C /opt/honeyforge && rm -f /tmp/.hf-app.tgz'
  ok "/opt/honeyforge в CT $CENTER_VMID обновлён"
}

push_center_secrets() {
  say "Ключи оркестратора и переменные Proxmox → CT $CENTER_VMID"
  pct exec "$CENTER_VMID" -- mkdir -p /opt/honeyforge/infra/secrets
  if [ -f "$SECRETS/pve_agent_ed25519" ]; then
    pct push "$CENTER_VMID" "$SECRETS/pve_agent_ed25519" /opt/honeyforge/infra/secrets/pve_agent_ed25519 --perms 600
    rm -f "$SECRETS/pve_agent_ed25519"   # приватный ключ на хосте больше не нужен — теперь он в CT
  fi
  pct push "$CENTER_VMID" "$SECRETS/known_hosts" /opt/honeyforge/infra/secrets/known_hosts --perms 600
  pct push "$CENTER_VMID" "$SECRETS/proxmox.env" /opt/honeyforge/infra/proxmox.env.generated --perms 600
  pct exec "$CENTER_VMID" -- chmod 700 /opt/honeyforge/infra/secrets
  ok "скопированы"
}

write_center_env() {
  if pct exec "$CENTER_VMID" -- test -f /opt/honeyforge/infra/.env; then
    ok "infra/.env в CT $CENTER_VMID уже настроен — не трогаю"
    return
  fi
  say "Генерирую infra/.env в CT $CENTER_VMID (секреты видны только внутри контейнера)"
  local gen; gen=$(mktemp)
  cat > "$gen" <<'SH'
set -eu
cd /opt/honeyforge/infra
HF_SECRET_KEY=$(openssl rand 32 | openssl base64 -A | tr '+/' '-_')
HF_DB_PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9')
ORCH_TOKEN=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9')
HONEYMIND_TOKEN=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9')
{
  echo "HF_SECRET_KEY=$HF_SECRET_KEY"
  echo "HF_DB_PASSWORD=$HF_DB_PASSWORD"
  echo "ORCH_TOKEN=$ORCH_TOKEN"
  echo "HONEYMIND_TOKEN=$HONEYMIND_TOKEN"
  echo "HF_COOKIE_SECURE=false"
  echo "HF_PUBLIC_URL=http://__CENTER_IP__:__CENTER_PORT__"
  grep -E '^(PROXMOX_|PVE_SSH_HOST=)' proxmox.env.generated
} > .env
chmod 600 .env
SH
  sed -i "s/__CENTER_IP__/$CENTER_IP/; s/__CENTER_PORT__/$CENTER_PORT/" "$gen"
  pct push "$CENTER_VMID" "$gen" /tmp/.hf-env.sh --perms 700
  rm -f "$gen"
  pct exec "$CENTER_VMID" -- sh /tmp/.hf-env.sh
  pct exec "$CENTER_VMID" -- rm -f /tmp/.hf-env.sh
  ok "infra/.env готов"
}

compose_up_center() {
  say "Собираю и запускаю docker compose в CT $CENTER_VMID (первый раз — несколько минут)"
  pct exec "$CENTER_VMID" -- sh -c 'cd /opt/honeyforge/infra && docker compose up -d --build'
  local i
  for i in $(seq 90); do
    pct exec "$CENTER_VMID" -- curl -sf "http://127.0.0.1:$CENTER_PORT/api/health" >/dev/null 2>&1 && break
    [ "$i" = 90 ] && die "центр не отвечает на /api/health — смотрите: pct exec $CENTER_VMID -- sh -c 'cd /opt/honeyforge/infra && docker compose logs'"
    sleep 2
  done
  ok "центр отвечает: http://$CENTER_IP:$CENTER_PORT"
}

create_center_admin() {
  if pct exec "$CENTER_VMID" -- test -f /opt/honeyforge/.admin-created; then
    ok "первый администратор уже был создан этим скриптом ранее — пароль не меняю"
    return
  fi
  say "Создаю первого администратора (admin)"
  ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9')
  local tmp; tmp=$(mktemp); printf '%s\n' "$ADMIN_PASSWORD" > "$tmp"
  pct push "$CENTER_VMID" "$tmp" /tmp/.hf-admin-pw --perms 600
  shred -u "$tmp" 2>/dev/null || rm -f "$tmp"
  pct exec "$CENTER_VMID" -- sh -c \
    'cd /opt/honeyforge/infra && docker compose exec -T center python -m app.cli create-admin admin < /tmp/.hf-admin-pw; st=$?; rm -f /tmp/.hf-admin-pw; exit $st'
  pct exec "$CENTER_VMID" -- touch /opt/honeyforge/.admin-created
  ok "пользователь admin создан"
}

setup_admin_tls() {
  [ "$ADMIN_TLS" = 1 ] || { warn "HTTPS для панели выключен (--no-admin-tls) — панель только по http://$CENTER_IP:$CENTER_PORT"; return 0; }
  say "HTTPS для панели на :$ADMIN_TLS_PORT (самоподписанный сертификат, порт $CENTER_PORT не трогаем — канал агентов не страдает)"
  if pct exec "$CENTER_VMID" -- systemctl is-active --quiet honeyforge-tls-admin 2>/dev/null; then
    ok "уже настроено: https://$CENTER_IP:$ADMIN_TLS_PORT/"
    return
  fi
  local script; script=$(mktemp)
  cat > "$script" <<'SH'
set -eu
PORT="$1"; IP="$2"; BACKEND_PORT="$3"
DIR=/etc/honeyforge-tls
mkdir -p "$DIR"
if [ ! -f "$DIR/stunnel.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
    -keyout "$DIR/key.pem" -out "$DIR/cert.pem" -subj "/CN=$IP" -addext "subjectAltName=IP:$IP"
  chmod 600 "$DIR/key.pem"
  cat "$DIR/cert.pem" "$DIR/key.pem" > "$DIR/stunnel.pem"
  chmod 600 "$DIR/stunnel.pem"
fi
command -v stunnel4 >/dev/null 2>&1 || command -v stunnel >/dev/null 2>&1 || {
  DEBIAN_FRONTEND=noninteractive apt-get -q update >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get -q install -y stunnel4 >/dev/null
}
STUNNEL_BIN=$(command -v stunnel4 || command -v stunnel)
mkdir -p /etc/stunnel
cat > /etc/stunnel/honeyforge-admin.conf <<CONF
pid = /run/stunnel-honeyforge-admin.pid
foreground = yes
[honeyforge-admin]
accept = $PORT
connect = 127.0.0.1:$BACKEND_PORT
cert = $DIR/stunnel.pem
CONF
cat > /etc/systemd/system/honeyforge-tls-admin.service <<UNIT
[Unit]
Description=HoneyForge admin HTTPS (:$PORT -> 127.0.0.1:$BACKEND_PORT, самоподписанный, stunnel)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=$STUNNEL_BIN /etc/stunnel/honeyforge-admin.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now honeyforge-tls-admin.service
SH
  pct push "$CENTER_VMID" "$script" /tmp/.hf-admin-tls.sh --perms 755
  rm -f "$script"
  pct exec "$CENTER_VMID" -- sh /tmp/.hf-admin-tls.sh "$ADMIN_TLS_PORT" "$CENTER_IP" "$CENTER_PORT"
  pct exec "$CENTER_VMID" -- rm -f /tmp/.hf-admin-tls.sh
  ok "https://$CENTER_IP:$ADMIN_TLS_PORT/ (сертификат самоподписанный — браузер спросит подтверждение один раз)"
}

cmd_bootstrap() {
  need_tools
  is_ip "$CENTER_IP" || die "укажите --center-ip <свободный IP в локальной сети> — на нём поднимется контейнер центра"
  init_defaults
  init_center_defaults
  is_ip "$PVE_IP" || die "не удалось определить адрес хоста на $WAN_IF (укажите --pve-ip)"
  say "Bootstrap HoneyForge: контейнер центра $CENTER_IP на $CENTER_BRIDGE, хост $NODE, шаблон ловушек $TEMPLATE_ID"
  create_center_ct
  save_state
  deploy_app_source
  provision_host
  push_center_secrets
  write_center_env
  compose_up_center
  create_center_admin
  setup_admin_tls
  save_state

  cat <<EOF

$(say "Готово. HoneyForge развёрнут полностью — хост Proxmox и центр со всем стеком.")
  Панель:  http://$CENTER_IP:$CENTER_PORT
EOF
  [ "$ADMIN_TLS" = 1 ] && echo "  HTTPS:   https://$CENTER_IP:$ADMIN_TLS_PORT/   (самоподписанный сертификат — подтвердить один раз в браузере)"
  if [ -n "$ADMIN_PASSWORD" ]; then
    echo "  Админ:   admin / $ADMIN_PASSWORD   (сохраните — больше не показывается)"
  else
    echo "  Админ:   admin (создан при первом bootstrap, пароль не менялся)"
  fi
  cat <<EOF
  При первом входе: QR в приложении-аутентификаторе (2FA) и резервные коды.
  Дальше: «Профили» → создать профиль ловушки, «Контейнеры» → создать в Proxmox (docs/INSTALL.md, п.5).
  Обновить код после правок: hf-proxmox.sh update-app. Статус: hf-proxmox.sh status.
EOF
}

cmd_update_app() {
  need_tools
  init_defaults
  [ -n "$(guest_conf "$CENTER_VMID")" ] || die "контейнер центра $CENTER_VMID не найден — сначала bootstrap"
  deploy_app_source
  compose_up_center
  ok "Готово."
}

cmd_admin_tls() {
  need_tools
  init_defaults
  [ -n "$(guest_conf "$CENTER_VMID")" ] || die "контейнер центра $CENTER_VMID не найден — сначала bootstrap"
  is_ip "$CENTER_IP" || die "укажите --center-ip <адрес контейнера центра> (тот же, что при bootstrap)"
  ADMIN_TLS=1
  setup_admin_tls
  save_state
}

# ---------- удаление ----------
confirm() {
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "нужно подтверждение: запустите в терминале или добавьте --yes"
  local a; read -r -p "Удалить всё перечисленное? Введите yes: " a
  [ "$a" = yes ] || die "отменено"
}

destroy_guest() {
  local id=$1 kind=$2
  if [ "$kind" = lxc ]; then
    [ "$(pct status "$id" | awk '{print $2}')" = running ] && pct stop "$id"
    pct destroy "$id" --purge 1 --destroy-unreferenced-disks 1
  else
    [ "$(qm status "$id" | awk '{print $2}')" = running ] && qm stop "$id"
    qm destroy "$id" --purge 1 --destroy-unreferenced-disks 1
  fi
}

cmd_uninstall() {
  need_tools
  init_defaults
  local ours=() foreign_on_bridge=() id kind conf
  while read -r id kind conf; do
    if has_tag "$conf" "$TAG" || has_tag "$conf" "$TAG_TPL" || has_tag "$conf" "$TAG_CENTER"; then
      ours+=("$id:$kind:$(awk -F': ' '/^(hostname|name):/ {print $2; exit}' "$conf")")
    elif grep -qE "^net[0-9]+:.*bridge=$BRIDGE(,|\$)" "$conf"; then
      foreign_on_bridge+=("$id")
    fi
  done < <(guests)

  say "Будет удалено с ноды $NODE:"
  if [ ${#ours[@]} -gt 0 ]; then
    for g in "${ours[@]}"; do echo "    - гость ${g%%:*} (${g##*:}) с тегом $TAG/$TAG_TPL/$TAG_CENTER"; done
  else
    echo "    - машин-ловушек, шаблонов и контейнера центра нет"
  fi
  echo "    - пользователь $PVE_USER с токеном, роли $ROLE_TRAPS/$ROLE_TPL, пул $POOL, ACL"
  echo "    - ключ $KEY_COMMENT из $(authorized_keys)"
  echo "    - $CTL, $PKG_DIR"
  if [ ${#foreign_on_bridge[@]} -gt 0 ]; then
    echo "    - мост $BRIDGE НЕ удаляется: к нему подключены чужие гости ${foreign_on_bridge[*]}"
  elif bridge_is_ours; then
    echo "    - мост $BRIDGE и файрвол DMZ ($FW)"
  fi
  [ -n "$STORAGE_ADDED_CONTENT" ] && echo "    - типы содержимого $STORAGE_ADDED_CONTENT у хранилища $STORAGE (если там не осталось дисков)"
  echo "    - $STATE_DIR, $SECRETS"
  confirm

  say "Машины-ловушки и шаблон"
  for g in "${ours[@]}"; do
    id=${g%%:*}; kind=${g#*:}; kind=${kind%%:*}
    if destroy_guest "$id" "$kind" >/dev/null 2>&1; then ok "удалён $id"; else warn "не удалось удалить $id"; fi
  done

  say "Доступ оркестратора"
  local ak; ak=$(authorized_keys)
  if [ -f "$ak" ] && grep -qE " $KEY_COMMENT\$" "$ak"; then
    local tmp; tmp=$(mktemp)
    grep -vE " $KEY_COMMENT\$" "$ak" > "$tmp" || true
    cat "$tmp" > "$ak"; rm -f "$tmp"
    ok "ключ $KEY_COMMENT удалён"
  fi
  if grep -q "^user:$PVE_USER:" "$USER_CFG"; then
    local acl
    for acl in "/pool/$POOL:$ROLE_TRAPS" "/storage/$STORAGE:$ROLE_TRAPS" "/sdn/zones/localnetwork/$BRIDGE:$ROLE_TRAPS" \
               "/nodes/$NODE:PVEAuditor" "/vms/$TEMPLATE_ID:$ROLE_TPL"; do
      pveum acl delete "${acl%%:*}" --users "$PVE_USER" --roles "${acl##*:}" >/dev/null 2>&1 || true
    done
    pveum user delete "$PVE_USER"
    ok "пользователь $PVE_USER и его токены удалены"
  fi
  local r
  for r in "$ROLE_TRAPS" "$ROLE_TPL"; do
    grep -q "^role:$r:" "$USER_CFG" && { pveum role delete "$r"; ok "роль $r удалена"; }
  done
  if grep -q "^pool:$POOL:" "$USER_CFG"; then
    if pveum pool delete "$POOL" 2>/dev/null; then ok "пул $POOL удалён"; else warn "пул $POOL не пуст — оставлен"; fi
  fi
  rm -f "$CTL"; rm -rf "$PKG_DIR"
  ok "hf-agent-ctl и код агента удалены"

  say "Сеть DMZ"
  if [ ${#foreign_on_bridge[@]} -gt 0 ]; then
    warn "мост $BRIDGE оставлен: к нему подключены ${foreign_on_bridge[*]}"
  elif bridge_is_ours; then
    ifdown "$BRIDGE" >/dev/null 2>&1 || true
    cp -a "$IFACES" "$IFACES.bak-hf-$(date +%Y%m%d%H%M%S)"
    remove_bridge_stanza
    ifreload -a
    ok "мост $BRIDGE удалён из $IFACES (бэкап рядом)"
  fi
  [ -x "$FW" ] && { "$FW" down; rm -f "$FW"; }
  rm -f "$FW_CONF" "$SYSCTL"
  ok "файрвол DMZ снят (ip_forward не трогаем — он может быть нужен другим)"

  if [ -n "$STORAGE_ADDED_CONTENT" ] && storage_exists "$STORAGE"; then
    say "Хранилище $STORAGE"
    local left=0 t keep=""
    for t in ${STORAGE_ADDED_CONTENT//,/ }; do
      [ -n "$(pvesm list "$STORAGE" --content "$t" 2>/dev/null | tail -n +2)" ] && left=1
    done
    if [ "$left" = 1 ]; then
      warn "на $STORAGE остались диски гостей — типы $STORAGE_ADDED_CONTENT оставлены"
    else
      for t in $(storage_content "$STORAGE" | tr ',' ' '); do
        [[ ",$STORAGE_ADDED_CONTENT," == *",$t,"* ]] || keep="${keep:+$keep,}$t"
      done
      pvesm set "$STORAGE" --content "$keep"
      ok "типы содержимого возвращены: $keep"
    fi
  fi

  rm -rf "$STATE_DIR" "$SECRETS"
  say "HoneyForge удалён с хоста. Скачанный образ Ubuntu в $OST_STORAGE оставлен (общий)."
}

# ---------- статус ----------
cmd_status() {
  need_tools
  init_defaults
  local mark
  check() { if eval "$2" >/dev/null 2>&1; then mark="\033[32m✓\033[0m"; else mark="\033[31m✗\033[0m"; fi; printf "  $mark %s\n" "$1"; }
  say "HoneyForge на ноде $NODE (центр ${CENTER_IP:-?}:$CENTER_PORT)"
  check "мост $BRIDGE с файрволом DMZ" "bridge_is_ours && ip link show $BRIDGE"
  check "цепочки iptables HFDMZ/HFDMZIN" "iptables -C FORWARD -i $BRIDGE -j HFDMZ && iptables -C INPUT -i $BRIDGE -j HFDMZIN"
  check "NAT $DMZ_NET → $WAN_IF" "iptables -t nat -C POSTROUTING -s $DMZ_NET -o $WAN_IF -j MASQUERADE"
  check "пул $POOL" "grep -q '^pool:$POOL:' $USER_CFG"
  check "роли $ROLE_TRAPS, $ROLE_TPL" "grep -q '^role:$ROLE_TRAPS:' $USER_CFG && grep -q '^role:$ROLE_TPL:' $USER_CFG"
  check "пользователь $PVE_USER и токен $TOKEN_NAME" "grep -q '^token:$PVE_USER!$TOKEN_NAME:' $USER_CFG"
  check "шаблон $TEMPLATE_ID" "c=\$(guest_conf $TEMPLATE_ID) && [ -n \"\$c\" ] && grep -q '^template: 1' \$c && has_tag \$c $TAG_TPL"
  check "$CTL" "test -x $CTL"
  check "код агента $PKG" "test -s $PKG"
  check "ключ оркестратора ($KEY_COMMENT)" "grep -qE ' $KEY_COMMENT\$' \$(authorized_keys)"
  local n=0 id kind conf
  while read -r id kind conf; do has_tag "$conf" "$TAG" && n=$((n + 1)); done < <(guests)
  echo "  машин-ловушек на ноде: $n"
  check "контейнер центра $CENTER_VMID ($CENTER_IP)" "c=\$(guest_conf $CENTER_VMID) && [ -n \"\$c\" ] && has_tag \$c $TAG_CENTER"
  check "центр отвечает на :$CENTER_PORT" "pct exec $CENTER_VMID -- curl -sf http://127.0.0.1:$CENTER_PORT/api/health"
  check "HTTPS панели :$ADMIN_TLS_PORT" "pct exec $CENTER_VMID -- systemctl is-active --quiet honeyforge-tls-admin"
}

case "$CMD" in
  install) cmd_install ;;
  bootstrap) cmd_bootstrap ;;
  update-app) cmd_update_app ;;
  admin-tls) cmd_admin_tls ;;
  uninstall) cmd_uninstall ;;
  status) cmd_status ;;
  update-agent) need_tools; install_agent_pkg ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 1 ;;
esac
