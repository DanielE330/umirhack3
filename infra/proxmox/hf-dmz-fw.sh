#!/bin/sh
# HoneyForge DMZ (vmbr1, 10.20.0.0/24): ловушки не видят домашнюю сеть, оверлеи и сам Proxmox.
# Разрешено: ответы на входящие, канал агента к центру, выход в интернет через NAT.
# Параметры — в /etc/default/hf-dmz (пишет hf-proxmox.sh install), ниже значения по умолчанию.
NET=10.20.0.0/24
CENTER=192.168.1.122   # HLCX (CT 102), центр HoneyForge
CPORT=4000
BRIDGE=vmbr1           # мост DMZ
WAN=vmbr0              # мост с выходом в интернет (NAT)
[ -r /etc/default/hf-dmz ] && . /etc/default/hf-dmz
case "$1" in
up)
  iptables -N HFDMZ 2>/dev/null || iptables -F HFDMZ
  iptables -A HFDMZ -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A HFDMZ -d $NET -j RETURN
  iptables -A HFDMZ -d $CENTER -p tcp --dport $CPORT -j RETURN
  for n in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16; do iptables -A HFDMZ -d $n -j DROP; done
  iptables -C FORWARD -i $BRIDGE -j HFDMZ 2>/dev/null || iptables -I FORWARD 1 -i $BRIDGE -j HFDMZ
  iptables -N HFDMZIN 2>/dev/null || iptables -F HFDMZIN
  iptables -A HFDMZIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A HFDMZIN -d $CENTER -p tcp --dport $CPORT -j RETURN   # центр на самом хосте Proxmox
  iptables -A HFDMZIN -j DROP
  iptables -C INPUT -i $BRIDGE -j HFDMZIN 2>/dev/null || iptables -I INPUT 1 -i $BRIDGE -j HFDMZIN
  iptables -t nat -C POSTROUTING -s $NET -o $WAN -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s $NET -o $WAN -j MASQUERADE
  ;;
down)
  iptables -D FORWARD -i $BRIDGE -j HFDMZ 2>/dev/null; iptables -F HFDMZ 2>/dev/null; iptables -X HFDMZ 2>/dev/null
  iptables -D INPUT -i $BRIDGE -j HFDMZIN 2>/dev/null; iptables -F HFDMZIN 2>/dev/null; iptables -X HFDMZIN 2>/dev/null
  iptables -t nat -D POSTROUTING -s $NET -o $WAN -j MASQUERADE 2>/dev/null
  ;;
esac
exit 0
