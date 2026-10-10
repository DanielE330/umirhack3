from proxmoxer import ProxmoxAPI
import ipaddress
import os
import re
import threading
import time

# Оркестратор управляет ТОЛЬКО машинами с этим тегом: прод и остальные гости Proxmox недоступны для него.
TAG = "honeyforge"
VMID_FROM = 1100


class NotOurMachine(Exception):
    """Машины нет или она не помечена тегом honeyforge."""


class ProxmoxManager:
    """
    Управление машинами-ловушками в Proxmox (LXC и QEMU).
    Ловушки клонируются из шаблона в изолированную сеть (DMZ-мост) на отдельное хранилище.
    """

    def __init__(self, host, user, password=None, token_name=None, token_value=None, node=None,
                 verify_ssl=False, port=8006, storage="hdd", bridge="vmbr1", network="10.20.0.0/24",
                 gateway="10.20.0.1", nameserver="1.1.1.1", template_lxc=104, template_kvm=None):
        # Подключение к Proxmox API: API-токен предпочтительнее пароля
        auth = {"token_name": token_name, "token_value": token_value} if token_name else {"password": password}
        self.proxmox = ProxmoxAPI(host, user=user, verify_ssl=verify_ssl, port=port, **auth)
        # Имя ноды берём из Proxmox, если не задано явно
        self.node = node or self.proxmox.nodes.get()[0]["node"]
        self.storage, self.bridge, self.nameserver = storage, bridge, nameserver
        self.network = ipaddress.ip_network(network)
        self.gateway = gateway
        self.templates = {"lxc": template_lxc, "kvm": template_kvm}
        self._lock = threading.Lock()   # выдача VMID и IP не должна гоняться между параллельными созданиями
        self._reserved_ips: set[str] = set()

    @classmethod
    def from_env(cls) -> "ProxmoxManager":
        """Все настройки и секреты — из окружения (PROXMOX_*), в коде их нет."""
        env = os.environ.get
        kvm = env("PROXMOX_TEMPLATE_KVM")
        return cls(
            host=env("PROXMOX_HOST", "192.168.1.94"),
            user=env("PROXMOX_USER", "root@pam"),
            password=env("PROXMOX_PASSWORD"),
            token_name=env("PROXMOX_TOKEN_NAME"),
            token_value=env("PROXMOX_TOKEN_VALUE"),
            node=env("PROXMOX_NODE"),
            port=int(env("PROXMOX_PORT", "8006")),
            storage=env("PROXMOX_STORAGE", "hdd"),
            bridge=env("PROXMOX_BRIDGE", "vmbr1"),
            network=env("PROXMOX_NETWORK", "10.20.0.0/24"),
            gateway=env("PROXMOX_GATEWAY", "10.20.0.1"),
            nameserver=env("PROXMOX_NAMESERVER", "1.1.1.1"),
            template_lxc=int(env("PROXMOX_TEMPLATE_LXC", "104")),
            template_kvm=int(kvm) if kvm else None,
        )

    # ---------- служебное ----------
    def _api(self, kind: str):
        return self.proxmox.nodes(self.node).lxc if kind == "lxc" else self.proxmox.nodes(self.node).qemu

    def _wait(self, upid: str, timeout: int = 900) -> None:
        """Ждём завершения задачи Proxmox (клонирование, запуск) вместо фиксированного sleep."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.proxmox.nodes(self.node).tasks(upid).status.get()
            if status.get("status") == "stopped":
                if status.get("exitstatus") != "OK":
                    raise RuntimeError(f"Задача Proxmox завершилась с ошибкой: {status.get('exitstatus')}")
                return
            time.sleep(2)
        raise TimeoutError("Задача Proxmox не завершилась вовремя")

    @staticmethod
    def _size_gb(disk: str) -> int:
        m = re.search(r"size=(\d+)([GMT])", disk or "")
        if not m:
            return 0
        n, unit = int(m.group(1)), m.group(2)
        return n * 1024 if unit == "T" else n if unit == "G" else max(1, n // 1024)

    def _describe(self, kind: str, guest: dict) -> dict:
        cfg = self._api(kind)(guest["vmid"]).config.get()
        net = cfg.get("net0", "")
        ip = re.search(r"ip=([\d.]+)", net)
        bridge = re.search(r"bridge=([\w.-]+)", net)
        disk = cfg.get("rootfs") if kind == "lxc" else cfg.get("scsi0") or cfg.get("virtio0") or ""
        return {
            "vmid": int(guest["vmid"]), "name": guest.get("name", ""), "type": kind,
            "status": guest.get("status", "unknown"), "lock": guest.get("lock") or None,
            "cores": int(cfg.get("cores", 1)), "memory_mb": int(cfg.get("memory", 0)),
            "disk_gb": self._size_gb(disk), "ip": ip.group(1) if ip else "",
            "bridge": bridge.group(1) if bridge else "", "node": self.node,
            "uptime": int(guest.get("uptime", 0)),
        }

    def _ours(self) -> list[tuple[str, dict]]:
        out = []
        for kind in ("lxc", "kvm"):
            for g in self._api(kind).get():
                if TAG in (g.get("tags") or "").split(";"):
                    out.append((kind, g))
        return out

    def _kind_of(self, vmid: int) -> str:
        for kind, g in self._ours():
            if int(g["vmid"]) == vmid:
                return kind
        raise NotOurMachine(vmid)

    # ---------- чтение ----------
    def list_machines(self) -> list[dict]:
        return sorted((self._describe(kind, g) for kind, g in self._ours()), key=lambda m: m["vmid"])

    # ---------- создание ----------
    def allocate(self) -> tuple[int, str]:
        """Свободный VMID (от 1100) и свободный IP в DMZ."""
        with self._lock:
            used_ids = {int(g["vmid"]) for g in self.proxmox.cluster.resources.get(type="vm")}
            vmid = VMID_FROM
            while vmid in used_ids:
                vmid += 1
            used_ips = {m["ip"] for m in self.list_machines()} | self._reserved_ips | {self.gateway}
            for host in self.network.hosts():
                ip = str(host)
                if int(host) - int(self.network.network_address) >= 10 and ip not in used_ips:
                    self._reserved_ips.add(ip)
                    return vmid, ip
        raise RuntimeError("В DMZ закончились свободные адреса")

    def provision(self, vmid: int, ip: str, name: str, kind: str = "lxc", cores: int = 1,
                  memory_mb: int = 1024, disk_gb: int = 10) -> None:
        """
        Клон шаблона → ресурсы и сеть DMZ → запуск. Долгая операция: вызывается в фоне.
        По ТЗ ловушка по умолчанию: 1 ядро, 1 ГБ ОЗУ, 10 ГБ диска.
        """
        template = self.templates.get(kind)
        if not template:
            raise RuntimeError(f"Шаблон для {kind} не настроен")
        api = self._api(kind)
        try:
            name_key = "hostname" if kind == "lxc" else "name"
            self._wait(api(template).clone.post(newid=vmid, full=1, storage=self.storage, **{name_key: name}))
            net = f"bridge={self.bridge},ip={ip}/{self.network.prefixlen},gw={self.gateway}"
            common = {"cores": cores, "memory": memory_mb, "tags": TAG,
                      "description": "HoneyForge: машина-ловушка (создана оркестратором)"}
            if kind == "lxc":
                api(vmid).config.put(**common, swap=512, nameserver=self.nameserver,
                                     net0=f"name=eth0,{net},type=veth")
                disk_name = "rootfs"
            else:
                api(vmid).config.post(**common, net0=f"virtio,bridge={self.bridge}",
                                      ipconfig0=f"ip={ip}/{self.network.prefixlen},gw={self.gateway}")
                disk_name = "scsi0"
            # Proxmox умеет только увеличивать диск: меньше, чем у шаблона, не сделать
            current = self._size_gb(api(vmid).config.get().get(disk_name, ""))
            if disk_gb > current:
                api(vmid).resize.put(disk=disk_name, size=f"{disk_gb}G")
            self._wait(api(vmid).status.start.post())
        finally:
            with self._lock:
                self._reserved_ips.discard(ip)

    # ---------- управление ----------
    def action(self, vmid: int, action: str) -> None:
        if action not in ("start", "shutdown", "reboot", "stop"):
            raise ValueError(action)
        kind = self._kind_of(vmid)
        self._wait(getattr(self._api(kind)(vmid).status, action).post(), timeout=180)

    def update(self, vmid: int, cores: int | None = None, memory_mb: int | None = None,
               disk_gb: int | None = None, name: str | None = None) -> None:
        kind = self._kind_of(vmid)
        api = self._api(kind)(vmid)
        changes = {k: v for k, v in {"cores": cores, "memory": memory_mb}.items() if v}
        if name:
            changes["hostname" if kind == "lxc" else "name"] = name
        if changes:
            (api.config.put if kind == "lxc" else api.config.post)(**changes)
        if disk_gb:
            disk_name = "rootfs" if kind == "lxc" else "scsi0"
            current = self._size_gb(api.config.get().get(disk_name, ""))
            if disk_gb < current:
                raise ValueError(f"Диск можно только увеличить (сейчас {current} ГБ)")
            if disk_gb > current:
                api.resize.put(disk=disk_name, size=f"{disk_gb}G")

    def destroy(self, vmid: int) -> None:
        kind = self._kind_of(vmid)
        api = self._api(kind)(vmid)
        if api.status.current.get().get("status") == "running":
            self._wait(api.status.stop.post(), timeout=180)
        self._wait(api.delete(purge=1, **{"destroy-unreferenced-disks": 1}), timeout=300)
