import os
import time

import paramiko


class AgentInstaller:
    """
    Включает и выключает агентов ловушек внутри машин через хост Proxmox.
    Ключ оркестратора на хосте разрешает ровно одну команду — hf-agent-ctl (infra/proxmox/hf-agent-ctl),
    которая сама проверяет, что машина помечена тегом honeyforge.
    """

    def __init__(self, host: str, key_path: str, known_hosts: str | None = None, user: str = "root"):
        self.host, self.key_path, self.known_hosts, self.user = host, key_path, known_hosts, user

    @classmethod
    def from_env(cls) -> "AgentInstaller":
        env = os.environ.get
        return cls(host=env("PVE_SSH_HOST") or env("PROXMOX_HOST", "192.168.1.94"),
                   key_path=env("PVE_SSH_KEY", "/run/hf-secrets/pve_agent_ed25519"),
                   known_hosts=env("PVE_SSH_KNOWN_HOSTS", "/run/hf-secrets/known_hosts"))

    def _run(self, *args: str) -> str:
        client = paramiko.SSHClient()
        if self.known_hosts and os.path.exists(self.known_hosts):
            client.load_host_keys(self.known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())  # чужой хост вместо Proxmox — отказ
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.host, username=self.user, key_filename=self.key_path,
                           look_for_keys=False, allow_agent=False, timeout=15)
            _, out, err = client.exec_command(" ".join(args), timeout=180)
            rc = out.channel.recv_exit_status()
            if rc != 0:
                raise RuntimeError(err.read().decode().strip() or f"hf-agent-ctl: код {rc}")
            return out.read().decode().strip()
        finally:
            client.close()

    def install(self, vmid: int, trap_id: int, center_url: str, token: str, attempts: int = 6) -> None:
        # Сразу после запуска машины systemd внутри ещё поднимается: несколько попыток с паузой
        for i in range(attempts):
            try:
                self._run("install", str(vmid), str(trap_id), center_url, token)
                return
            except RuntimeError as e:
                permanent = any(w in str(e) for w in ("bad ", "not a honeyforge", "template", "not preinstalled"))
                if permanent or i == attempts - 1:
                    raise
                time.sleep(5)

    def remove(self, vmid: int, trap_id: int) -> None:
        self._run("remove", str(vmid), str(trap_id))
