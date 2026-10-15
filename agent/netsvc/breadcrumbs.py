"""Digital Breadcrumbs Engine (Умные хлебные крошки).
Вместо изолированных honeypot'ов внедряет матрицу связанных артефактов на хосте:
- Файлы ~/.kube/config с токенизированными канареечными учётными данными
- Записи в /etc/hosts (k8s-master.corp.local, ai-gateway.corp.local)
- Файлы AWS CLI (~/.aws/credentials)
- Правдоподобную историю команд (~/.bash_history) с вызовом приватных хостов
Нарушитель на одном скомпрометированном хосте гарантированно находит тропинки
к остальным ловушкам HoneyForge.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("netsvc.breadcrumbs")

KUBECONFIG_TEMPLATE = """apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: http://10.20.0.15:{kube_port}
  name: honeyforge-k8s-cluster
contexts:
- context:
    cluster: honeyforge-k8s-cluster
    namespace: production
    user: cluster-admin-canary
  name: default-context
current-context: default-context
kind: Config
preferences: {{}}
users:
- name: cluster-admin-canary
  user:
    token: hf_kube_canary_sec_99182
"""

AWS_CREDENTIALS_TEMPLATE = """[default]
aws_access_key_id = AKIA_CANARY_PROD_DEPLOY_771
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARYPROD
region = eu-central-1
"""

BASH_HISTORY_ENTRIES = [
    "ssh root@10.20.0.15 -p 22",
    "kubectl get nodes",
    "kubectl get pods -n production",
    "cat ~/.kube/config",
    "curl -s http://10.20.0.15:{llm_port}/v1/models",
    "mysql -h 10.20.0.15 -u prod_admin -p'Sup3rS3cr3t_DB_2026!' finance",
    "docker ps -a",
    "git pull origin main",
    "systemctl status k8s-agent",
]


def deploy_breadcrumbs(state_dir: str, kube_port: int = 6443, llm_port: int = 8000) -> list[str]:
    """Развёртывает хлебные крошки в файловой системе (в безопасных путях и домашней директории)."""
    planted = []
    home = Path.home()
    root_paths = [home, Path("/root"), Path(state_dir)]

    # 1. Kubeconfig
    kube_content = KUBECONFIG_TEMPLATE.format(kube_port=kube_port)
    for p in root_paths:
        try:
            kdir = p / ".kube"
            kdir.mkdir(parents=True, exist_ok=True)
            kfile = kdir / "config"
            kfile.write_text(kube_content, encoding="utf-8")
            planted.append(str(kfile))
            break
        except Exception:
            continue

    # 2. AWS Credentials
    for p in root_paths:
        try:
            adir = p / ".aws"
            adir.mkdir(parents=True, exist_ok=True)
            afile = adir / "credentials"
            afile.write_text(AWS_CREDENTIALS_TEMPLATE, encoding="utf-8")
            planted.append(str(afile))
            break
        except Exception:
            continue

    # 3. Bash history
    hist_lines = [cmd.format(llm_port=llm_port) for cmd in BASH_HISTORY_ENTRIES]
    for p in root_paths:
        try:
            hfile = p / ".bash_history"
            existing = hfile.read_text(encoding="utf-8", errors="ignore") if hfile.exists() else ""
            to_add = [line for line in hist_lines if line not in existing]
            if to_add:
                with hfile.open("a", encoding="utf-8") as f:
                    f.write("\n" + "\n".join(to_add) + "\n")
                planted.append(str(hfile))
            break
        except Exception:
            continue

    # 4. /etc/hosts (если есть права на запись)
    hosts_entry = "\n10.20.0.15 k8s-master.corp.local ai-gateway.corp.local fake-db.corp.local\n"
    try:
        hosts_file = Path("/etc/hosts")
        if hosts_file.exists() and os.access("/etc/hosts", os.W_OK):
            curr_hosts = hosts_file.read_text(encoding="utf-8", errors="ignore")
            if "k8s-master.corp.local" not in curr_hosts:
                with hosts_file.open("a", encoding="utf-8") as f:
                    f.write(hosts_entry)
                planted.append("/etc/hosts")
    except Exception:
        pass

    log.info("Breadcrumbs Engine развернул приманки: %s", planted)
    return planted
