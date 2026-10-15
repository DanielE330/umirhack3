"""Medium-Interaction Kubernetes API Honeypot (KubeForge Decoy).
Эмулирует Kubernetes API Server (порты 6443, 8443) и Kubelet API.
Перехватывает атаки на кластер:
- Сканирование API (/version, /api, /api/v1, /apis)
- Разведку подов и пространств имён (kubectl get pods, kubectl get namespaces)
- Кражу секретов и токенов ServiceAccount (kubectl get secrets -A) — КРИТИЧЕСКИЙ АЛЕРТ
- Проверку привилегий (kubectl auth can-i --list / SelfSubjectRulesReview)
- Попытки исполнения команд в подах (kubectl exec / pods/exec)
Выдаёт специально токенизированные приманки (Canary Honeytokens).
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import uuid
from email.utils import formatdate
from urllib.parse import parse_qs, urlsplit

from ..emitter import Emitter

log = logging.getLogger("netsvc.kube")
REQUEST_TIMEOUT = 10.0
MAX_HEADER = 16 * 1024

# Поддельные секреты кластера (Honeytokens)
FAKE_SECRETS = {
    "default": [
        {
            "name": "db-prod-credentials",
            "type": "Opaque",
            "data": {
                "username": base64.b64encode(b"prod_admin").decode(),
                "password": base64.b64encode(b"Sup3rS3cr3t_DB_2026!").decode(),
                "database_url": base64.b64encode(b"postgres://prod_admin:Sup3rS3cr3t_DB_2026!@10.20.0.45:5432/finance").decode(),
            },
        },
        {
            "name": "stripe-api-key",
            "type": "Opaque",
            "data": {
                "api_key": base64.b64encode(b"sk_live_51M0neyF0rge_CANARY_TOKEN_7721").decode(),
                "webhook_secret": base64.b64encode(b"whsec_canary_webhook_secret_9981").decode(),
            },
        },
    ],
    "kube-system": [
        {
            "name": "bootstrap-token-canary",
            "type": "bootstrap.kubernetes.io/token",
            "data": {
                "token-id": base64.b64encode(b"canary").decode(),
                "token-secret": base64.b64encode(b"98a72b1c6e4f3a21").decode(),
            },
        },
    ],
    "production": [
        {
            "name": "aws-serviceaccount-token",
            "type": "Opaque",
            "data": {
                "AWS_ACCESS_KEY_ID": base64.b64encode(b"AKIA_CANARY_K8S_EXPLOIT").decode(),
                "AWS_SECRET_ACCESS_KEY": base64.b64encode(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARYK8S").decode(),
            },
        },
    ],
}

# Поддельные поды
FAKE_PODS = [
    {
        "name": "payment-service-6f8d9b74b-2x8pl",
        "namespace": "production",
        "ip": "10.244.1.22",
        "image": "registry.corp.local/finance/payment-service:v2.4.1",
        "status": "Running",
    },
    {
        "name": "auth-gateway-5c744f699-m9zqn",
        "namespace": "default",
        "ip": "10.244.1.23",
        "image": "registry.corp.local/core/auth-gateway:v1.9.0",
        "status": "Running",
    },
    {
        "name": "vault-agent-698f86dfc7-k4k89",
        "namespace": "kube-system",
        "ip": "10.244.0.12",
        "image": "hashicorp/vault-k8s:1.3.1",
        "status": "Running",
    },
]


class KubeTrap:
    def __init__(self, service: dict, config: dict, emitter: Emitter):
        self.service, self.config, self.emitter = service, config, emitter
        self.server: asyncio.AbstractServer | None = None
        self.port_num = service.get("port", 6443)

    async def start(self, host: str = "0.0.0.0") -> None:
        self.server = await asyncio.start_server(self._handle, host, self.port_num)
        log.info("KubeForge Trap запущен на порту %d", self.port)

    @property
    def port(self) -> int:
        if self.server and self.server.sockets:
            return self.server.sockets[0].getsockname()[1]
        return self.port_num

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        sid = uuid.uuid4().hex[:16]
        base = dict(src_ip=peer[0], src_port=peer[1], dst_port=self.port, proto="k8s", session_id=sid)

        # Детекция первичного подключения к K8s
        self.emitter.emit("connect", **base, data={"banner": "Kubernetes API Server v1.29.2"})

        try:
            for _ in range(30):
                req = await asyncio.wait_for(self._read_request(reader), REQUEST_TIMEOUT)
                if req is None:
                    break
                keep = await self._respond(req, writer, base)
                if not keep:
                    break
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_request(self, reader: asyncio.StreamReader) -> dict | None:
        try:
            line = await reader.readline()
            if not line:
                return None
            
            # Если клиент шлёт TLS ClientHello (0x16 0x03), вежливо закрываем или сообщаем
            if line.startswith(b"\x16\x03"):
                return {"is_tls_handshake": True}

            header_text = line.decode("latin1", errors="replace")
            parts = header_text.split()
            if len(parts) < 2:
                return None
            method, raw_path = parts[0].upper(), parts[1]

            headers = {}
            total = len(line)
            while True:
                hline = await reader.readline()
                if not hline or hline in (b"\r\n", b"\n"):
                    break
                total += len(hline)
                if total > MAX_HEADER:
                    return None
                hstr = hline.decode("latin1", errors="replace")
                if ":" in hstr:
                    k, v = hstr.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            body = b""
            clen = int(headers.get("content-length", 0))
            if 0 < clen <= 32 * 1024:
                body = await reader.readexactly(clen)

            return {
                "method": method,
                "path": raw_path,
                "headers": headers,
                "body": body,
                "is_tls_handshake": False,
            }
        except Exception:
            return None

    async def _respond(self, req: dict, writer: asyncio.StreamWriter, base: dict) -> bool:
        if req.get("is_tls_handshake"):
            # Для чистой работы kubectl по HTTP/HTTPS
            return False

        method = req["method"]
        raw_path = req["path"]
        headers = req["headers"]
        body = req["body"]
        auth_hdr = headers.get("authorization", "")
        token = ""
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr.split(" ", 1)[1].strip()

        ua = headers.get("user-agent", "")
        parsed = urlsplit(raw_path)
        path = parsed.path

        # 1. Логируем HTTP-запрос к K8s API
        auth_user = "system:anonymous"
        if token:
            auth_user = f"token:{token[:12]}..."
            self.emitter.emit(
                "auth_attempt",
                **base,
                username=auth_user,
                password=token[:40],
                data={"token": token, "user_agent": ua, "target": path},
            )

        # 2. Обработка эндпоинтов Kubernetes
        status_code = 200
        content_type = "application/json"
        resp_data = {}

        # /version
        if path == "/version":
            resp_data = {
                "major": "1",
                "minor": "29",
                "gitVersion": "v1.29.2",
                "gitCommit": "4b1f7132c88fe82ed442b577f3c87f08968c3405",
                "gitTreeState": "clean",
                "buildDate": "2026-02-14T10:14:28Z",
                "goVersion": "go1.21.7",
                "compiler": "gc",
                "platform": "linux/amd64",
            }
            self.emitter.emit("k8s_recon", **base, command="kubectl version", data={"path": path, "ua": ua})

        # /api /apis
        elif path in ("/api", "/apis"):
            resp_data = {
                "kind": "APIVersions",
                "versions": ["v1"],
                "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": f"10.20.0.15:{self.port}"}],
            }

        # /api/v1 (Core API resources)
        elif path == "/api/v1":
            resp_data = {
                "kind": "APIResourceList",
                "groupVersion": "v1",
                "resources": [
                    {"name": "namespaces", "singularName": "namespace", "namespaced": False, "kind": "Namespace", "verbs": ["get", "list"]},
                    {"name": "pods", "singularName": "pod", "namespaced": True, "kind": "Pod", "verbs": ["get", "list", "watch", "create", "delete"]},
                    {"name": "secrets", "singularName": "secret", "namespaced": True, "kind": "Secret", "verbs": ["get", "list", "watch"]},
                    {"name": "services", "singularName": "service", "namespaced": True, "kind": "Service", "verbs": ["get", "list"]},
                    {"name": "configmaps", "singularName": "configmap", "namespaced": True, "kind": "ConfigMap", "verbs": ["get", "list"]},
                ],
            }

        # /api/v1/namespaces
        elif path in ("/api/v1/namespaces", "/api/v1/namespaces/"):
            items = []
            for ns in ["default", "kube-system", "production", "monitoring", "finance"]:
                items.append({
                    "metadata": {"name": ns, "creationTimestamp": "2026-01-10T08:00:00Z"},
                    "status": {"phase": "Active"},
                })
            resp_data = {"kind": "NamespaceList", "apiVersion": "v1", "items": items}
            self.emitter.emit("k8s_recon", **base, command="kubectl get namespaces", data={"path": path})

        # /api/v1/pods или /api/v1/namespaces/{ns}/pods
        elif "pods" in path:
            items = []
            for p in FAKE_PODS:
                items.append({
                    "metadata": {"name": p["name"], "namespace": p["namespace"], "labels": {"app": p["name"].split("-")[0]}},
                    "spec": {"containers": [{"name": "app", "image": p["image"]}]},
                    "status": {"phase": p["status"], "podIP": p["ip"]},
                })
            resp_data = {"kind": "PodList", "apiVersion": "v1", "items": items}
            self.emitter.emit("k8s_recon", **base, command="kubectl get pods", data={"path": path})

        # /api/v1/secrets или /api/v1/namespaces/{ns}/secrets — КРИТИЧЕСКИЙ ПЕРЕХВАТ!
        elif "secrets" in path:
            all_secrets = []
            for ns, sec_list in FAKE_SECRETS.items():
                for s in sec_list:
                    all_secrets.append({
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {"name": s["name"], "namespace": ns},
                        "type": s["type"],
                        "data": s["data"],
                    })
            resp_data = {"kind": "SecretList", "apiVersion": "v1", "items": all_secrets}

            # Генерируем КРИТИЧЕСКОЕ событие honeytoken
            self.emitter.emit(
                "honeytoken",
                **base,
                command=f"kubectl get secrets -A ({path})",
                username=auth_user,
                data={
                    "attack_type": "k8s_secret_theft",
                    "path": path,
                    "token": token,
                    "user_agent": ua,
                    "exfiltrated_secrets": [s["metadata"]["name"] for s in all_secrets],
                    "threat_score": 98,
                    "category": "credential_theft",
                    "summary": "Нарушитель запросил дамп секретов Kubernetes (kubectl get secrets). Получены канареечные ключи.",
                },
            )

        # kubectl auth can-i (SelfSubjectRulesReview) — говорим атакующему, что ему ВСЁ можно!
        elif "selfsubjectrulesreviews" in path or "selfsubjectaccessreviews" in path:
            resp_data = {
                "kind": "SelfSubjectRulesReview",
                "apiVersion": "authorization.k8s.io/v1",
                "status": {
                    "resourceRules": [
                        {"verbs": ["*"], "apiGroups": ["*"], "resources": ["*"]},
                    ],
                    "nonResourceRules": [
                        {"verbs": ["*"], "nonResourceURLs": ["*"]},
                    ],
                    "incomplete": False,
                },
            }
            self.emitter.emit("k8s_recon", **base, command="kubectl auth can-i --list", data={"granted": "admin"})

        else:
            # Fallback 404 Kubernetes
            status_code = 404
            resp_data = {
                "kind": "Status",
                "apiVersion": "v1",
                "metadata": {},
                "status": "Failure",
                "message": f"the server could not find the requested resource ({method} {path})",
                "reason": "NotFound",
                "code": 404,
            }

        body_bytes = json.dumps(resp_data, ensure_ascii=False, indent=2).encode("utf-8")
        reason = "OK" if status_code == 200 else "Not Found"
        is_close = headers.get("connection", "").lower() == "close"
        headers_out = [
            f"HTTP/1.1 {status_code} {reason}",
            f"Date: {formatdate(time.time(), usegmt=True)}",
            "Server: Kubernetes/v1.29.2",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body_bytes)}",
            f"Connection: {'close' if is_close else 'keep-alive'}",
            "",
            "",
        ]
        writer.write("\r\n".join(headers_out).encode("latin1") + body_bytes)
        await writer.drain()
        return not is_close
