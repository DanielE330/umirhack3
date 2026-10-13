"""Полноценная закрытая изолированная ловушка базы данных MySQL (FR-A5 / Medium-High).
Реализует бинарный протокол MySQL Wire Protocol (v10 handshake, аутентификация, COM_QUERY),
песочницу изолированных баз данных (SQLite backend), honeytokens и детектор вымогателей (Ransomware).
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from ..emitter import Emitter

log = logging.getLogger("netsvc.mysql")

# Regex для детекции адресов вымогателей и криптовалютных кошельков
BTC_RE = re.compile(r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39})\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RANSOM_KEYWORDS = re.compile(r"\b(ransom|recover|restore|bitcoin|btc|decrypt|wallet|pay|contact|onion|warning|please_read)\b", re.IGNORECASE)

DEFAULT_VERSION = "8.0.36-0ubuntu0.22.04.1"


def make_packet(seq_id: int, payload: bytes) -> bytes:
    """Формирует пакет MySQL с 4-байтовым заголовком (3 байта длины + 1 байт sequence id)."""
    length = len(payload)
    header = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, seq_id & 0xFF])
    return header + payload


def lenenc_int(n: int) -> bytes:
    """Length-encoded integer по спецификации MySQL."""
    if n < 251:
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfc" + n.to_bytes(2, "little")
    elif n <= 0xFFFFFF:
        return b"\xfd" + n.to_bytes(3, "little")
    else:
        return b"\xfe" + n.to_bytes(8, "little")


def lenenc_str(s: str | bytes) -> bytes:
    """Length-encoded string по спецификации MySQL."""
    b = s.encode("utf-8") if isinstance(s, str) else s
    return lenenc_int(len(b)) + b


def ok_packet(seq_id: int, affected_rows: int = 0, last_insert_id: int = 0, status_flags: int = 0x0002) -> bytes:
    """Формирует MySQL OK Packet (0x00)."""
    payload = b"\x00" + lenenc_int(affected_rows) + lenenc_int(last_insert_id) + status_flags.to_bytes(2, "little") + b"\x00\x00"
    return make_packet(seq_id, payload)


def err_packet(seq_id: int, err_code: int, sql_state: str, msg: str) -> bytes:
    """Формирует MySQL ERR Packet (0xFF)."""
    payload = b"\xff" + err_code.to_bytes(2, "little") + b"#" + sql_state.encode("ascii")[:5] + msg.encode("utf-8", "replace")
    return make_packet(seq_id, payload)


def eof_packet(seq_id: int, status_flags: int = 0x0002, warnings: int = 0) -> bytes:
    """Формирует MySQL EOF Packet (0xFE)."""
    payload = b"\xfe" + warnings.to_bytes(2, "little") + status_flags.to_bytes(2, "little")
    return make_packet(seq_id, payload)


def resultset_packets(start_seq: int, column_names: list[str], rows: list[list[Any]]) -> list[bytes]:
    """Формирует последовательность пакетов для MySQL Resultset (columns + eof + rows + eof)."""
    pkts: list[bytes] = []
    # 1. Packet: Column count
    pkts.append(make_packet(start_seq, lenenc_int(len(column_names))))
    seq = start_seq + 1

    # 2. Packets: Column definitions
    for col in column_names:
        col_payload = (
            lenenc_str("def") +
            lenenc_str("") +
            lenenc_str("") +
            lenenc_str("") +
            lenenc_str(col) +
            lenenc_str(col) +
            b"\x0c" +
            (33).to_bytes(2, "little") +      # utf8_general_ci
            (255).to_bytes(4, "little") +     # column length
            b"\xfd" +                         # MYSQL_TYPE_VAR_STRING
            b"\x00\x00" +                     # flags
            b"\x00" +                         # decimals
            b"\x00\x00"                       # filler
        )
        pkts.append(make_packet(seq, col_payload))
        seq += 1

    # 3. Packet: EOF after column definitions
    pkts.append(eof_packet(seq))
    seq += 1

    # 4. Packets: Row data
    for row in rows:
        row_payload = b"".join(lenenc_str(str(val) if val is not None else "") for val in row)
        pkts.append(make_packet(seq, row_payload))
        seq += 1

    # 5. Packet: EOF after rows
    pkts.append(eof_packet(seq))
    return pkts


class MysqlTrap:
    """
    Изолированная закрытая ловушка MySQL.
    Отвечает на порту 3306, собирает попытки авторизации, команды, SQL-инъекции,
    выдаёт правдоподобные таблицы с приманками (honeytokens) и фиксирует атаки вымогателей.
    """

    def __init__(self, service: dict, config: dict, emitter: Emitter, state_dir: str = "."):
        self.service = service
        self.config = config
        self.emitter = emitter
        self.state_dir = Path(state_dir)
        self.server: asyncio.AbstractServer | None = None
        self._thread_id = 1000

        # Читаем параметры из профиля
        decoys = config.get("decoys", {})
        self.accept_any = decoys.get("accept_any_password", True)
        self.users = {(u["username"], u["password"]) for u in decoys.get("users", [])}
        self.honeytokens = decoys.get("honeytokens", [])
        self.version = service.get("banner") or DEFAULT_VERSION

        # Инициализируем локальную изолированную БД песочницы (SQLite)
        self._db_path = self.state_dir / "mysql_sandbox.sqlite"
        self._init_sandbox_db()

    def _init_sandbox_db(self) -> None:
        """Создаёт изолированную БД с правдоподобными таблицами и приманками."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL,
                        api_key TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS orders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        customer TEXT NOT NULL,
                        amount REAL NOT NULL,
                        card_last4 TEXT NOT NULL,
                        status TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS system_config (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)

                # Проверяем наличие записей в users
                count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                if count == 0:
                    conn.executemany("""
                        INSERT INTO users (username, email, password_hash, role, api_key)
                        VALUES (?, ?, ?, ?, ?)
                    """, [
                        ("admin", "admin@corp-local.internal", "$2y$12$K8yH.vLwKx5V3oT0e6F2z.1iJ4v3w2", "superadmin", "sk_live_prod_99f2b84291"),
                        ("cfo_backup", "finance@corp-local.internal", "$2y$12$N9xJ.wMwLx6W4pU1f7G3a.2jK5w4x3", "executive", "sk_live_fin_88a1c73180"),
                        ("support", "helpdesk@corp-local.internal", "$2y$12$P0yK.xNxMx7X5qV2g8H4b.3kL6x5y4", "operator", "sk_test_dev_77b0d62070"),
                    ])
                    conn.executemany("""
                        INSERT INTO orders (customer, amount, card_last4, status)
                        VALUES (?, ?, ?, ?)
                    """, [
                        ("Acme Corp", 12450.00, "4242", "completed"),
                        ("Global Logistics", 8900.50, "5555", "processing"),
                        ("CyberSec Solutions", 43200.00, "3782", "completed"),
                    ])
                    conn.executemany("""
                        INSERT INTO system_config (key, value)
                        VALUES (?, ?)
                    """, [
                        ("aws_backup_bucket", "s3://corp-db-backups-secure-2024/"),
                        ("encryption_algo", "AES-256-GCM"),
                        ("maintenance_window", "Sun 02:00-04:00 UTC"),
                    ])
        finally:
            conn.close()

    async def start(self, host: str = "0.0.0.0") -> None:
        port = self.service.get("port", 3306)
        self.server = await asyncio.start_server(self._handle_client, host, port)
        log.info("MySQL trap listening on %s:%s", host, port)

    @property
    def port(self) -> int:
        return self.server.sockets[0].getsockname()[1] if self.server else self.service.get("port", 3306)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        sid = uuid.uuid4().hex[:16]
        dst_port = self.service.get("port", 3306)
        base = dict(src_ip=peer[0], src_port=peer[1], dst_port=dst_port, proto="mysql", session_id=sid)

        # 1. Фиксируем соединение
        self.emitter.emit("connect", **base)
        self._thread_id += 1
        thread_id = self._thread_id

        # Случайная 20-байтовая соль для аутентификации
        salt = os.urandom(20)

        try:
            # 2. Отправка Initial Handshake Packet (Protocol 10)
            handshake_payload = self._build_handshake_packet(thread_id, salt)
            writer.write(make_packet(0, handshake_payload))
            await writer.drain()

            # 3. Чтение ответа клиента (Handshake Response 41)
            resp_header = await reader.readexactly(4)
            resp_len = resp_header[0] | (resp_header[1] << 8) | (resp_header[2] << 16)
            resp_seq = resp_header[3]
            resp_payload = await reader.readexactly(resp_len)

            username, password_repr, db_name = self._parse_handshake_response(resp_payload)

            # Проверка авторизации
            # Реалистичная пауза проверки пароля
            await asyncio.sleep(random.uniform(0.05, 0.15))
            auth_ok = self.accept_any or (username, password_repr) in self.users or any(u == username for u, _ in self.users)

            self.emitter.emit("auth_attempt", **base, username=username, password=password_repr)

            if not auth_ok:
                err_msg = f"Access denied for user '{username}'@'{peer[0]}' (using password: YES)"
                writer.write(err_packet(resp_seq + 1, 1045, "28000", err_msg))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                self.emitter.emit("session_end", **base)
                return

            # Отправляем OK Packet об успешном входе
            writer.write(ok_packet(resp_seq + 1))
            await writer.drain()

            # 4. Основной цикл обработки команд (COM_QUERY, COM_INIT_DB, COM_PING, COM_QUIT)
            current_db = db_name or "production_db"

            while True:
                try:
                    cmd_header = await asyncio.wait_for(reader.readexactly(4), timeout=180.0)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                cmd_len = cmd_header[0] | (cmd_header[1] << 8) | (cmd_header[2] << 16)
                cmd_seq = cmd_header[3]
                cmd_payload = await reader.readexactly(cmd_len)
                if not cmd_payload:
                    break

                cmd_type = cmd_payload[0]

                # 0x01 = COM_QUIT
                if cmd_type == 0x01:
                    break

                # 0x0E = COM_PING
                elif cmd_type == 0x0E:
                    writer.write(ok_packet(cmd_seq + 1))
                    await writer.drain()

                # 0x02 = COM_INIT_DB (USE db_name)
                elif cmd_type == 0x02:
                    current_db = cmd_payload[1:].decode("utf-8", "replace").strip()
                    self.emitter.emit("command", **base, username=username, command=f"USE {current_db}")
                    writer.write(ok_packet(cmd_seq + 1))
                    await writer.drain()

                # 0x04 = COM_FIELD_LIST
                elif cmd_type == 0x04:
                    writer.write(eof_packet(cmd_seq + 1))
                    await writer.drain()

                # 0x03 = COM_QUERY
                elif cmd_type == 0x03:
                    query_text = cmd_payload[1:].decode("utf-8", "replace").strip()

                    # Фиксируем команду в событиях
                    self.emitter.emit("command", **base, username=username, command=query_text,
                                      data={"db": current_db, "proto": "mysql"})

                    # Проверка на вымогателей (Ransomware detection)
                    self._check_ransomware(query_text, base, username)

                    # Реалистичная задержка СУБД (10-40 мс)
                    await asyncio.sleep(random.uniform(0.01, 0.04))

                    # Обработка запроса и формирование ответа
                    packets = self._execute_query(query_text, current_db, base, username)
                    for pkt in packets:
                        writer.write(pkt)
                    await writer.drain()

                else:
                    # Неизвестная команда -> возвращаем OK или generic error
                    writer.write(ok_packet(cmd_seq + 1))
                    await writer.drain()

        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            self.emitter.emit("session_end", **base)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _build_handshake_packet(self, thread_id: int, salt: bytes) -> bytes:
        """Собирает начальный Handshake Packet v10."""
        ver_bytes = self.version.encode("utf-8") + b"\x00"
        salt1 = salt[:8]
        salt2 = salt[8:] + b"\x00"

        # Capabilities: CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG |
        # CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 | CLIENT_INTERACTIVE |
        # CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
        cap_lower = 0xF7FF
        cap_upper = 0x81FF

        payload = (
            b"\x0a" +                                    # protocol version 10
            ver_bytes +                                  # server version string
            thread_id.to_bytes(4, "little") +           # connection thread id
            salt1 +                                      # auth plugin data part 1 (8 bytes)
            b"\x00" +                                    # filter byte
            cap_lower.to_bytes(2, "little") +           # capability flags lower
            b"\x21" +                                    # character set: utf8_general_ci (33)
            (0x0002).to_bytes(2, "little") +            # server status: autocommit
            cap_upper.to_bytes(2, "little") +           # capability flags upper
            bytes([len(salt) + 1]) +                     # length of auth plugin data (21)
            b"\x00" * 10 +                               # reserved (10 bytes)
            salt2 +                                      # auth plugin data part 2 (12 bytes + 0x00)
            b"mysql_native_password\x00"                 # auth plugin name
        )
        return payload

    def _parse_handshake_response(self, payload: bytes) -> tuple[str, str, str]:
        """Разбирает ответ клиента Handshake Response 41."""
        if len(payload) < 32:
            return "unknown", "", ""
        try:
            # Смещение: 4 (caps) + 4 (max packet) + 1 (charset) + 23 (reserved) = 32
            idx = 32
            # Читаем null-terminated username
            null_pos = payload.find(b"\x00", idx)
            if null_pos != -1:
                username = payload[idx:null_pos].decode("utf-8", "replace")
                idx = null_pos + 1
            else:
                username = "root"

            # Читаем длину пароля / scramble data
            password_repr = ""
            if idx < len(payload):
                auth_len = payload[idx]
                idx += 1
                if idx + auth_len <= len(payload):
                    auth_data = payload[idx:idx + auth_len]
                    password_repr = auth_data.hex() if auth_data else ""
                    idx += auth_len

            # Читаем database name, если указано
            db_name = ""
            if idx < len(payload):
                db_null = payload.find(b"\x00", idx)
                if db_null != -1:
                    db_name = payload[idx:db_null].decode("utf-8", "replace")

            return username or "root", password_repr, db_name
        except Exception:
            return "root", "", ""

    def _check_ransomware(self, query: str, base: dict, username: str) -> None:
        """Детектирует попытки вымогательства (Ransomware bots: дроп базы и требование выкупа в BTC)."""
        btc_match = BTC_RE.search(query)
        xmr_match = XMR_RE.search(query)
        email_match = EMAIL_RE.search(query)
        keyword_match = RANSOM_KEYWORDS.search(query)

        upper = query.upper()
        is_drop = "DROP DATABASE" in upper or "DROP TABLE" in upper or "TRUNCATE" in upper

        if (btc_match or xmr_match) and (keyword_match or is_drop):
            crypto = btc_match.group(0) if btc_match else (xmr_match.group(0) if xmr_match else "")
            email = email_match.group(0) if email_match else ""
            log.warning("Ransomware attack detected from %s: crypto=%s email=%s", base.get("src_ip"), crypto, email)
            self.emitter.emit("payload", **base, username=username, command=f"ransomware_note:{crypto}",
                              data={
                                  "category": "ransomware",
                                  "threat_score": 95,
                                  "crypto_address": crypto,
                                  "contact_email": email,
                                  "ransom_query": query[:1000],
                              })
        elif "PLEASE_READ" in upper or "RESTORE_DATA" in upper or "RECOVER_DATABASE" in upper:
            self.emitter.emit("payload", **base, username=username, command=query[:80],
                              data={"category": "ransomware", "threat_score": 90, "ransom_query": query[:1000]})

    def _execute_query(self, query: str, current_db: str, base: dict, username: str) -> list[bytes]:
        """Обрабатывает SQL-запрос, обращается к песочнице SQLite и возвращает MySQL-пакеты."""
        q = query.strip().rstrip(";").strip()
        upper = q.upper()

        # 1. Системные переменные и служебные функции
        if upper in ("SELECT @@VERSION", "SELECT VERSION()", "SELECT @@GLOBAL.VERSION"):
            return resultset_packets(1, ["VERSION()"], [[self.version]])

        if upper.startswith("SELECT @@VERSION_COMMENT") or "VERSION_COMMENT" in upper:
            return resultset_packets(1, ["@@version_comment"], [["Ubuntu"]])

        if upper in ("SELECT DATABASE()", "SELECT SCHEMA()"):
            return resultset_packets(1, ["DATABASE()"], [[current_db]])

        if upper in ("SELECT USER()", "SELECT CURRENT_USER()"):
            return resultset_packets(1, ["USER()"], [[f"{username}@localhost"]])

        if upper.startswith("SELECT @@") and "MAX_ALLOWED_PACKET" in upper:
            return resultset_packets(1, ["@@max_allowed_packet"], [[67108864]])

        # 2. SHOW DATABASES / SHOW SCHEMAS
        if upper in ("SHOW DATABASES", "SHOW SCHEMAS"):
            dbs = [
                ["information_schema"],
                ["mysql"],
                ["performance_schema"],
                ["sys"],
                ["production_db"],
                ["billing_records"],
            ]
            return resultset_packets(1, ["Database"], dbs)

        # 3. SHOW TABLES
        if upper.startswith("SHOW TABLES"):
            tables = [
                ["users"],
                ["orders"],
                ["system_config"],
                ["audit_logs"],
            ]
            return resultset_packets(1, [f"Tables_in_{current_db}"], tables)

        # 4. Honeytokens в запросах (например, чтение конфигов или приватных ключей)
        if "USERS" in upper or "SYSTEM_CONFIG" in upper or "PASSWORD" in upper or "API_KEY" in upper:
            self.emitter.emit("honeytoken", **base, username=username, command=q,
                              data={"honeytoken": True, "table": "users", "query": q})

        # 5. Выполнение DDL / DML в изолированной SQLite-песочнице
        try:
            conn = sqlite3.connect(self._db_path)
            try:
                # Адаптация некоторых конструкций MySQL под SQLite
                sqlite_q = self._adapt_to_sqlite(q)
                cur = conn.cursor()
                cur.execute(sqlite_q)

                if cur.description:
                    col_names = [d[0] for d in cur.description]
                    rows = cur.fetchall()
                    return resultset_packets(1, col_names, rows)
                else:
                    conn.commit()
                    affected = cur.rowcount if cur.rowcount >= 0 else 1
                    return [ok_packet(1, affected_rows=affected)]
            finally:
                conn.close()
        except sqlite3.Error as e:
            # Для CREATE / DROP / UPDATE при синтаксических несовпадениях с SQLite возвращаем правдоподобный OK,
            # чтобы атакующий или бот думал, что операция удалась
            if upper.startswith(("CREATE", "DROP", "ALTER", "INSERT", "UPDATE", "DELETE", "SET", "FLUSH")):
                return [ok_packet(1, affected_rows=1)]
            # Для некорректных SELECT отдаём ошибку MySQL
            return [err_packet(1, 1064, "42000", f"You have an error in your SQL syntax near '{q[:40]}': {e}")]

    def _adapt_to_sqlite(self, q: str) -> str:
        """Небольшая адаптация запросов из диалекта MySQL в SQLite для безопасного исполнения."""
        # Удаляем специфичные для MySQL подсказки и бэктики
        s = q.replace("`", "")
        # LIMIT a, b -> LIMIT b OFFSET a
        s = re.sub(r"LIMIT\s+(\d+)\s*,\s*(\d+)", r"LIMIT \2 OFFSET \1", s, flags=re.IGNORECASE)
        return s
