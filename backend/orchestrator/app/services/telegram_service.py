import asyncio
import html
import json
import os
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


async def send_alert(event_name: str, attacker_ip: str, properties: dict, chat_ids: Optional[List[str]] = None):
    """
    Отправляет уведомление об атаке в Telegram всем привязанным операторам.
    """
    if not TELEGRAM_BOT_TOKEN:
        return

    # Собираем список адресатов
    targets = list(chat_ids or [])
    if not targets:
        targets = await get_center_subscribers()
    if not targets and TELEGRAM_CHAT_ID:
        targets = [str(TELEGRAM_CHAT_ID)]

    if not targets:
        print("ℹ️ Нет привязанных операторов для рассылки алертов в Telegram.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    proxy_url = get_proxy_url()

    # Форматируем детали
    details = html.escape(json.dumps(properties, indent=2, ensure_ascii=False))
    message = (
        f"🚨 <b>НОВАЯ АТАКА В HONEYFORGE!</b>\n\n"
        f"<b>Тип события:</b> {html.escape(event_name)}\n"
        f"<b>IP хакера:</b> {html.escape(attacker_ip)}\n\n"
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
                        {"text": "❌ Заблокировать IP", "callback_data": f"block_{attacker_ip}"},
                        {"text": "🗑️ Скрыть", "callback_data": "ignore"},
                    ]
                ]
            },
        }
        try:
            async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    print(f"❌ Ошибка Telegram (chat_id={cid}, код {response.status_code}): {response.text}")
                else:
                    print(f"✅ Уведомление успешно отправлено в Telegram (chat_id={cid})")
        except Exception as e:
            print(f"❌ Ошибка соединения с Telegram при отправке на {cid}: {e}")


async def start_polling():
    """Фоновая задача (long-polling) для приёма команд операторов и обработки нажатий кнопок."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    proxy_url = get_proxy_url()

    print(f"🔍 Запуск Telegram сервиса: токен={'[ЗАДАН]' if token else '[НЕ ЗАДАН]'}, прокси={proxy_url or 'напрямую'}", flush=True)

    if not token:
        print("ℹ️ TELEGRAM_BOT_TOKEN не задан в .env, Telegram-бот отключён.", flush=True)
        return

    base_tg = f"https://api.telegram.org/bot{token}"
    offset = 0

    # Проверяем связь с Telegram
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=12.0) as check_client:
            me_resp = await check_client.get(f"{base_tg}/getMe")
            if me_resp.status_code == 200:
                binfo = me_resp.json().get("result", {})
                print(f"🤖 Telegram бот успешно подключен: @{binfo.get('username')} ({binfo.get('first_name')})", flush=True)
            else:
                print(f"❌ Ошибка проверки бота через Telegram API (HTTP {me_resp.status_code}): {me_resp.text}", flush=True)
    except Exception as e:
        print(f"❌ Не удалось достучаться до Telegram API ({proxy_url or 'без прокси'}): {e}", flush=True)

    print("✅ Запущен интерактивный Telegram Long-Polling с поддержкой аутентификации операторов!", flush=True)

    async with httpx.AsyncClient(proxy=proxy_url, timeout=35.0) as tg_client:
        while True:
            try:
                resp = await tg_client.get(f"{base_tg}/getUpdates", params={"offset": offset, "timeout": 30})
                if resp.status_code != 200:
                    print(f"❌ Telegram getUpdates HTTP {resp.status_code}: {resp.text}")
                    await asyncio.sleep(5)
                    continue

                data = resp.json()
                for update in data.get("result", []):
                    offset = update["update_id"] + 1

                    # 1. ОБРАБОТКА ТЕКСТОВЫХ СООБЩЕНИЙ И КОМАНД
                    if "message" in update:
                        msg = update["message"]
                        chat_id = msg["chat"]["id"]
                        text = msg.get("text", "").strip()
                        from_user = msg.get("from", {})
                        tg_username = from_user.get("username")

                        if not text:
                            continue

                        print(f"📩 Telegram сообщение от chat_id={chat_id} (@{tg_username}): {text!r}")

                        # Команда привязки: /start HF-XXXXXX или /link HF-XXXXXX
                        if text.startswith("/start") or text.startswith("/link") or text.startswith("/bind"):
                            parts = text.split(maxsplit=1)
                            if len(parts) > 1 and parts[1].strip():
                                code = parts[1].strip()
                                success, info = await bind_user_by_code(code, chat_id, tg_username)
                                if success:
                                    reply_text = (
                                        f"🎉 <b>Telegram успешно привязан к платформе HoneyForge!</b>\n\n"
                                        f"{info}\n\n"
                                        f"🛡️ Теперь вам будут приходить оперативные алерты об атаках, "
                                        f"и вы можете блокировать IP хакеров прямо отсюда."
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
                                        f"Бот подключен и готов присылать алерты."
                                    )
                                else:
                                    reply_text = (
                                        f"👋 <b>Добро пожаловать в HoneyForge SOC Bot!</b>\n\n"
                                        f"🔒 <i>Бот предназначен для операторов и администраторов платформы HoneyForge.</i>\n\n"
                                        f"<b>Как привязать свой аккаунт:</b>\n"
                                        f"1. Войдите в веб-панель HoneyForge\n"
                                        f"2. В верхнем меню нажмите <b>«📱 Подключить Telegram»</b>\n"
                                        f"3. Отправьте боту полученную команду вида: <code>/link HF-XXXXXX</code>"
                                    )
                            send_res = await tg_client.post(
                                f"{base_tg}/sendMessage",
                                json={"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"},
                            )
                            if send_res.status_code != 200:
                                print(f"❌ Ошибка отправки в Telegram HTTP {send_res.status_code}: {send_res.text}")
                            else:
                                print(f"📤 Ответ успешно отправлен в Telegram chat_id={chat_id}")

                        elif text == "/status":
                            auth_status = await check_user_auth(chat_id)
                            if auth_status.get("authenticated"):
                                reply_text = (
                                    f"🛡️ <b>HoneyForge SOC — Статус</b>\n\n"
                                    f"🟢 <b>Статус:</b> Авторизован\n"
                                    f"👤 <b>Пользователь:</b> {auth_status.get('username')}\n"
                                    f"🔑 <b>Роль:</b> <code>{auth_status.get('role')}</code>\n\n"
                                    f"Вам разрешено получение алертов и блокировка IP в Proxmox."
                                )
                            else:
                                reply_text = (
                                    f"🔒 <b>Вы не авторизованы.</b>\n"
                                    f"Чтобы подключить получение алертов, войдите в панель HoneyForge "
                                    f"и используйте команду <code>/link &lt;код&gt;</code>."
                                )
                            await tg_client.post(
                                f"{base_tg}/sendMessage",
                                json={"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"},
                            )

                        elif text == "/unlink":
                            await unbind_user(chat_id)
                            await tg_client.post(
                                f"{base_tg}/sendMessage",
                                json={
                                    "chat_id": chat_id,
                                    "text": "🔌 <b>Telegram успешно отвязан от вашего аккаунта HoneyForge.</b>",
                                    "parse_mode": "HTML",
                                },
                            )

                        elif text in ("/help", "/info"):
                            reply_text = (
                                f"📖 <b>Команды HoneyForge Bot:</b>\n\n"
                                f"• <code>/status</code> — проверить статус авторизации и роль\n"
                                f"• <code>/link &lt;код&gt;</code> — привязать аккаунт по коду из панели\n"
                                f"• <code>/unlink</code> — отвязать Telegram\n"
                                f"• <code>/help</code> — список команд"
                            )
                            await tg_client.post(
                                f"{base_tg}/sendMessage",
                                json={"chat_id": chat_id, "text": reply_text, "parse_mode": "HTML"},
                            )

                    # 2. ОБРАБОТКА НАЖАТИЙ КНОПОК (CALLBACK QUERY)
                    elif "callback_query" in update:
                        cb = update["callback_query"]
                        cb_data = cb.get("data", "")
                        cb_id = cb["id"]
                        message_id = cb["message"]["message_id"]
                        from_user = cb.get("from", {})
                        from_user_id = from_user.get("id")
                        from_username = from_user.get("username", "неизвестно")

                        # ПРОВЕРКА ПРАВ: разрешать блокировку ТОЛЬКО авторизованным операторам!
                        auth_status = await check_user_auth(from_user_id)
                        if not auth_status.get("authenticated"):
                            await tg_client.post(
                                f"{base_tg}/answerCallbackQuery",
                                json={
                                    "callback_query_id": cb_id,
                                    "text": "⛔ Доступ запрещён! Ваш Telegram не привязан к аккаунту оператора HoneyForge.",
                                    "show_alert": True,
                                },
                            )
                            continue

                        operator_name = auth_status.get("username")
                        operator_mention = f"@{from_username} ({operator_name})"

                        # Кнопка "Заблокировать IP"
                        if cb_data.startswith("block_"):
                            ip_to_block = cb_data.split("_")[1]
                            print(f"🛡️ Команда блокировки IP {ip_to_block} от оператора {operator_name} (tg={from_user_id})")

                            try:
                                from app.services.proxmox_manager import ProxmoxManager
                                pm = ProxmoxManager.from_env()
                                pm.block_ip(ip_to_block)
                                block_status_text = f"🛑 <b>ВЕРДИКТ:</b> IP {ip_to_block} ЗАБЛОКИРОВАН В PROXMOX!"
                            except Exception as ex:
                                print(f"❌ Ошибка блокировки: {ex}")
                                block_status_text = f"⚠️ <b>ВЕРДИКТ:</b> Ошибка блокировки IP в Proxmox ({ex})"

                            await tg_client.post(
                                f"{base_tg}/answerCallbackQuery",
                                json={"callback_query_id": cb_id, "text": f"IP {ip_to_block} ЗАБЛОКИРОВАН!"},
                            )

                            current_text = cb["message"].get("text", "")
                            await tg_client.post(
                                f"{base_tg}/editMessageText",
                                json={
                                    "chat_id": cb["message"]["chat"]["id"],
                                    "message_id": message_id,
                                    "text": f"{current_text}\n\n{block_status_text}\n<i>Оператор: {operator_mention}</i>",
                                    "parse_mode": "HTML",
                                    "reply_markup": {"inline_keyboard": []},
                                },
                            )

                        # Кнопка "Игнорировать / Скрыть"
                        elif cb_data == "ignore":
                            await tg_client.post(
                                f"{base_tg}/answerCallbackQuery",
                                json={"callback_query_id": cb_id, "text": "Алерт скрыт."},
                            )
                            await tg_client.post(
                                f"{base_tg}/editMessageText",
                                json={
                                    "chat_id": cb["message"]["chat"]["id"],
                                    "message_id": message_id,
                                    "text": f"<i>Алерт скрыт оператором {operator_mention}.</i>",
                                    "parse_mode": "HTML",
                                    "reply_markup": {"inline_keyboard": []},
                                },
                            )

            except asyncio.CancelledError:
                break
            except Exception as e:
                import traceback
                print(f"❌ Ошибка в Telegram Long-Polling: {e}")
                traceback.print_exc()
                await asyncio.sleep(5)
