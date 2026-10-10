import httpx
import os
import json
import html
import asyncio

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

async def send_alert(event_name: str, attacker_ip: str, properties: dict):
    """
    Отправляет уведомление об атаке в Telegram.
    Библиотека httpx автоматически подхватит прокси (HTTP_PROXY),
    заданный в окружении.

    event_name/attacker_ip/properties приходят от атакующего (тип события, IP, введённые команды/
    логины/пароли) и подставляются в HTML-сообщение (parse_mode=HTML) — экранируем, иначе это
    канал HTML-инъекции в Telegram.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    # Красиво форматируем детали
    details = html.escape(json.dumps(properties, indent=2, ensure_ascii=False))

    message = (
        f"🚨 <b>НОВАЯ АТАКА В HONEYFORGE!</b>\n\n"
        f"<b>Тип события:</b> {html.escape(event_name)}\n"
        f"<b>IP хакера:</b> {html.escape(attacker_ip)}\n\n"
        f"<b>Детали (Payload):</b>\n<pre>{details}</pre>"
    )
    
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "reply_markup": {
            "inline_keyboard": [
                [
                    {"text": "❌ Заблокировать IP", "callback_data": f"block_{attacker_ip}"},
                    {"text": "🗑️ Скрыть", "callback_data": "ignore"}
                ]
            ]
        }
    }
    proxy_url = os.getenv("TELEGRAM_PROXY")
    if proxy_url and proxy_url.startswith("socks5h://"):
        proxy_url = proxy_url.replace("socks5h://", "socks5://")
    if not proxy_url:
        proxy_url = None
    
    try:
        async with httpx.AsyncClient(proxy=proxy_url) as client:
            response = await client.post(url, json=payload)
            if response.status_code != 200:
                print(f"❌ Ошибка Telegram (Код {response.status_code}): {response.text}")
            else:
                print("✅ Уведомление успешно отправлено в Telegram!")
    except Exception as e:
        print(f"❌ Ошибка соединения с Telegram: {e}")

async def start_polling():
    """Фоновая задача (long-polling) для получения нажатий кнопок от Telegram"""
    if not TELEGRAM_BOT_TOKEN:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
    proxy_url = os.getenv("TELEGRAM_PROXY")
    if proxy_url and proxy_url.startswith("socks5h://"):
        proxy_url = proxy_url.replace("socks5h://", "socks5://")
    if not proxy_url:
        proxy_url = None
    offset = 0

    print("✅ Запущен Telegram Long-Polling для интерактивных алертов!")
    
    async with httpx.AsyncClient(proxy=proxy_url, timeout=35.0) as client:
        while True:
            try:
                # Long polling: ждем до 30 секунд новые сообщения/нажатия
                resp = await client.get(url, params={"offset": offset, "timeout": 30})
                if resp.status_code != 200:
                    await asyncio.sleep(5)
                    continue
                
                data = resp.json()
                for update in data.get("result", []):
                    offset = update["update_id"] + 1
                    
                    if "callback_query" in update:
                        cb = update["callback_query"]
                        cb_data = cb.get("data", "")
                        cb_id = cb["id"]
                        message_id = cb["message"]["message_id"]
                        
                        # Обработка кнопки "Заблокировать IP"
                        if cb_data.startswith("block_"):
                            ip_to_block = cb_data.split("_")[1]
                            print(f"🛡️ Получена команда блокировки IP {ip_to_block} из Telegram!")
                            
                            # Инициализируем Proxmox прямо перед блокировкой, чтобы не ронять цикл при старте
                            from app.services.proxmox_manager import ProxmoxManager
                            pm = ProxmoxManager.from_env()
                            
                            # Блокируем в Proxmox
                            pm.block_ip(ip_to_block)
                            
                            # Отвечаем телеграму, что кнопка нажата
                            await client.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery", 
                                              json={"callback_query_id": cb_id, "text": f"IP {ip_to_block} ЗАБЛОКИРОВАН!"})
                            
                            # Изменяем сообщение (убираем кнопки и пишем вердикт)
                            await client.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageText", json={
                                "chat_id": TELEGRAM_CHAT_ID,
                                "message_id": message_id,
                                "text": cb["message"]["text"] + f"\n\n🛑 <b>ВЕРДИКТ:</b> IP {ip_to_block} ЗАБЛОКИРОВАН В PROXMOX!",
                                "parse_mode": "HTML",
                                "reply_markup": {"inline_keyboard": []}
                            })
                            
                        # Обработка кнопки "Игнорировать"
                        elif cb_data == "ignore":
                            await client.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery", 
                                              json={"callback_query_id": cb_id, "text": "Алерт скрыт."})
                            await client.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageText", json={
                                "chat_id": TELEGRAM_CHAT_ID,
                                "message_id": message_id,
                                "text": "<i>Алерт проигнорирован и скрыт.</i>",
                                "parse_mode": "HTML",
                                "reply_markup": {"inline_keyboard": []}
                            })
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Ошибка в Telegram Long-Polling: {e}")
                await asyncio.sleep(5)

