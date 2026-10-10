import httpx
import os
import json
import html

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
        "parse_mode": "HTML"
    }
    
    proxy_url = os.getenv("TELEGRAM_PROXY")
    
    try:
        async with httpx.AsyncClient(proxy=proxy_url) as client:
            response = await client.post(url, json=payload)
            if response.status_code != 200:
                print(f"❌ Ошибка Telegram (Код {response.status_code}): {response.text}")
            else:
                print("✅ Уведомление успешно отправлено в Telegram!")
    except Exception as e:
        print(f"❌ Ошибка соединения с Telegram: {e}")
