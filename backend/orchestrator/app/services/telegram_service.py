import httpx
import os
import json

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

async def send_alert(event_name: str, attacker_ip: str, properties: dict):
    """
    Отправляет уведомление об атаке в Telegram.
    Библиотека httpx автоматически подхватит прокси (HTTP_PROXY), 
    который проставит скрипт Даниэля.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
        
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    # Красиво форматируем детали
    details = json.dumps(properties, indent=2, ensure_ascii=False)
    
    message = (
        f"🚨 <b>НОВАЯ АТАКА В HONEYFORGE!</b>\n\n"
        f"<b>Тип события:</b> {event_name}\n"
        f"<b>IP хакера:</b> {attacker_ip}\n\n"
        f"<b>Детали (Payload):</b>\n<pre>{details}</pre>"
    )
    
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload)
    except Exception as e:
        print(f"Ошибка отправки в Telegram: {e}")
