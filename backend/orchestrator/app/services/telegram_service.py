import httpx
import os
import json

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

async def send_alert(event_name: str, attacker_ip: str, properties: dict):
    """
    Отправляет уведомление об атаке в Telegram.
    Библиотека httpx автоматически подхватит прокси (HTTP_PROXY), 
    заданный в окружении.
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
    
    await _send(message)


async def send_threat_alert(event_name: str, attacker_ip: str, verdict: dict):
    """
    Алерт по оценке HoneyMind (threat_score >= порога). Берём только поля из ответа HoneyMind
    (summary собран из шаблонов, без текста атакующего — безопасно показывать в Telegram), а не
    сырой payload события.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    message = (
        f"⚠️ <b>HONEYMIND: ОПАСНОЕ ДЕЙСТВИЕ ({verdict.get('threat_score')}/100)</b>\n\n"
        f"<b>Тип события:</b> {event_name}\n"
        f"<b>IP хакера:</b> {attacker_ip}\n"
        f"<b>Категория:</b> {verdict.get('category')}\n\n"
        f"<b>{verdict.get('summary', '')}</b>"
    )
    await _send(message)


async def _send(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
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
