import asyncio
import csv
import json
from sqlalchemy import select
from app.db.database import AsyncSessionLocal
from app.models.models import Event

async def export_to_csv():
    print("Подключаемся к БД для выгрузки данных...")
    async with AsyncSessionLocal() as session:
        # Достаем все события из таблицы events
        result = await session.execute(select(Event))
        events = result.scalars().all()
        
    # Записываем в CSV файл
    filename = "ml_dataset.csv"
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "timestamp", "attacker_ip", "event_type", "payload"])
        
        for e in events:
            writer.writerow([
                e.id,
                e.timestamp,
                e.attacker_ip,
                e.event_type,
                json.dumps(e.payload) if e.payload else "{}"
            ])
            
    print(f"✅ Успешно выгружено {len(events)} событий в файл '{filename}'!")
    print("Передайте этот файл ML-инженеру, он сможет открыть его через pandas.read_csv()")

if __name__ == "__main__":
    asyncio.run(export_to_csv())
