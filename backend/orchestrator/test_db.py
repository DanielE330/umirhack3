import asyncio
from app.db.database import engine, Base
# Импортируем модели, чтобы SQLAlchemy знала, какие таблицы создавать
from app.models.models import User, Profile, Trap, Event, AuditLog

async def init_db():
    print("Подключаемся к базе данных PostgreSQL...")
    try:
        # Создаем подключение и генерируем таблицы
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("✅ УСПЕХ! Подключение к БД работает, все 5 таблиц успешно созданы!")
    except Exception as e:
        print(f"❌ ОШИБКА подключения к БД: {e}")
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(init_db())
