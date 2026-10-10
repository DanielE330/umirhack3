from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
import os

# Ссылка на подключение берется из переменной окружения (или используется локальная для тестов)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://admin:password123@localhost:5432/honeyforge")

# Создаем движок (echo=True будет выводить SQL-запросы в консоль для отладки)
engine = create_async_engine(DATABASE_URL, echo=False)

# Фабрика сессий для работы с БД
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Базовый класс, от которого мы унаследуем все наши таблицы
Base = declarative_base()

# Функция для получения сессии БД (используется в FastAPI Dependency Injection)
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
