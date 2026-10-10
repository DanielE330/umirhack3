"""Точка входа для Docker/uvicorn:   uvicorn main:app --host 0.0.0.0 --port 8001

Вся логика живёт в пакете honeymind/ (так её можно тестировать и переобучать); этот файл — тонкая обёртка,
чтобы контракт «один main.py с POST /predict» сохранялся.
"""
from honeymind.api import app  # noqa: F401

if __name__ == "__main__":
    import os

    import uvicorn

    uvicorn.run(app, host=os.getenv("HONEYMIND_HOST", "127.0.0.1"), port=int(os.getenv("HONEYMIND_PORT", "8001")))
