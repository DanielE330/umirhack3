"""Скрипт для создания/сброса 5 учётных записей администраторов madrigal1..5 для жюри и экспертов.
Запуск: python seed_madrigal.py [пароль]
"""
import os
import sys
from pathlib import Path

# Добавляем backend/center в sys.path
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "backend" / "center"))

# Если HF_DATABASE_URL не задана и нет psycopg, используем локальный SQLite для dev
if not os.environ.get("HF_DATABASE_URL"):
    try:
        import psycopg
    except ImportError:
        os.environ["HF_DATABASE_URL"] = "sqlite:///./honeyforge.db"

from app.cli import seed_madrigal_users

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    pwd = sys.argv[1] if len(sys.argv) > 1 else "Madrigal2026!"
    print(f"[*] Инициализация админ-аккаунтов для жюри (пароль: {pwd})...")
    seed_madrigal_users(password=pwd)
