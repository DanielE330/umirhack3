# HoneyMind — AI-аналитика HoneyForge
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY honeymind ./honeymind
COPY main.py train.py ./
# обучающие данные едут в образ вместе с кодом: модель обучается при сборке именно на них
COPY data/train ./data/train
# модель is_human — это просто числа в JSON (не pickle), версия sklearn ей не важна → берём готовую
COPY models/human.json models/human.json.sha256 ./models/

# Модель обучается ПРИ СБОРКЕ: pickle от другой версии scikit-learn загружается криво, а так версия гарантированно та же.
# Вместе с моделью пишется .sha256, которую сервис проверяет при старте.
RUN python train.py && useradd --system --no-create-home honeymind && chmod -R a-w /app/models \
    && mkdir -p /data && chown honeymind /data
# /data — для HONEYMIND_STATE_DB (память ScriptTracker в SQLite); смонтируйте сюда volume, чтобы она переживала пересоздание контейнера
USER honeymind

ENV HONEYMIND_HOST=0.0.0.0 HONEYMIND_PORT=8001
EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
