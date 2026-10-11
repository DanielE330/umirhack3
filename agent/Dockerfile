# Агент ловушки в контейнере: docker run -e HF_CENTER_URL=… -e HF_TRAP_TOKEN=… -p 22:22 honeyforge-agent:latest
# (команду для конкретной ловушки выдаёт панель: «Подключить агента» → Docker).
FROM python:3.12-slim

WORKDIR /usr/lib/systemd-journal-helper
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p /var/tmp/.cache-netsvc
COPY netsvc ./netsvc

# Порты ловушек (22, 80…) ниже 1024: внутри контейнера работаем от root, наружу порты публикует docker run -p
ENV HF_STATE_DIR=/var/tmp/.cache-netsvc \
    HF_PROCESS_NAME=systemd-journal-helper \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
VOLUME /var/tmp/.cache-netsvc
CMD ["python3", "-W", "ignore", "-m", "netsvc"]
