# Контекст сборки — корень репозитория (docker build -f backend/center/Dockerfile .): нужен frontend/

# Веб-интерфейс (React + Vite): собирается здесь, в образ центра попадает только dist/
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY backend/center/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/center/app ./app
COPY --from=web /web/dist ./frontend
ENV HF_STATIC_DIR=/srv/frontend
RUN useradd --system --uid 10001 hf
USER hf

EXPOSE 4000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "4000"]
