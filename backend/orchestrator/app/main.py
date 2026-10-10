from fastapi import FastAPI
from app.api.v1 import traps, telemetry, stats, machines, events, notify

app = FastAPI(title="HoneyForge API", version="1.0.0")


@app.on_event("startup")
async def create_tables():
    # Таблицы телеметрии и статистики создаются при старте, а не отдельным скриптом
    from app.db.database import Base, engine
    from app.models import models  # noqa: F401 — регистрирует модели
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

app.include_router(traps.router, prefix="/api/v1/traps", tags=["Traps"])
app.include_router(machines.router, prefix="/api/v1/machines", tags=["Machines (Proxmox)"])
app.include_router(notify.router, prefix="/api/v1/notify", tags=["Notifications"])
app.include_router(events.router, prefix="/api/v1/events", tags=["Live Attack Feed"])
app.include_router(stats.router, prefix="/api/v1/stats", tags=["Dashboard Stats"])
app.include_router(telemetry.router, prefix="/api/v1", tags=["Telemetry (Masked)"])

@app.get("/")
def root():
    return {"status": "ok", "message": "HoneyForge API is running"}
