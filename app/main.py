from fastapi import FastAPI
from app.api.v1 import traps, telemetry, stats, events

app = FastAPI(title="HoneyForge API", version="1.0.0")

app.include_router(traps.router, prefix="/api/v1/traps", tags=["Traps"])
app.include_router(stats.router, prefix="/api/v1/stats", tags=["Dashboard Stats"])
app.include_router(events.router, prefix="/api/v1/events", tags=["Live Attack Feed"])
app.include_router(telemetry.router, prefix="/api/v1", tags=["Telemetry (Masked)"])

@app.get("/")
def root():
    return {"status": "ok", "message": "HoneyForge API is running"}
