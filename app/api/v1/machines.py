import threading

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import internal_only
from app.schemas.machine import MachineCreate, MachineUpdate
from app.services.proxmox_manager import NotOurMachine, ProxmoxManager

router = APIRouter(dependencies=[Depends(internal_only)])

# Создание машины длится минуты: отдаём ответ сразу, а ход работ держим здесь
JOBS: dict[int, dict] = {}
_manager: ProxmoxManager | None = None


def manager() -> ProxmoxManager:
    global _manager
    if _manager is None:
        try:
            _manager = ProxmoxManager.from_env()
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Proxmox недоступен: {e}")
    return _manager


def _run(vmid: int, ip: str, body: MachineCreate) -> None:
    try:
        manager().provision(vmid, ip, body.name, body.type, body.cores, body.memory_mb, body.disk_gb)
        JOBS.pop(vmid, None)
    except Exception as e:
        JOBS[vmid] = {**JOBS.get(vmid, {}), "state": "error", "error": str(e)}


@router.get("/")
def list_machines():
    """Машины-ловушки (только с тегом honeyforge) + те, что ещё создаются."""
    machines = manager().list_machines()
    seen = {m["vmid"] for m in machines}
    for m in machines:
        if m["vmid"] in JOBS:
            m["job"] = JOBS[m["vmid"]]
    for vmid, job in JOBS.items():
        if vmid not in seen:
            machines.append({"vmid": vmid, "name": job["name"], "type": job["type"], "status": "creating",
                             "ip": job["ip"], "job": job})
    return machines


@router.post("/", status_code=202)
def create_machine(body: MachineCreate):
    if body.type == "kvm" and not manager().templates.get("kvm"):
        raise HTTPException(status_code=422, detail="Шаблон KVM не настроен: доступны только LXC-машины")
    vmid, ip = manager().allocate()
    JOBS[vmid] = {"state": "creating", "name": body.name, "type": body.type, "ip": ip}
    threading.Thread(target=_run, args=(vmid, ip, body), daemon=True).start()
    return {"vmid": vmid, "ip": ip, "status": "creating"}


@router.post("/{vmid}/{action}")
def machine_action(vmid: int, action: str):
    if action not in ("start", "shutdown", "reboot", "stop"):
        raise HTTPException(status_code=404, detail="Unknown action")
    try:
        manager().action(vmid, action)
    except NotOurMachine:
        raise HTTPException(status_code=404, detail="Машина не найдена")
    return {"vmid": vmid, "status": "ok"}


@router.put("/{vmid}")
def update_machine(vmid: int, body: MachineUpdate):
    try:
        manager().update(vmid, body.cores, body.memory_mb, body.disk_gb, body.name)
    except NotOurMachine:
        raise HTTPException(status_code=404, detail="Машина не найдена")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"vmid": vmid, "status": "ok"}


@router.delete("/{vmid}")
def delete_machine(vmid: int):
    if JOBS.get(vmid, {}).get("state") == "creating":
        raise HTTPException(status_code=409, detail="Машина ещё создаётся")
    try:
        manager().destroy(vmid)
    except NotOurMachine:
        if JOBS.pop(vmid, None):  # неудачное создание: просто забываем
            return {"vmid": vmid, "status": "deleted"}
        raise HTTPException(status_code=404, detail="Машина не найдена")
    JOBS.pop(vmid, None)
    return {"vmid": vmid, "status": "deleted"}
