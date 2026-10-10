import threading

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import internal_only
from app.schemas.machine import AgentInstall, MachineCreate, MachineUpdate
from app.services.agent_installer import AgentInstaller
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
    except Exception as e:
        JOBS[vmid] = {**JOBS.get(vmid, {}), "state": "error", "error": str(e)}
        return
    # Агенты ловушек, добавленных, пока машина создавалась, включаем сразу после запуска
    failed = []
    for a in JOBS.get(vmid, {}).get("agents", []):
        try:
            AgentInstaller.from_env().install(vmid, a.trap_id, a.center_url, a.token)
        except Exception as e:
            failed.append(f"ловушка {a.trap_id}: {e}")
    if failed:
        JOBS[vmid] = {**JOBS[vmid], "state": "error", "error": "агент не включён — " + "; ".join(failed), "agents": []}
    else:
        JOBS.pop(vmid, None)


@router.get("/")
def list_machines():
    """Машины-ловушки (только с тегом honeyforge) + те, что ещё создаются."""
    machines = manager().list_machines()
    seen = {m["vmid"] for m in machines}
    for m in machines:
        if m["vmid"] in JOBS:
            m["job"] = {k: v for k, v in JOBS[m["vmid"]].items() if k != "agents"}
    for vmid, job in JOBS.items():
        if vmid not in seen:
            machines.append({"vmid": vmid, "name": job["name"], "type": job["type"], "status": "creating",
                             "ip": job["ip"], "job": {k: v for k, v in job.items() if k != "agents"}})
    return machines


@router.post("/", status_code=202)
def create_machine(body: MachineCreate):
    if body.type == "kvm" and not manager().templates.get("kvm"):
        raise HTTPException(status_code=422, detail="Шаблон KVM не настроен: доступны только LXC-машины")
    vmid, ip = manager().allocate()
    JOBS[vmid] = {"state": "creating", "name": body.name, "type": body.type, "ip": ip}
    threading.Thread(target=_run, args=(vmid, ip, body), daemon=True).start()
    return {"vmid": vmid, "ip": ip, "status": "creating"}


@router.post("/{vmid}/agents")
def install_agent(vmid: int, body: AgentInstall):
    """Включить агента ловушки внутри машины (токен приходит от центра и нигде не сохраняется)."""
    job = JOBS.get(vmid)
    if job and job.get("state") == "creating":
        job.setdefault("agents", []).append(body)
        return {"vmid": vmid, "trap_id": body.trap_id, "status": "queued"}
    try:
        AgentInstaller.from_env().install(vmid, body.trap_id, body.center_url, body.token)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Агент не включён: {e}")
    return {"vmid": vmid, "trap_id": body.trap_id, "status": "installed"}


@router.delete("/{vmid}/agents/{trap_id}")
def remove_agent(vmid: int, trap_id: int):
    job = JOBS.get(vmid)
    if job and job.get("state") == "creating":
        job["agents"] = [a for a in job.get("agents", []) if a.trap_id != trap_id]
        return {"vmid": vmid, "trap_id": trap_id, "status": "dequeued"}
    try:
        AgentInstaller.from_env().remove(vmid, trap_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Агент не выключен: {e}")
    return {"vmid": vmid, "trap_id": trap_id, "status": "removed"}


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
