"""Машины-ловушки в Proxmox: центр проверяет вход и права, пишет аудит и передаёт команду оркестратору."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from .. import auth
from ..db import get_db
from ..models import Event, Trap, User
from ..schemas import MachineIn, MachinePatch
from ..services import trap_status

router = APIRouter(prefix="/api/machines", tags=["machines"])
operator = auth.require_role("admin", "operator")
ACTIONS = {"start", "shutdown", "reboot"}


def orchestrator(request: Request):
    return request.app.state.orchestrator


def _link(machine: dict, traps: list[Trap], settings) -> str:
    """Состояние агента на машине: online, если хоть одна её ловушка на связи."""
    states = [trap_status(t, settings) for t in traps]
    if "online" in states:
        return "online"
    if "offline" in states:
        return "offline"
    return "never"


@router.get("")
def list_machines(request: Request, _: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    settings = auth.settings_of(request)
    machines = orchestrator(request).request("GET", "/")
    traps = db.scalars(select(Trap).options(joinedload(Trap.profile)).where(Trap.machine_vmid.is_not(None))).all()
    counts = dict(db.execute(select(Event.trap_id, func.count()).group_by(Event.trap_id)).all())
    by_vmid: dict[int, list[Trap]] = {}
    for t in traps:
        by_vmid.setdefault(t.machine_vmid, []).append(t)
    for m in machines:
        own = by_vmid.get(m["vmid"], [])
        m["agent"] = _link(m, own, settings)
        last = max((t.last_seen for t in own if t.last_seen), default=None)
        m["last_seen"] = last.isoformat() + "Z" if last else None
        m["traps"] = [{"id": t.id, "name": t.name, "profile": t.profile.name if t.profile else None,
                       "level": t.profile.level if t.profile else None, "enabled": t.enabled,
                       "status": trap_status(t, settings), "events": counts.get(t.id, 0)} for t in own]
    return machines


@router.post("", status_code=202)
def create_machine(body: MachineIn, request: Request, user: User = Depends(operator)):
    payload = {"name": body.name, "type": body.type, "cores": body.cores,
               "memory_mb": body.memory_gb * 1024, "disk_gb": body.disk_gb}
    result = orchestrator(request).request("POST", "/", payload)
    with request.app.state.session_factory() as db:
        auth.audit(db, user.username, "machine.create", f"{body.name} ({body.type} {result.get('vmid')})",
                   auth.client_ip(request))
        db.commit()
    return result


@router.post("/{vmid}/{action}")
def machine_action(vmid: int, action: str, request: Request, user: User = Depends(operator),
                   db: Session = Depends(get_db)):
    if action not in ACTIONS:
        raise HTTPException(404, "Неизвестное действие")
    result = orchestrator(request).request("POST", f"/{vmid}/{action}", timeout=200)
    auth.audit(db, user.username, f"machine.{action}", str(vmid), auth.client_ip(request))
    db.commit()
    return result


@router.put("/{vmid}")
def update_machine(vmid: int, body: MachinePatch, request: Request, user: User = Depends(operator),
                   db: Session = Depends(get_db)):
    payload = {"name": body.name, "cores": body.cores, "disk_gb": body.disk_gb,
               "memory_mb": body.memory_gb * 1024 if body.memory_gb else None}
    result = orchestrator(request).request("PUT", f"/{vmid}", {k: v for k, v in payload.items() if v is not None},
                                           timeout=120)
    auth.audit(db, user.username, "machine.update", f"{vmid}: {body.model_dump(exclude_none=True)}",
               auth.client_ip(request))
    db.commit()
    return result


@router.delete("/{vmid}")
def delete_machine(vmid: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    result = orchestrator(request).request("DELETE", f"/{vmid}", timeout=400)
    traps = db.scalars(select(Trap).where(Trap.machine_vmid == vmid)).all()
    for t in traps:  # ловушки машины уходят вместе с ней
        db.delete(t)
    auth.audit(db, user.username, "machine.delete", f"{vmid} (ловушек: {len(traps)})", auth.client_ip(request))
    db.commit()
    return result
