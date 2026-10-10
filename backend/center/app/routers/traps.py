from __future__ import annotations

import shlex

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Event, Profile, Trap, User
from ..schemas import CommandIn, DeployIn, TrapIn, TrapPatch
from ..services import hash_agent_token, new_agent_token, trap_status

router = APIRouter(prefix="/api/traps", tags=["traps"])
operator = auth.require_role("admin", "operator")


def trap_view(t: Trap, settings, events: int = 0) -> dict:
    return {"id": t.id, "name": t.name, "profile_id": t.profile_id, "profile": t.profile.name if t.profile else None,
            "level": t.profile.level if t.profile else None, "enabled": t.enabled, "host": t.host,
            "agent_version": t.agent_version, "status": trap_status(t, settings),
            "last_seen": t.last_seen.isoformat() + "Z" if t.last_seen else None,
            "pending_command": t.pending_command, "events": events, "machine_vmid": t.machine_vmid, "created_at": t.created_at.isoformat() + "Z"}


def _agent(request: Request, action: str, t: Trap, vmid: int | None, token: str | None = None) -> str:
    """Включить/выключить агента ловушки в её машине через оркестратор. Ошибка не роняет основное действие."""
    if not vmid:
        return "no-machine"
    orch = request.app.state.orchestrator
    try:
        if action == "install":
            body = {"trap_id": t.id, "center_url": auth.settings_of(request).public_url.rstrip("/"), "token": token}
            return orch.request("POST", f"/{vmid}/agents", body, timeout=240)["status"]
        orch.request("DELETE", f"/{vmid}/agents/{t.id}", timeout=120)
        return "removed"
    except HTTPException as e:
        return f"error: {e.detail}"


def _get(db: Session, trap_id: int) -> Trap:
    t = db.get(Trap, trap_id)
    if not t:
        raise HTTPException(404, "Ловушка не найдена")
    return t


def _check_profile(db: Session, profile_id: int | None) -> None:
    if profile_id is not None and not db.get(Profile, profile_id):
        raise HTTPException(422, "Профиль не найден")


@router.get("")
def list_traps(request: Request, _: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    settings = auth.settings_of(request)
    counts = dict(db.execute(select(Event.trap_id, func.count()).group_by(Event.trap_id)).all())
    return [trap_view(t, settings, counts.get(t.id, 0)) for t in db.scalars(select(Trap).order_by(Trap.id))]


@router.post("", status_code=201)
def create_trap(body: TrapIn, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    _check_profile(db, body.profile_id)
    token = new_agent_token()
    t = Trap(name=body.name.strip(), profile_id=body.profile_id, machine_vmid=body.machine_vmid,
             token_hash=hash_agent_token(token))
    db.add(t)
    auth.audit(db, user.username, "trap.create", t.name, auth.client_ip(request))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Ловушка с таким именем уже есть")
    agent = _agent(request, "install", t, t.machine_vmid, token)
    view = {**trap_view(t, auth.settings_of(request)), "agent": agent}
    if agent not in ("installed", "queued"):
        view["token"] = token  # агент не включён автоматически: токен показывается один раз для ручной установки
    return view


@router.get("/{trap_id}")
def get_trap(trap_id: int, request: Request, _: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    t = _get(db, trap_id)
    n = db.scalar(select(func.count()).select_from(Event).where(Event.trap_id == t.id)) or 0
    return trap_view(t, auth.settings_of(request), n)


@router.patch("/{trap_id}")
def patch_trap(trap_id: int, body: TrapPatch, request: Request, user: User = Depends(operator),
               db: Session = Depends(get_db)):
    t = _get(db, trap_id)
    if body.name is not None:
        t.name = body.name.strip()
    if body.clear_profile:
        t.profile_id = None
    elif body.profile_id is not None:
        _check_profile(db, body.profile_id)
        t.profile_id = body.profile_id
    if body.enabled is not None:
        t.enabled = body.enabled
    old_vmid, new_token = t.machine_vmid, None
    if body.machine_vmid is not None and body.machine_vmid != t.machine_vmid:
        t.machine_vmid = body.machine_vmid
        new_token = new_agent_token()  # в новой машине — новый токен, старый перестаёт работать
        t.token_hash = hash_agent_token(new_token)
    auth.audit(db, user.username, "trap.update", f"{t.name}: {body.model_dump(exclude_none=True)}",
               auth.client_ip(request))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Ловушка с таким именем уже есть")
    db.refresh(t)
    view = trap_view(t, auth.settings_of(request))
    if new_token:
        _agent(request, "remove", t, old_vmid)
        view["agent"] = _agent(request, "install", t, t.machine_vmid, new_token)
    return view


@router.delete("/{trap_id}", status_code=204)
def delete_trap(trap_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    t = _get(db, trap_id)
    _agent(request, "remove", t, t.machine_vmid)
    auth.audit(db, user.username, "trap.delete", t.name, auth.client_ip(request))
    db.delete(t)
    db.commit()


@router.post("/{trap_id}/command")
def send_command(trap_id: int, body: CommandIn, request: Request, user: User = Depends(operator),
                 db: Session = Depends(get_db)):
    """Команда центр → ловушка. Доставляется агентом при ближайшем опросе."""
    t = _get(db, trap_id)
    t.pending_command = body.command
    auth.audit(db, user.username, "trap.command", f"{t.name}: {body.command}", auth.client_ip(request))
    db.commit()
    return trap_view(t, auth.settings_of(request))


def _render_artifact(kind: str, trap: Trap, token: str, public_url: str) -> str:
    ports = [s["port"] for s in (trap.profile.services if trap.profile else [])]
    if kind == "docker":
        publish = " ".join(f"-p {p}:{p}" for p in ports)
        parts = ["docker run -d", f"--name hf-{trap.name}", "--restart unless-stopped",
                 f"-e HF_CENTER_URL={shlex.quote(public_url)}", f"-e HF_TRAP_TOKEN={shlex.quote(token)}"]
        if publish:
            parts.append(publish)
        parts.append("honeyforge-agent:latest")
        return " \\\n  ".join(parts) + "\n"
    return ("#!/bin/sh\nset -eu\n"
            "# Запускать из каталога, где лежит пакет агента netsvc\n"
            f"export HF_CENTER_URL={shlex.quote(public_url)}\n"
            f"export HF_TRAP_TOKEN={shlex.quote(token)}\n"
            "exec python3 -m netsvc\n")


@router.post("/{trap_id}/agent")
def reinstall_agent(trap_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    """Переустановить агента в машине ловушки: новый токен, доставка через оркестратор. Токен никому не показывается."""
    t = _get(db, trap_id)
    if not t.machine_vmid:
        raise HTTPException(422, "Ловушка не привязана к машине")
    token = new_agent_token()
    t.token_hash = hash_agent_token(token)
    db.commit()
    agent = _agent(request, "install", t, t.machine_vmid, token)
    auth.audit(db, user.username, "trap.agent", f"{t.name}: {agent}", auth.client_ip(request))
    db.commit()
    if agent.startswith("error"):
        raise HTTPException(502, agent.removeprefix("error: "))
    return {"agent": agent}


@router.post("/{trap_id}/deploy")
def deploy_artifact(trap_id: int, body: DeployIn, request: Request, user: User = Depends(operator),
                    db: Session = Depends(get_db)):
    """Оркестратор: выпускает НОВЫЙ токен (старый перестаёт работать) и собирает команду/скрипт развёртывания."""
    t = _get(db, trap_id)
    token = new_agent_token()
    t.token_hash = hash_agent_token(token)
    auth.audit(db, user.username, "trap.deploy", f"{t.name}: {body.kind} (токен перевыпущен)", auth.client_ip(request))
    db.commit()
    settings = auth.settings_of(request)
    return {"kind": body.kind, "artifact": _render_artifact(body.kind, t, token, settings.public_url), "token": token}
