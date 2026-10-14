"""Роли и флаги доступа. Системные роли только для чтения; свои роли создаёт и меняет тот, у кого есть roles.manage,
причём выдать роли можно только права, которые есть у него самого."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Role, User
from ..permissions import PERMISSIONS, SYSTEM_ROLES

router = APIRouter(prefix="/api/roles", tags=["roles"])

_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{1,39}$")


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    title: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)
    permissions: list[str] = Field(default_factory=list, max_length=len(PERMISSIONS))

    @field_validator("permissions")
    @classmethod
    def known(cls, v: list[str]) -> list[str]:
        bad = sorted(set(v) - set(PERMISSIONS))
        if bad:
            raise ValueError("неизвестные права: " + ", ".join(bad))
        return sorted(set(v))


class RolePatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = None

    @field_validator("permissions")
    @classmethod
    def known(cls, v):
        return RoleIn.known(v) if v is not None else v


def _view(r: Role, users: int = 0) -> dict:
    return {"id": r.id, "name": r.name, "title": r.title, "description": r.description, "permissions": r.permissions,
            "is_system": r.is_system, "created_by": r.created_by, "users": users}


def _counts(db: Session) -> dict[str, int]:
    return dict(db.execute(select(User.role, func.count()).group_by(User.role)).all())


@router.get("/permissions")
def list_permissions(_: User = Depends(auth.current_user)):
    """Справочник флагов для конструктора ролей: флаг, группа, описание."""
    return [{"flag": f, "group": g, "description": d} for f, (g, d) in PERMISSIONS.items()]


@router.get("")
def list_roles(_: User = Depends(auth.require_perm("users.manage")), db: Session = Depends(get_db)):
    counts = _counts(db)
    return [_view(r, counts.get(r.name, 0)) for r in db.scalars(select(Role).order_by(Role.is_system.desc(), Role.id))]


def _own_perms_cover(db: Session, actor: User, perms: list[str]) -> None:
    if not set(perms) <= auth.permissions_of(db, actor):
        raise HTTPException(403, "Нельзя выдать роли права, которых нет у вас")


@router.post("", status_code=201)
def create_role(body: RoleIn, request: Request, actor: User = Depends(auth.require_perm("roles.manage")),
                db: Session = Depends(get_db)):
    name = body.name.strip().lower()
    if not _SLUG.match(name):
        raise HTTPException(422, "Имя роли: 2–40 символов, a-z, 0-9, дефис, подчёркивание")
    if name in SYSTEM_ROLES or db.scalar(select(Role).where(Role.name == name)):
        raise HTTPException(409, "Роль с таким именем уже есть")
    _own_perms_cover(db, actor, body.permissions)
    role = Role(name=name, title=body.title.strip(), description=body.description.strip(), permissions=body.permissions,
                is_system=False, created_by=actor.username)
    db.add(role)
    auth.audit(db, actor.username, "role.create", f"{name}: {', '.join(body.permissions) or 'без прав'}", auth.client_ip(request))
    db.commit()
    return _view(role)


def _custom(db: Session, role_id: int) -> Role:
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(404, "Роль не найдена")
    if role.is_system:
        raise HTTPException(409, "Системные роли менять и удалять нельзя")
    return role


@router.patch("/{role_id}")
def update_role(role_id: int, body: RolePatch, request: Request,
                actor: User = Depends(auth.require_perm("roles.manage")), db: Session = Depends(get_db)):
    role = _custom(db, role_id)
    if body.permissions is not None:
        _own_perms_cover(db, actor, body.permissions)
        role.permissions = body.permissions
    if body.title is not None:
        role.title = body.title.strip()
    if body.description is not None:
        role.description = body.description.strip()
    # права изменились — сеансы владельцев роли продолжают работать, но с новыми правами (они читаются при каждом запросе)
    auth.audit(db, actor.username, "role.update", f"{role.name}: {body.model_dump(exclude_none=True)}", auth.client_ip(request))
    db.commit()
    return _view(role, _counts(db).get(role.name, 0))


@router.delete("/{role_id}")
def delete_role(role_id: int, request: Request, actor: User = Depends(auth.require_perm("roles.manage")),
                db: Session = Depends(get_db)):
    role = _custom(db, role_id)
    if _counts(db).get(role.name):
        raise HTTPException(409, "Роль назначена пользователям: сначала смените им роль")
    auth.audit(db, actor.username, "role.delete", role.name, auth.client_ip(request))
    db.delete(role)
    db.commit()
    return {"ok": True}
