from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Profile, Trap, User
from ..schemas import ProfileIn

router = APIRouter(prefix="/api/profiles", tags=["profiles"])
operator = auth.require_role("admin", "operator")


def profile_view(p: Profile, traps: int = 0) -> dict:
    return {"id": p.id, "name": p.name, "description": p.description, "level": p.level, "services": p.services,
            "decoys": p.decoys, "logging": p.logging, "masking": p.masking, "traps": traps,
            "created_at": p.created_at.isoformat() + "Z", "updated_at": p.updated_at.isoformat() + "Z"}


def _apply(p: Profile, body: ProfileIn) -> None:
    p.name = body.name.strip()
    p.description = body.description
    p.level = body.level
    p.services = [s.model_dump() for s in body.services]
    p.decoys = body.decoys.model_dump()
    p.logging = body.logging.model_dump()
    p.masking = body.masking.model_dump()


def _get(db: Session, profile_id: int) -> Profile:
    p = db.get(Profile, profile_id)
    if not p:
        raise HTTPException(404, "Профиль не найден")
    return p


@router.get("")
def list_profiles(_: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    counts = dict(db.execute(select(Trap.profile_id, func.count()).group_by(Trap.profile_id)).all())
    return [profile_view(p, counts.get(p.id, 0)) for p in db.scalars(select(Profile).order_by(Profile.id))]


@router.post("", status_code=201)
def create_profile(body: ProfileIn, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    p = Profile()
    _apply(p, body)
    db.add(p)
    auth.audit(db, user.username, "profile.create", p.name, auth.client_ip(request))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Профиль с таким именем уже есть")
    return profile_view(p)


@router.get("/{profile_id}")
def get_profile(profile_id: int, _: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    p = _get(db, profile_id)
    n = db.scalar(select(func.count()).select_from(Trap).where(Trap.profile_id == p.id)) or 0
    return profile_view(p, n)


@router.put("/{profile_id}")
def update_profile(profile_id: int, body: ProfileIn, request: Request, user: User = Depends(operator),
                   db: Session = Depends(get_db)):
    p = _get(db, profile_id)
    _apply(p, body)
    auth.audit(db, user.username, "profile.update", p.name, auth.client_ip(request))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Профиль с таким именем уже есть")
    return profile_view(p)


@router.delete("/{profile_id}", status_code=204)
def delete_profile(profile_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    p = _get(db, profile_id)
    if db.scalar(select(func.count()).select_from(Trap).where(Trap.profile_id == p.id)):
        raise HTTPException(409, "Профиль используется ловушками")
    auth.audit(db, user.username, "profile.delete", p.name, auth.client_ip(request))
    db.delete(p)
    db.commit()
