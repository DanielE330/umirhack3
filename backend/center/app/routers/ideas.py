"""Идеи новых типов ловушек: предлагает любой оператор, статус ведёт admin."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import TrapIdea, User, utcnow

router = APIRouter(prefix="/api/ideas", tags=["ideas"])
admin = auth.require_perm("ideas.manage")
MAX_PER_DAY = 20  # защита от заваливания формы одним пользователем


class IdeaIn(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=4000)


class IdeaPatch(BaseModel):
    status: str = Field(pattern="^(new|accepted|rejected|done)$")


def _view(i: TrapIdea) -> dict:
    return {"id": i.id, "author": i.author, "title": i.title, "description": i.description,
            "status": i.status, "created_at": i.created_at.isoformat() + "Z"}


def _get(db: Session, idea_id: int) -> TrapIdea:
    idea = db.get(TrapIdea, idea_id)
    if not idea:
        raise HTTPException(404, "Идея не найдена")
    return idea


@router.get("")
def list_ideas(_: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    return [_view(i) for i in db.scalars(select(TrapIdea).order_by(TrapIdea.id.desc()))]


@router.post("", status_code=201)
def create_idea(body: IdeaIn, request: Request, user: User = Depends(auth.current_user),
                db: Session = Depends(get_db)):
    title = body.title.strip()
    if len(title) < 3:
        raise HTTPException(422, "Название идеи: от 3 символов")
    recent = db.scalar(select(func.count()).select_from(TrapIdea).where(
        TrapIdea.author == user.username, TrapIdea.created_at > utcnow() - timedelta(days=1)))
    if recent >= MAX_PER_DAY:
        raise HTTPException(429, "Слишком много идей за сутки")
    idea = TrapIdea(author=user.username, title=title, description=body.description.strip())
    db.add(idea)
    auth.audit(db, user.username, "idea.create", title, auth.client_ip(request))
    db.commit()
    return _view(idea)


@router.patch("/{idea_id}")
def update_idea(idea_id: int, body: IdeaPatch, request: Request, user: User = Depends(admin),
                db: Session = Depends(get_db)):
    idea = _get(db, idea_id)
    idea.status = body.status
    auth.audit(db, user.username, "idea.update", f"{idea.id}: {body.status}", auth.client_ip(request))
    db.commit()
    return _view(idea)


@router.delete("/{idea_id}", status_code=204)
def delete_idea(idea_id: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    idea = _get(db, idea_id)
    db.delete(idea)
    auth.audit(db, user.username, "idea.delete", str(idea_id), auth.client_ip(request))
    db.commit()
