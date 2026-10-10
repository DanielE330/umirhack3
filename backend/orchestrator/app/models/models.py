from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, ForeignKey, Enum, Float
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.db.database import Base

class InteractionLevel(str, enum.Enum):
    low = "low"
    high = "high"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

class Profile(Base):
    """Шаблоны ловушек (конфиги)"""
    __tablename__ = "profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    interaction_level = Column(Enum(InteractionLevel), nullable=False)
    image_or_template = Column(String, nullable=False) # ID шаблона Proxmox или имя Docker image
    config_json = Column(JSON, nullable=True) # Доп. настройки (порты, ОЗУ и тд)

class Trap(Base):
    """Собственно запущенные ловушки"""
    __tablename__ = "traps"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    ip_address = Column(String, nullable=True)
    status = Column(String, default="deploying") # deploying, running, stopped
    profile_id = Column(Integer, ForeignKey("profiles.id"))
    
    profile = relationship("Profile")

class Event(Base):
    """Логи атак хакеров"""
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    trap_id = Column(Integer, ForeignKey("traps.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    attacker_ip = Column(String, index=True)
    event_type = Column(String, index=True) # ssh_login, web_exploit, command_executed
    payload = Column(JSON) # JSON с полной информацией (введенный пароль, скачанный вирус и т.д.)
    session_id = Column(String, index=True, nullable=True) # для группировки событий одной сессии (HoneyMind /session)

    # Оценка HoneyMind (app/services/honeymind_client.py, app/services/scoring.py).
    # NULL, пока фоновая оценка не завершилась (сервис недоступен/таймаут) — это нормальное состояние, не ошибка.
    threat_score = Column(Integer, nullable=True, index=True)
    category = Column(String, nullable=True)
    needs_review = Column(Boolean, nullable=True, index=True)
    honeymind_result = Column(JSON, nullable=True) # полный ответ /predict (matched_rules, mitre, summary и т.д.)

    trap = relationship("Trap")


class SessionAssessment(Base):
    """Итог оценки сессии атакующего через HoneyMind /session («человек или бот»)."""
    __tablename__ = "session_assessments"

    session_id = Column(String, primary_key=True)
    attacker_ip = Column(String, index=True, nullable=True)
    is_human = Column(Boolean, nullable=True)
    human_probability = Column(Float, nullable=True)
    human_method = Column(String, nullable=True)
    human_reason = Column(String, nullable=True)
    script_seen_before = Column(Integer, nullable=True)
    result = Column(JSON, nullable=True) # полный ответ /session
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(Base):
    """Аудит действий админов панели"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False) # например: "deploy_trap", "delete_trap"
    timestamp = Column(DateTime, default=datetime.utcnow)
