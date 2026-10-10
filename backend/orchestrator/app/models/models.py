from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, ForeignKey, Enum
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
    
    trap = relationship("Trap")

class AuditLog(Base):
    """Аудит действий админов панели"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False) # например: "deploy_trap", "delete_trap"
    timestamp = Column(DateTime, default=datetime.utcnow)
