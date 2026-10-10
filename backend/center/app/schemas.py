"""Схемы валидации API: профили ловушек, события телеметрии."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

_PROCESS_NAME = re.compile(r"^[A-Za-z0-9_./ -]{1,40}$")


class Service(BaseModel):
    port: int = Field(ge=1, le=65535)
    proto: Literal["banner", "ssh", "http"] = "banner"
    banner: str = Field(default="", max_length=255)


class DecoyUser(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class Honeytoken(BaseModel):
    type: Literal["file", "url"]
    path: str = Field(min_length=2, max_length=200)
    content: str = Field(default="", max_length=2000)

    @field_validator("path")
    @classmethod
    def absolute(cls, v: str) -> str:
        if not v.startswith("/") or ".." in v:
            raise ValueError("путь должен быть абсолютным и без ..")
        return v


class Decoys(BaseModel):
    hostname: str = Field(default="", pattern=r"^[A-Za-z0-9.-]{0,63}$")  # пусто — настоящее имя машины
    users: list[DecoyUser] = Field(default_factory=list, max_length=20)
    honeytokens: list[Honeytoken] = Field(default_factory=list, max_length=20)
    accept_any_password: bool = True  # medium: пускать с любым паролем (после записи), иначе только приманки


class Logging(BaseModel):
    capture_passwords: bool = True
    capture_payload: bool = True
    max_payload_bytes: int = Field(default=512, ge=0, le=4096)


class Masking(BaseModel):
    beacon_interval: int = Field(default=15, ge=5, le=300)
    jitter: float = Field(default=0.3, ge=0, le=0.9)
    process_name: str = "systemd-journal-helper"

    @field_validator("process_name")
    @classmethod
    def safe_name(cls, v: str) -> str:
        if not _PROCESS_NAME.match(v):
            raise ValueError("имя процесса: до 40 символов, буквы, цифры и _./- ")
        return v


class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=1000)
    level: Literal["low", "medium"]
    services: list[Service] = Field(min_length=1, max_length=10)
    decoys: Decoys = Field(default_factory=Decoys)
    logging: Logging = Field(default_factory=Logging)
    masking: Masking = Field(default_factory=Masking)

    @model_validator(mode="after")
    def consistent(self) -> "ProfileIn":
        ports = [s.port for s in self.services]
        if len(ports) != len(set(ports)):
            raise ValueError("порты сервисов не должны повторяться")
        if self.level == "low" and any(s.proto != "banner" for s in self.services):
            raise ValueError("Low-ловушка умеет только баннеры (proto=banner)")
        return self


class TrapIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    profile_id: int | None = None
    machine_vmid: int | None = Field(default=None, ge=100)


class TrapPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    profile_id: int | None = None
    enabled: bool | None = None
    clear_profile: bool = False
    machine_vmid: int | None = Field(default=None, ge=100)


class MachineIn(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,61}$")
    type: Literal["lxc", "kvm"] = "lxc"
    cores: int = Field(default=1, ge=1, le=32)
    memory_gb: int = Field(default=1, ge=1, le=128)
    disk_gb: int = Field(default=10, ge=1, le=1000)


class MachinePatch(BaseModel):
    name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,61}$")
    cores: int | None = Field(default=None, ge=1, le=32)
    memory_gb: int | None = Field(default=None, ge=1, le=128)
    disk_gb: int | None = Field(default=None, ge=1, le=1000)


class CommandIn(BaseModel):
    command: Literal["restart", "refresh"]


class DeployIn(BaseModel):
    kind: Literal["docker", "script"] = "docker"


class AgentEvent(BaseModel):
    uid: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    ts: float
    type: Literal["connect", "auth_attempt", "command", "http_request", "payload", "honeytoken", "session_end"]
    src_ip: str = Field(default="", max_length=64)
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    proto: str = Field(default="", max_length=16)
    session_id: str = Field(default="", max_length=64)
    username: str = Field(default="", max_length=128)
    password: str = Field(default="", max_length=256)
    command: str = Field(default="", max_length=4000)
    data: dict = Field(default_factory=dict)

    @field_validator("data")
    @classmethod
    def small_data(cls, v: dict) -> dict:
        import json
        if len(json.dumps(v, default=str)) > 8000:
            raise ValueError("data слишком большой")
        return v


class AgentBatch(BaseModel):
    events: list[AgentEvent] = Field(max_length=500)
