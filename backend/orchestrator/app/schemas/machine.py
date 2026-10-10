from typing import Literal, Optional

from pydantic import BaseModel, Field

HOSTNAME = r"^[A-Za-z0-9][A-Za-z0-9-]{0,61}$"


class MachineCreate(BaseModel):
    name: str = Field(pattern=HOSTNAME)
    type: Literal["lxc", "kvm"] = "lxc"
    cores: int = Field(default=1, ge=1, le=32)
    memory_mb: int = Field(default=1024, ge=256, le=131072)
    disk_gb: int = Field(default=10, ge=1, le=1000)


class MachineUpdate(BaseModel):
    name: Optional[str] = Field(default=None, pattern=HOSTNAME)
    cores: Optional[int] = Field(default=None, ge=1, le=32)
    memory_mb: Optional[int] = Field(default=None, ge=256, le=131072)
    disk_gb: Optional[int] = Field(default=None, ge=1, le=1000)


class AgentInstall(BaseModel):
    trap_id: int = Field(ge=1)
    center_url: str = Field(pattern=r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$")
    token: str = Field(pattern=r"^hf_[0-9a-f]{64}$")
