from pydantic import BaseModel

class TrapCreate(BaseModel):
    trap_type: str
    image: str
    container_port: int
    host_port: int

class ProxmoxTrapCreate(BaseModel):
    name: str
    template_vmid: int = 104
