from pydantic import BaseModel

class TrapCreate(BaseModel):
    trap_type: str
    image: str
    container_port: int
    host_port: int
