from fastapi import APIRouter, HTTPException
from app.services.docker_manager import DockerManager
from app.services.proxmox_manager import ProxmoxManager
from app.schemas.trap import TrapCreate, ProxmoxTrapCreate
import random

router = APIRouter()
docker_manager = DockerManager()

def get_proxmox_manager():
    return ProxmoxManager(
        host="100.64.0.12",
        user="root@pam",
        password="10293847", 
        port=8006
    )

@router.post("/")
def create_trap(trap: TrapCreate):
    try:
        result = docker_manager.deploy_trap(
            trap_type=trap.trap_type,
            image=trap.image,
            container_port=trap.container_port,
            host_port=trap.host_port
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/proxmox")
def create_proxmox_trap(trap: ProxmoxTrapCreate):
    """Эндпоинт для фронтенда: создает реальный контейнер в Proxmox"""
    try:
        manager = get_proxmox_manager()
        vmid = random.randint(2000, 3000)
        result = manager.create_trap_vm(
            vmid=vmid, 
            name=trap.name, 
            template_vmid=trap.template_vmid, 
            is_lxc=True
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/")
def list_traps():
    return docker_manager.list_all_traps()

@router.delete("/{container_id}")
def delete_trap(container_id: str):
    success = docker_manager.remove_trap(container_id)
    if not success:
        raise HTTPException(status_code=404, detail="Trap not found")
    return {"status": "deleted", "container_id": container_id}

@router.post("/{container_id}/stop")
def stop_trap(container_id: str):
    success = docker_manager.stop_trap(container_id)
    if not success:
        raise HTTPException(status_code=404, detail="Trap not found")
    return {"status": "stopped", "container_id": container_id}
