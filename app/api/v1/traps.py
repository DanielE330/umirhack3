from fastapi import APIRouter, Depends, HTTPException
from app.api.deps import internal_only
from app.services.docker_manager import DockerManager
from app.services.proxmox_manager import ProxmoxManager
from app.schemas.trap import TrapCreate, ProxmoxTrapCreate

router = APIRouter(dependencies=[Depends(internal_only)])
_docker: DockerManager | None = None


def docker_manager() -> DockerManager:
    """Docker нужен только Docker-ловушкам: без сокета остальной сервис (Proxmox) работает."""
    global _docker
    if _docker is None:
        try:
            _docker = DockerManager()
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Docker недоступен: {e}")
    return _docker

def get_proxmox_manager():
    # Доступ к Proxmox только из окружения (PROXMOX_*), секреты в коде не храним
    return ProxmoxManager.from_env()

@router.post("/")
def create_trap(trap: TrapCreate):
    try:
        result = docker_manager().deploy_trap(
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
        # Создаём так же, как /api/v1/machines: в DMZ, на хранилище ловушек, с тегом honeyforge
        manager = get_proxmox_manager()
        vmid, ip = manager.allocate()
        manager.provision(vmid, ip, trap.name, "lxc")
        return {"status": "success", "message": f"Ловушка {trap.name} развернута в Proxmox",
                "vmid": vmid, "ip": ip, "specs": "1 Core, 1GB RAM, 10GB Disk"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/")
def list_traps():
    return docker_manager().list_all_traps()

@router.delete("/{container_id}")
def delete_trap(container_id: str):
    success = docker_manager().remove_trap(container_id)
    if not success:
        raise HTTPException(status_code=404, detail="Trap not found")
    return {"status": "deleted", "container_id": container_id}

@router.post("/{container_id}/stop")
def stop_trap(container_id: str):
    success = docker_manager().stop_trap(container_id)
    if not success:
        raise HTTPException(status_code=404, detail="Trap not found")
    return {"status": "stopped", "container_id": container_id}
