import docker
from docker.errors import NotFound, APIError
import uuid

class DockerManager:
    """Управление Docker-контейнерами ловушек"""
    
    def __init__(self):
        self.client = docker.from_env()
        self.label_prefix = "honeyforge"
    
    def deploy_trap(self, trap_type: str, image: str, container_port: int, host_port: int) -> dict:
        """Развернуть новую ловушку"""
        trap_id = str(uuid.uuid4())
        container_name = f"honeyforge_{trap_type}_{trap_id[:8]}"
        
        try:
            container = self.client.containers.run(
                image=image,
                name=container_name,
                detach=True,
                ports={f"{container_port}/tcp": host_port},
                restart_policy={"Name": "unless-stopped"},
                labels={
                    self.label_prefix: "true",
                    f"{self.label_prefix}.trap_id": trap_id,
                    f"{self.label_prefix}.trap_type": trap_type,
                },
                cap_drop=["ALL"],
                cap_add=["NET_BIND_SERVICE"],
                security_opt=["no-new-privileges"],
            )
            
            return {
                "trap_id": trap_id,
                "container_id": container.id,
                "container_name": container_name,
                "status": "running",
                "host_port": host_port,
            }
        except APIError as e:
            raise Exception(f"Docker error: {e}")

    def stop_trap(self, container_id: str) -> bool:
        """Остановить ловушку"""
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=10)
            return True
        except NotFound:
            return False

    def remove_trap(self, container_id: str) -> bool:
        """Удалить ловушку и контейнер"""
        try:
            container = self.client.containers.get(container_id)
            container.remove(force=True)
            return True
        except NotFound:
            return False

    def list_all_traps(self) -> list:
        """Список всех ловушек HoneyForge"""
        containers = self.client.containers.list(
            all=True,
            filters={"label": f"{self.label_prefix}=true"}
        )
        return [
            {
                "container_id": c.id,
                "name": c.name,
                "status": c.status,
                "trap_type": c.labels.get(f"{self.label_prefix}.trap_type"),
                "trap_id": c.labels.get(f"{self.label_prefix}.trap_id"),
                "ports": c.ports,
            }
            for c in containers
        ]
