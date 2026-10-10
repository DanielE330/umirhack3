from proxmoxer import ProxmoxAPI
import time

class ProxmoxManager:
    """
    Управление виртуальными машинами (ловушками) в Proxmox.
    Для High-interaction ловушек (уровень ОС).
    """
    
    def __init__(self, host, user, password, node="pve", verify_ssl=False, port=8006):
        # Подключение к Proxmox API
        self.proxmox = ProxmoxAPI(host, user=user, password=password, verify_ssl=verify_ssl, port=port)
        self.node = node
        
    def create_trap_vm(self, vmid: int, name: str, template_vmid: int, is_lxc: bool = True):
        """
        Создает новую виртуалку-ловушку по требованиям Даниэля:
        - 1 Ядро CPU
        - 1 ГБ ОЗУ (RAM)
        - 10 ГБ Диск (Storage)
        Поддерживает как QEMU (виртуалки), так и LXC (контейнеры).
        """
        # Автоматически определяем имя ноды Даниэля (вместо стандартного 'pve')
        nodes = self.proxmox.nodes.get()
        if not nodes:
            raise Exception("Не найдено ни одной ноды в Proxmox!")
        self.node = nodes[0]['node']
        
        # Выбираем правильный API (LXC или QEMU)
        api = self.proxmox.nodes(self.node).lxc if is_lxc else self.proxmox.nodes(self.node).qemu
        disk_name = "rootfs" if is_lxc else "scsi0"
        
        print(f"Найдена нода: {self.node}. Начинаем развертывание ловушки {name} (VMID: {vmid}) из шаблона {template_vmid} (LXC: {is_lxc})...")
        
        # 1. Клонируем базовый шаблон
        if is_lxc:
            api(template_vmid).clone.post(newid=vmid, hostname=name, full=1)
        else:
            api(template_vmid).clone.post(newid=vmid, name=name, full=1)
        
        # Ждем, пока Proxmox завершит клонирование (LXC клонируется не мгновенно)
        # В идеале здесь нужно слушать статус таски, но для MVP ставим слип
        print("Ожидаем завершения клонирования (30 сек)...")
        time.sleep(30) 

        # 2. Настраиваем ресурсы по ТЗ (1 Ядро, 1 ГБ ОЗУ = 1024 МБ)
        # В LXC конфигурация обновляется через PUT, а в QEMU через POST
        if is_lxc:
            api(vmid).config.put(cores=1, memory=1024, description="HoneyForge High-Interaction Trap")
        else:
            api(vmid).config.post(cores=1, memory=1024, description="HoneyForge High-Interaction Trap")
        
        # 3. Устанавливаем размер диска 10 ГБ
        # Обратите внимание: Proxmox может только увеличивать диск.
        try:
            api(vmid).resize.put(
                disk=disk_name,
                size="10G"
            )
        except Exception as e:
            print(f"Внимание: не удалось изменить размер диска (возможно он уже 10ГБ). Ошибка: {e}")
        
        # 4. Запускаем ловушку
        api(vmid).status.start.post()
        
        return {
            "status": "success", 
            "message": f"Ловушка {name} успешно развернута в Proxmox",
            "vmid": vmid,
            "specs": "1 Core, 1GB RAM, 10GB Disk"
        }
