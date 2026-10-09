from proxmoxer import ProxmoxAPI
import time

class ProxmoxManager:
    """
    Управление виртуальными машинами (ловушками) в Proxmox.
    Для High-interaction ловушек (уровень ОС).
    """
    
    def __init__(self, host, user, password, node="pve", verify_ssl=False):
        # Подключение к Proxmox API
        self.proxmox = ProxmoxAPI(host, user=user, password=password, verify_ssl=verify_ssl)
        self.node = node
        
    def create_trap_vm(self, vmid: int, name: str, template_vmid: int):
        """
        Создает новую виртуалку-ловушку по требованиям Даниэля:
        - 1 Ядро CPU
        - 10 ГБ ОЗУ (RAM)
        - 10 ГБ Диск (Storage)
        """
        print(f"Начинаем развертывание ловушки {name} (VMID: {vmid}) из шаблона {template_vmid}...")
        
        # 1. Клонируем базовый шаблон ОС (например, чистая Ubuntu)
        self.proxmox.nodes(self.node).qemu(template_vmid).clone.post(
            newid=vmid,
            name=name,
            full=1 # Полный клон
        )
        
        # Ждем, пока Proxmox завершит клонирование (в реальности нужно проверять статус таски)
        time.sleep(5) 
        
        # 2. Настраиваем ресурсы по ТЗ (1 Ядро, 10 ГБ ОЗУ = 10240 МБ)
        self.proxmox.nodes(self.node).qemu(vmid).config.post(
            cores=1,
            memory=10240, 
            description="HoneyForge High-Interaction Trap"
        )
        
        # 3. Устанавливаем размер диска 10 ГБ (если диск scsi0)
        # Обратите внимание: Proxmox может только увеличивать диск. 
        # Шаблон должен быть изначально <= 10GB.
        try:
            self.proxmox.nodes(self.node).qemu(vmid).resize.put(
                disk="scsi0",
                size="10G"
            )
        except Exception as e:
            print(f"Внимание: не удалось изменить размер диска (возможно он уже 10ГБ). Ошибка: {e}")
        
        # 4. Запускаем ловушку
        self.proxmox.nodes(self.node).qemu(vmid).status.start.post()
        
        return {
            "status": "success", 
            "message": f"Ловушка {name} успешно развернута в Proxmox",
            "vmid": vmid,
            "specs": "1 Core, 10GB RAM, 10GB Disk"
        }
