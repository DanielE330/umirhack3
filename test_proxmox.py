from app.services.proxmox_manager import ProxmoxManager

print("--- ТЕСТ: АВТОРАЗВЕРТКА PROXMOX ---")

# ВНИМАНИЕ: Сюда нужно вписать реальные логин, пароль и ID шаблона от Даниэля!
# По умолчанию я поставил IP 100.64.0.30, который он вам дал.

try:
    manager = ProxmoxManager(
        host="100.64.0.6",
        user="root@pam",       # Имя пользователя в Proxmox (обычно root@pam)
        password="10293847",   # Пароль от Proxmox
        verify_ssl=False,
        port=443               # Даниэль открыл 443 порт вместо 8006
    )
    
    print("Успешно подключились к Proxmox! Запускаем клонирование...")
    
    # Пытаемся создать виртуалку с ID 999 из шаблона с ID 100
    # (Спросите у Даниэля, какой ID у его шаблона)
    result = manager.create_trap_vm(
        vmid=999, 
        name="honeyforge-test-trap", 
        template_vmid=100
    )
    
    print("Результат:")
    print(result)
    
except Exception as e:
    print(f"Ошибка при подключении или создании ловушки: {e}")
