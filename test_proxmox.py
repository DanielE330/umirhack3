from app.services.proxmox_manager import ProxmoxManager

print("--- ТЕСТ: АВТОРАЗВЕРТКА PROXMOX ---")

# ВНИМАНИЕ: Сюда нужно вписать реальные логин, пароль и ID шаблона от Даниэля!
# По умолчанию я поставил IP 100.64.0.30, который он вам дал.

try:
    manager = ProxmoxManager(
        host="100.64.0.12",
        user="root@pam",       # Имя пользователя в Proxmox (обычно root@pam)
        password="10293847",   # Пароль от Proxmox
        verify_ssl=False,
        port=8006              # Даниэль вернул доступ на 8006 порт
    )
    
    print("Успешно подключились к Proxmox! Запускаем клонирование...")
    
    # ВНИМАНИЕ: Прошлый тест (999) успешно склонировался! 
    # Поэтому теперь создаем ловушку с новым ID 1001, чтобы не было ошибки "уже существует"
    result = manager.create_trap_vm(
        vmid=1001, 
        name="honeyforge-test-trap", 
        template_vmid=104
    )
    
    print("Результат:")
    print(result)
    
except Exception as e:
    print(f"Ошибка при подключении или создании ловушки: {e}")
