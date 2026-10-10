import paramiko
import sys

def test_lxc_logs():
    host = "100.64.0.12"
    user = "root"
    password = "10293847"
    vmid = 1001  # Наша ловушка, которую мы успешно создали вчера

    print(f"--- ТЕСТ: ЧТЕНИЕ ЛОГОВ LXC (VMID {vmid}) ПО СТЕЛСУ ---")
    print(f"Подключаемся по SSH к гипервизору {host}...")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(host, username=user, password=password, timeout=5)
        print("Успешное подключение к гипервизору!")
        
        # Запускаем команду ВНУТРИ контейнера через Proxmox CLI (pct exec)
        # Это позволяет нам читать файлы внутри ловушки, не устанавливая туда агентов!
        command = f"pct exec {vmid} -- ls -la /var/log"
        print(f"Выполняем команду: {command}")
        
        stdin, stdout, stderr = ssh.exec_command(command)
        
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        if error:
            print(f"Ошибка при выполнении: {error}")
        else:
            print("\nРезультат (Содержимое /var/log ловушки):")
            print(output)
            
    except Exception as e:
        print(f"Критическая ошибка: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    test_lxc_logs()
