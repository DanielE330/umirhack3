"""Экспертные правила: быстрая, объяснимая «первая линия» оценки команды.

Каждое правило — набор регулярок, которые должны найтись ВСЕ (all_of) и не должны найтись ни одна из none_of.
Многопаттерновая схема вместо `a.*b.*c` сделана специально: каждая регулярка линейна, ReDoS невозможен,
а длина входа дополнительно ограничена в textnorm.MAX_LEN.

Правила — это не истина в последней инстанции, а страховка снизу («пол» оценки): ML может оценку
поднять, но не опустить ниже сработавшего правила.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CategoryInfo:
    severity: int      # «типичная» тяжесть класса, 0..100 (используется для ожидаемого балла модели)
    title_ru: str


CATEGORIES: dict[str, CategoryInfo] = {
    "benign":               CategoryInfo(3,  "безобидная навигация"),
    "reconnaissance":       CategoryInfo(22, "разведка"),
    "privilege_escalation": CategoryInfo(55, "повышение привилегий"),
    "defense_evasion":      CategoryInfo(62, "заметание следов / отключение защиты"),
    "network_scan":         CategoryInfo(70, "сканирование сети / движение вбок"),
    "persistence":          CategoryInfo(80, "закрепление в системе"),
    "credential_access":    CategoryInfo(80, "кража учётных данных"),
    "malware_execution":    CategoryInfo(82, "запуск вредоносного кода"),
    "cryptominer":          CategoryInfo(88, "криптомайнер"),
    "destructive":          CategoryInfo(90, "разрушительные действия"),
    "malware_downloader":   CategoryInfo(90, "загрузка вредоноса"),
    "reverse_shell":        CategoryInfo(96, "обратная оболочка"),
}
# Классы, которые не предсказывает ML по тексту команды (приходят из других типов событий):
EXTRA_CATEGORIES = {"credential_attempt": CategoryInfo(25, "подбор паролей")}
UNKNOWN = "unknown"
DANGER_THRESHOLD = 60  # score >= порога считаем «опасным» (для алертов и метрик)


def title_ru(category: str) -> str:
    info = CATEGORIES.get(category) or EXTRA_CATEGORIES.get(category)
    return info.title_ru if info else "не классифицировано"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    score: int
    desc: str
    mitre: tuple[str, ...]
    all_of: tuple[str, ...]
    none_of: tuple[str, ...] = ()
    final: bool = False   # True — правило «решающее»: ML не может поднять оценку (только для безобидного)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_all", tuple(re.compile(p) for p in self.all_of))
        object.__setattr__(self, "_none", tuple(re.compile(p) for p in self.none_of))

    def excluded_by(self, lower: str) -> bool:
        return any(r.search(lower) for r in self._none)  # type: ignore[attr-defined]

    def matches(self, lower: str) -> bool:
        return all(r.search(lower) for r in self._all) and not any(r.search(lower) for r in self._none)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class Hit:
    rule: Rule

    @property
    def score(self) -> int:
        return self.rule.score


_PRE = r"(?:^|[;&|(]\s*|\bsudo\s+|\bnohup\s+)"


def _cmd(alts: str) -> str:
    """Имя команды в «позиции команды»: начало строки, после ; & | ( ` или после sudo/nohup."""
    return rf"(?:^|[;&|(`]\s*|\bsudo\s+|\bnohup\s+)(?:{alts})\b"


_DL_TOOLS = r"\b(?:wget|curl|tftp|ftpget|ftp|fetch|lwp-download|aria2c|axel)\b"
_URLISH = r"://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+\.[a-z]{2,6}/\S"
_IP_LOOKUP = r"ifconfig\.me|ipinfo\.io|icanhazip|ipify|checkip|whatismyip|ip-api\.com"
_EXEC_MARK = r"\bchmod\b|(?:^|[;&|\s])\./[\w.\-]+|\b(?:sh|bash|dash|ash)\b|\|\s*(?:sudo\s+)?(?:sh|bash)\b"

RULES: tuple[Rule, ...] = (
    # ───────── безобидное ─────────
    Rule("benign_nav", "benign", 3, "обычная навигация по файловой системе", (),
         (r"^(?:cd(?: [\w/.~-]+)?|ls(?: -[a-z]+)*(?: [\w/.~*-]+)?|pwd|clear|exit|logout|true|:)$",), final=True),

    # ───────── разведка ─────────
    Rule("recon_sysinfo", "reconnaissance", 22, "сбор сведений о системе", ("T1082",),
         (_cmd(r"uname|whoami|id|hostname|uptime|lscpu|nproc|free|df|w|who|last|lastlog|ps|top|htop|ifconfig|ip|"
               r"netstat|ss|env|printenv|lsb_release|arch|dmesg|lsmod|mount|lsblk|groups|finger|users|history|ping|"
               r"nslookup|dig|host|nvidia-smi|lspci|dmidecode|lsusb|getconf"),)),
    Rule("recon_files", "reconnaissance", 30, "чтение системных файлов с описанием хоста", ("T1082", "T1087.001"),
         (r"\b(?:cat|head|tail|less|more|grep|awk|cut)\b",
          r"/proc/(?:cpuinfo|meminfo|version|mounts|self/\w+)|/etc/(?:os-release|issue|hostname|lsb-release|"
          r"redhat-release|group|hosts|resolv\.conf|passwd)\b")),
    Rule("recon_crontab_list", "reconnaissance", 25, "просмотр заданий cron", ("T1053.003",), (r"\bcrontab\s+-l\b",)),
    Rule("recon_busybox_arch", "reconnaissance", 30, "проверка busybox / архитектуры по ELF-заголовку", ("T1082",),
         (r"\bbusybox\b|\bcat\s+/bin/(?:echo|ls|sh|busybox)\b|\bfile\s+/bin/",)),
    Rule("recon_writable_probe", "reconnaissance", 30, "проверка возможности записи в каталоги", ("T1083",),
         (r"^echo\b", r">\s*\S+/\.[a-z0-9_]{2,}")),
    Rule("recon_touch_hidden", "reconnaissance", 25, "создание пустого файла редиректом (проверка записи)", ("T1083",),
         (r"^>\s*\S+",), (r"elf|@",)),
    Rule("recon_shell_menu", "reconnaissance", 15, "перебор меню/оболочек устройства", ("T1059.004",),
         (r"^(?:enable|system|shell|linuxshell|sh)$",)),
    Rule("recon_echo_marker", "reconnaissance", 15, "проверка выполнения команд через echo", ("T1059.004",),
         (r"^echo\s+(?:-[ne]+\s+)?[\"']?[a-z0-9_.:-]{1,24}[\"']?$",)),
    Rule("benign_trivial", "benign", 3, "строка из одних знаков/короткий мусор, не команда", (), (r"^[^a-z0-9]{1,3}$",), final=True),
    Rule("benign_blob", "benign", 4, "строка-«каша» (base64/случайные символы), не команда", (),
         (r"^[a-z0-9+=][a-z0-9+/=]{15,}$",), final=True),
    Rule("recon_cleanup_relative", "reconnaissance", 25, "удаление файлов в текущем каталоге (уборка следов проб)", ("T1070.004",),
         (r"^rm\s+(?:-[a-z]+\s+)?\.?[\w*-][\w.*-]*(?:\s+\.?[\w*-][\w.*-]*){0,5}\s*;?$",)),
    Rule("benign_comment", "benign", 2, "строка-комментарий", (), (r"^#[^;&|]*$",), final=True),
    Rule("recon_hidden_file_ops", "reconnaissance", 25, "операции со скрытым файлом (проверка записи)", ("T1083",),
         (r"^(?:cat|rm|ls|stat)\b", r"/\.[a-z0-9_]{2,}\s*$")),
    Rule("recon_external_ip", "reconnaissance", 35, "определение внешнего IP", ("T1016",),
         (r"\b(?:curl|wget)\b", _IP_LOOKUP)),

    Rule("recon_tool_probe", "reconnaissance", 20, "проверка наличия утилит загрузки (без аргументов)", ("T1082",),
         (r"^(?:(?:/bin/)?busybox\s+)?(?:wget|curl|tftp|ftpget)\s*(?:;|$)",)),
    Rule("recon_touch_probe", "reconnaissance", 25, "создание пустого файла (проверка записи)", ("T1083",),
         (r"^touch\s+\.?[\w-]{1,16}\s*;?$",)),
    Rule("recon_busybox_copy_prep", "reconnaissance", 30, "подготовка исполняемой копии busybox для дроппера (без сети)", ("T1083",),
         (r"\bbusybox\s+cp\s+/bin/busybox\s+\.?\w+",), (_DL_TOOLS + r"\s+\S",)),
    Rule("recon_echo_pipe_probe", "reconnaissance", 30, "проба через echo | sh (busybox-маркер)", ("T1059.004",),
         (r"^echo\s+['\"]?(?:/bin/)?busybox\s+[a-z]{3,12}['\"]?\s*\|\s*sh\s*;?$",)),
    Rule("benign_protocol_line", "benign", 3, "строка заголовка HTTP/SMTP, не команда", (),
         (r"^(?:host|user-agent|accept(?:-[a-z]+)?|connection|cookie|content-(?:type|length)|referer|origin|"
          r"upgrade|cache-control|pragma|authorization|ehlo|helo|mail from|rcpt to)\s*:?\s",), final=True),
    Rule("benign_shell_fragment", "benign", 3, "обрывок скрипта (служебное слово/литерал), не действие", (),
         (r"^(?:fi|done|then|else|esac|do|\}|\{|end\w*;?|start;?|nan|null|none)$|^[\w-]+\s*\(\)\s*\{$|"
          r"^[a-z_]\w*=['\"][^'\"$`]*['\"];?$",), final=True),
    Rule("benign_binary_garbage", "benign", 4, "обрывок бинарного вывода (ELF), не команда", (),
         (r"^\S{0,40}$", r"elf", r"[@'?]"), final=True),
    Rule("recon_empty_write", "reconnaissance", 25, "создание пустого файла (проверка записи)", ("T1083",),
         (r"^(?:head\s+-c\s+0|dd\s+bs=\d+\s+count=0|:|true)\s*>\s*\S+\s*;?$",)),
    Rule("dropper_stdin", "malware_downloader", 85, "приём бинарника через stdin в файл (дроппер без сети)", ("T1105",),
         (r"^(?:dd\s+bs=\d+\s+count=[1-9]\d*|head\s+-c\s+[1-9]\d*)\s*>\s*\S+",)),
    Rule("exec_eval", "malware_execution", 65, "выполнение собранной строки через eval", ("T1059.004", "T1027"),
         (r"(?:^|[;&|(]\s*)eval\s",)),

    # ───────── заметание следов ─────────
    Rule("evasion_history", "defense_evasion", 62, "отключение или очистка истории команд", ("T1070.003",),
         (r"\bunset\s+hist\w*|\bexport\s+hist\w*=|\bset\s+\+o\s+history|\bhistfile\s*=\s*/dev/null",)),
    Rule("evasion_history_cmd", "defense_evasion", 58, "управление историей команд", ("T1070.003",),
         (r"\bhistory\s+-[cwn]\b",)),
    Rule("evasion_logs", "defense_evasion", 75, "удаление логов / истории", ("T1070.002",),
         (r"\b(?:rm|shred|truncate|unlink)\b", r"\.bash_history|/var/log/|/var/run/utmp|/var/log/wtmp|lastlog")),
    Rule("evasion_disable_security", "defense_evasion", 72, "отключение средств защиты", ("T1562.001", "T1562.004"),
         (r"\biptables\s+-f\b|\bufw\s+disable\b|\bsetenforce\s+0\b|"
          r"\b(?:service|systemctl)\s+(?:stop|disable)\s+(?:iptables|firewalld|ufw|auditd|apparmor|rsyslog|syslog)\b|"
          r"(?:^|[;&|]\s*)(?:echo\s*)?>\s*/etc/hosts\.(?:deny|allow)\b|"
          r"\b(?:pkill|killall|kill\s+-9)\s+\S*(?:auditd|rsyslog|syslog|aliyun|cloudmonitor|bcm-agent|"
          r"falco|osqueryd|crowdstrike|wazuh)",)),
    Rule("evasion_kill_loop", "defense_evasion", 65, "массовое завершение процессов (вытеснение конкурентов)", ("T1562",),
         (r"/proc/\[0-9\]\*", r"\bkill\s+-9")),
    Rule("evasion_kill_process", "defense_evasion", 55, "завершение процессов (конкуренты, удалённый доступ владельца)", ("T1562", "T1489"),
         (r"\b(?:pkill|killall)\s+(?:-\d+\s+|-[a-z]+\s+)*[\w.-]+",), (r"\b(?:pkill|killall)\s+(?:-\d+\s+)?(?:sleep|cat)\s*(?:;|$)",)),
    Rule("evasion_chattr", "defense_evasion", 60, "смена неизменяемых атрибутов файла", ("T1222.002",),
         (r"\bchattr\s+[+-]\w*[ia]\b",)),

    # ───────── закрепление ─────────
    Rule("persist_ssh_key_literal", "persistence", 85, "добавление SSH-ключа", ("T1098.004",),
         (r"ssh-(?:rsa|ed25519|dss)\s+aaaa|ecdsa-sha2-nistp\d+\s+aaaa",)),
    Rule("persist_authorized_keys", "persistence", 80, "изменение authorized_keys", ("T1098.004",),
         (r"authorized_keys", r">|\btee\b|\btouch\b|\bcp\b|\brm\b|\bmv\b|\bchmod\b|\bchattr\b|\bsed\b")),
    Rule("persist_ssh_dir", "persistence", 60, "подготовка каталога .ssh", ("T1098.004",),
         (r"\bmkdir\s+(?:-p\s+)?\S*\.ssh",)),
    Rule("persist_cron", "persistence", 78, "установка задания cron", ("T1053.003",),
         (r"\bcrontab\b|/etc/cron|/var/spool/cron",), (r"\bcrontab\s+-l\b",)),
    Rule("persist_startup", "persistence", 75, "запись в автозапуск", ("T1037.004", "T1546.004"),
         (r">>?\s*\S*(?:\.bashrc|\.profile|rc\.local|/etc/init\.d/)",)),
    Rule("persist_systemd", "persistence", 72, "создание или включение сервиса", ("T1543.002",),
         (r"\bsystemctl\s+(?:enable|daemon-reload)\b|/etc/systemd/system|\bupdate-rc\.d\b|\bchkconfig\b",)),
    Rule("persist_accounts", "persistence", 82, "создание или изменение учётных записей", ("T1136.001",),
         (r"\b(?:useradd|adduser|usermod|chpasswd)\b",)),
    Rule("persist_passwd_cmd", "persistence", 76, "смена пароля", ("T1098",), (_cmd(r"passwd|hive-passwd"),)),
    Rule("persist_preload", "persistence", 85, "правка ld.so.preload (руткит)", ("T1574.006",), (r"ld\.so\.preload",)),

    # ───────── загрузка и запуск вредоноса ─────────
    Rule("dl_with_url", "malware_downloader", 82, "загрузка файла по сети", ("T1105",),
         (_DL_TOOLS, _URLISH), (_IP_LOOKUP,)),
    Rule("dl_and_exec", "malware_downloader", 95, "загрузка и запуск файла", ("T1105", "T1059.004"),
         (_DL_TOOLS, _URLISH, _EXEC_MARK), (_IP_LOOKUP,)),
    Rule("dl_busybox_tftp", "malware_downloader", 85, "загрузка через busybox/tftp", ("T1105",),
         (r"\bbusybox\s+(?:wget|tftp|ftpget)\s+[^;&|\s]|\btftp\s+-[gr]\b|\bftpget\s+[^;&|\s]",)),
    Rule("dropper_echo_hex", "malware_downloader", 88, "запись бинарного файла через echo (дроппер без сети)", ("T1105", "T1027"),
         (r"^echo\b", r"(?:\\x[0-9a-f]{2}){8,}", r">>?\s*\S+")),
    Rule("dropper_script_staging", "malware_downloader", 70, "построчная сборка скрипта-дроппера", ("T1105", "T1059.004"),
         (r"^echo\b", r">>?\s*\.[a-z0-9_]{1,6}\s*$")),
    Rule("exec_chmod", "malware_execution", 78, "выдача прав на исполнение", ("T1222.002",),
         (r"\bchmod\s+(?:-\w+\s+)?(?:\+x|a\+x|u\+x|[0-7]?[0-7][0-7][0-7])\b",),
         (r"^>\s*\S", r"^(?!.*\b(?:wget|curl|tftp|ftpget)\s+\S).*\bbusybox\s+cp\s+/bin/busybox\b")),
    Rule("exec_from_tmp", "malware_execution", 82, "запуск файла из временного каталога", ("T1059.004",),
         (r"(?:^|[;&|(]\s*|\bnohup\s+|\bsudo\s+)(?:/tmp|/var/tmp|/dev/shm|/var/run|/run)/\S+",), (r"^>\s*\S",)),
    Rule("exec_local_binary", "malware_execution", 70, "запуск локального файла", ("T1059.004",),
         (_PRE + r"\./[\w.\-]+",), (r"^>\s*\S",)),
    Rule("exec_shell_script", "malware_execution", 65, "запуск shell-скрипта", ("T1059.004",),
         (r"(?:^|[;&|]\s*)(?:sh|bash|dash|ash)\s+[\w/.\-]+\.sh\b",)),
    Rule("exec_hidden_script", "malware_execution", 65, "запуск скрытого скрипта", ("T1059.004",),
         (r"(?:^|[;&|]\s*)(?:sh|bash|dash|ash)\s+\.[a-z0-9_]{1,6}\b",)),
    Rule("exec_pipe_to_shell", "malware_execution", 72, "передача данных в интерпретатор", ("T1059.004",),
         (r"\|\s*(?:sudo\s+)?(?:sh|bash|dash|zsh|python\d?|perl)\b",),
         (r"^echo\s+['\"]?(?:/bin/)?busybox\s+[a-z]{3,12}['\"]?\s*\|\s*sh\s*;?$",)),
    Rule("exec_detached", "malware_execution", 65, "фоновый запуск в обход сессии", ("T1059.004",),
         (r"\bnohup\b|\bsetsid\b|\bdisown\b",)),
    Rule("exec_inline_interpreter", "malware_execution", 50, "выполнение кода через интерпретатор", ("T1059.006",),
         (r"\b(?:python\d?|perl|ruby|php)\s+-[ce]\b",)),
    Rule("dl_devtcp_get", "malware_downloader", 90, "загрузка по HTTP через /dev/tcp", ("T1105",),
         (r"/dev/tcp/", r"\bget\s+/")),
    Rule("reverse_shell", "reverse_shell", 96, "обратная оболочка", ("T1059.004", "T1571"),
         (r"/dev/tcp/|/dev/udp/|\bbash\s+-i\b|\bmkfifo\b|"
          r"\b(?:nc|ncat|netcat)\b[^|;&]{0,80}\s-[a-z]*[ec]\s|"
          r"\b(?:python\d?|perl|ruby|php)\b[^|;&]{0,200}socket[^|;&]{0,200}(?:connect|fsockopen|tcpsocket)",),
         (r"/dev/tcp/[^;]{0,200}\bget\s+/",)),

    # ───────── майнеры ─────────
    Rule("cryptominer", "cryptominer", 88, "признаки криптомайнера", ("T1496",),
         (r"xmrig|minerd|cpuminer|stratum\+(?:tcp|ssl)|\bmonero\b|nanopool|supportxmr|minexmr|"
          r"--donate-level|cryptonight|xmr-stak|\bkdevtmpfsi\b|\bkinsing\b|ethminer|nicehash",)),

    Rule("cryptominer_install", "cryptominer", 96, "загрузка и установка криптомайнера", ("T1496", "T1105"),
         (_DL_TOOLS, r"xmrig|minerd|cpuminer|moneroocean|c3pool|xmr-stak|nicehash|kinsing|\bmonero\b")),

    # ───────── кража данных ─────────
    Rule("cred_shadow", "credential_access", 78, "чтение /etc/shadow", ("T1003.008",), (r"/etc/shadow",)),
    Rule("cred_files", "credential_access", 80, "доступ к ключам и секретам", ("T1552.001", "T1552.004"),
         (r"\b(?:cat|less|more|head|tail|cp|scp|base64|tar|zip|grep|strings|xxd|rsync|sqlite3|curl)\b",
          r"id_rsa|id_ed25519|id_ecdsa|\.aws/credentials|\.pgpass|\.git-credentials|\.docker/config|\.kube/config|"
          r"\.netrc|wp-config|\.env\b|\.my\.cnf|/\.bash_history|secrets?\.(?:ya?ml|json|txt)|passwords?\.(?:txt|csv|xlsx?)")),
    Rule("cred_dump", "credential_access", 85, "инструменты выгрузки паролей", ("T1003",),
         (r"\b(?:mimipenguin|lazagne|john|hashcat|unshadow)\b",)),

    # ───────── повышение привилегий ─────────
    Rule("privesc_sudo", "privilege_escalation", 45, "попытка получить права root", ("T1548.003",),
         (_cmd(r"sudo|su"),)),
    Rule("privesc_setuid", "privilege_escalation", 80, "установка SUID/SGID", ("T1548.001",),
         (r"\bchmod\s+(?:-\w+\s+)?(?:[ug]\+s|[24][0-7]{3})\b",)),
    Rule("privesc_suid_search", "privilege_escalation", 60, "поиск SUID-файлов", ("T1548.001",),
         (r"\bfind\b", r"-perm\s+(?:-?/?[24]000|-u=s|-g=s|/u=s)")),
    Rule("privesc_exploit", "privilege_escalation", 75, "эксплойт или инструмент повышения привилегий", ("T1068",),
         (r"dirtycow|dirty_?pipe|pwnkit|cve-\d{4}-\d{4,7}|\blinpeas|\blinenum|\bpspy|\bexploit\b|\bpkexec\b",)),

    # ───────── сеть ─────────
    Rule("netscan_tools", "network_scan", 75, "сканеры и инструменты перебора", ("T1046", "T1110"),
         (r"\b(?:nmap|masscan|zmap|zgrab|hping3?|nikto|sqlmap|hydra|medusa|ncrack|nuclei|gobuster)\b",)),
    Rule("netscan_nc_probe", "network_scan", 60, "зондирование портов через nc", ("T1046",),
         (r"\b(?:nc|ncat|netcat)\b", r"\s-[a-z]*z[a-z]*\s")),
    Rule("lateral_ssh", "network_scan", 55, "переход на другой хост по SSH/SCP", ("T1021.004",),
         (r"\b(?:ssh|scp|sftp)\s+(?:-\w+\s+\S+\s+)*[\w.\-]+@[\w.\-]+",)),

    # ───────── разрушение ─────────
    Rule("destroy_rm_root", "destructive", 90, "массовое удаление системных каталогов", ("T1485",),
         (r"\brm\s+(?:-[a-z]+\s+)*(?:--no-preserve-root\s+)?(?:/|/\*|~|/etc|/boot|/bin|/usr|/home|/root)\s*(?:$|[;&|])",)),
    Rule("destroy_disk", "destructive", 92, "перезапись или форматирование диска", ("T1561.001", "T1485"),
         (r"\bdd\b[^|;&]{0,80}\bof=/dev/(?:sd|hd|nvme|vd|xvd|mmcblk)|\bmkfs(?:\.\w+)?\s+/dev/|\bwipefs\b|>\s*/dev/(?:sd|hd|nvme|vd)",)),
    Rule("destroy_forkbomb", "destructive", 85, "fork-бомба", ("T1499.004",),
         (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",)),
)

RULES_BY_ID = {r.id: r for r in RULES}


def match(lower: str) -> list[Hit]:
    """Все сработавшие правила, по убыванию балла."""
    if not lower:
        return []
    hits = [Hit(r) for r in RULES if r.matches(lower)]
    # «Решающие» правила (final) — узкие детекторы «это не команда/безобидно»: если сработали, они главные.
    hits.sort(key=lambda h: (not h.rule.final, -h.score, h.rule.id))
    return hits
