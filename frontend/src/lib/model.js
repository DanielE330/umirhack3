// Модель данных и справочники HoneyForge (перенос из исходного panel.js без изменения логики)
import { getLang, t } from '../i18n/translations.js'

// ============ СОСТОЯНИЯ ============
export const STATES = {
  online: { label: 'Работает', hint: 'Машина запущена, агент на связи, ловушки принимают подключения' },
  creating: { label: 'Создаётся…', hint: 'Proxmox клонирует шаблон, задаёт ресурсы и сеть, устанавливает агент' },
  starting: { label: 'Запускается…', hint: 'Машина стартует, ждём подключения агента' },
  waiting: { label: 'Ждёт подключения', hint: 'Машина создана, но агент внутри ещё не вышел на связь' },
  offline: { label: 'Не отвечает', hint: 'Агент давно не выходил на связь: проверьте машину в Proxmox' },
  stopped: { label: 'Выключен', hint: 'Машина остановлена: ловушки не принимают подключения' },
  failed: {
    label: 'Ошибка создания',
    hint: 'Proxmox не смог создать машину: подробности в карточке. Её можно удалить и создать заново',
  },
}
export const ORDER = ['online', 'creating', 'starting', 'waiting', 'offline', 'stopped', 'failed']

// ============ PROXMOX ============
export const PVE = {
  bridge: 'vmbr1', // отдельный bridge под DMZ: ловушки не видят домашнюю LAN и прод
  bridgeLabel: 'vmbr1 · DMZ 10.20.0.0/24 (изолированная сеть)',
  templates: { lxc: 9100 }, // шаблон для клонирования (настраивается в оркестраторе)
  storage: 'hdd',
  defaults: { cores: 1, ram: 1, disk: 10 },
  limits: { cores: [1, 32], ram: [1, 128], disk: [10, 1000] },
}
export const TYPE_INFO = {
  lxc: { label: 'LXC', title: 'Контейнер', kind: 'CT', cli: 'pct', desc: 'Лёгкий, стартует за секунды. Подходит для Low и Medium.' },
  kvm: { label: 'KVM', title: 'Виртуальная машина', kind: 'VM', cli: 'qm', desc: 'Полноценная ОС и сильнее изоляция. Дольше стартует.' },
}
export const EVENT_TYPES = ['connect', 'auth_attempt', 'command', 'http_request', 'payload', 'honeytoken', 'session_end', 'alert']

export const plural = (n, one, few, many) =>
  n % 10 === 1 && n % 100 !== 11 ? one : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? few : many
export const resParts = (c) => {
  const cores = getLang() === 'en' ? (c.cores === 1 ? 'core' : 'cores') : plural(c.cores, 'ядро', 'ядра', 'ядер')
  return [c.cores + ' ' + cores, c.ram + ' ' + t('ГБ ОЗУ'), c.disk + ' ' + t('ГБ диск')]
}

// ============ ПОДСКАЗКИ ============
export const HELP = {
  agent: 'Агент — небольшая фоновая программа внутри машины-ловушки. Он получает от центра настройки (какие порты открыть и что отвечать), запускает ловушки, записывает действия атакующего и незаметно отправляет их в центр. Если связь пропала, события копятся у агента и досылаются позже.',
  seen: 'Когда агент последний раз выходил на связь с центром. Агент «отмечается» каждые 15–20 секунд со случайным разбросом, чтобы его трафик не выделялся регулярностью.',
  low: 'Low — простая ловушка: открывает порт и отвечает баннером сервиса (например, «220 ProFTPD»). Фиксирует сканирование и факт подключения. Риск минимальный.',
  medium: 'Medium — ловушка с логикой сервиса: поддельный SSH с консолью, поддельная веб-админка. Собирает логины, пароли, команды и запросы. Внутри — заглушка, а не настоящая система.',
  high: 'High — настоящая ОС в изолированной машине. Самые полные данные, но и самый высокий риск.',
  dmz: 'DMZ — отдельная изолированная сеть для ловушек. Из неё не видно домашнюю сеть, прод и центр управления: даже взломав ловушку, атакующий не уйдёт дальше.',
  beacon: 'Маяк — периодический запрос агента к центру за настройками. Интервал — как часто, джиттер — случайный разброс (0.3 = ±30%), чтобы запросы не шли строго по часам.',
  honeytoken: 'Honeytoken — файл-приманка (ключи, бэкап, пароли). Сам по себе он не нужен никому, кроме атакующего, поэтому любое обращение к нему — верный признак взлома.',
}
export const EVENT_HELP = {
  connect: 'Подключение к порту ловушки: кто-то просканировал или открыл соединение.',
  auth_attempt: 'Попытка входа: атакующий ввёл логин и пароль.',
  command: 'Команда, выполненная атакующим в поддельной консоли.',
  http_request: 'HTTP-запрос к поддельному веб-сервису.',
  payload: 'Данные, которые атакующий отправил в порт (полезная нагрузка).',
  honeytoken: 'Атакующий открыл файл-приманку (honeytoken) — признак настоящего взлома.',
  alert: 'Тревога центра: например, слишком много попыток входа с одного IP за минуту (перебор паролей).',
}

// ============ КАТАЛОГ ТИПОВ ЛОВУШЕК ============
// Всё, что умеет агент: banner (Low), ssh и http (Medium). planned — то, чего в агенте ещё нет.
export const CATALOG = [
  { id: 'ssh-banner', icon: 'SSH', name: 'SSH-сканер', level: 'low',
    services: [{ port: 22, proto: 'banner', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6' }],
    emulates: 'Открытый порт SSH с баннером OpenSSH. Войти нельзя — соединение закрывается после приветствия.',
    collects: 'IP и порт источника, время, версию SSH-клиента сканера.', risk: 'Минимальный' },
  { id: 'ftp', icon: 'FTP', name: 'FTP-сервер', level: 'low',
    services: [{ port: 21, proto: 'banner', banner: '220 ProFTPD 1.3.5 Server ready.' }],
    emulates: 'Приветствие ProFTPD 1.3.5 — версия с известными уязвимостями, на неё охотно идут боты.',
    collects: 'Подключение и первую команду клиента (обычно USER с логином).', risk: 'Минимальный' },
  { id: 'telnet', icon: 'TEL', name: 'Telnet', level: 'low',
    services: [{ port: 23, proto: 'banner', banner: 'Ubuntu 18.04.6 LTS\r\nweb-01 login:' }],
    emulates: 'Приглашение входа Telnet, как на старом сервере или роутере.',
    collects: 'Подключение и введённый логин — ботнеты вроде Mirai перебирают Telnet постоянно.', risk: 'Минимальный' },
  { id: 'smtp', icon: 'SMTP', name: 'Почтовый сервер', level: 'low',
    services: [{ port: 25, proto: 'banner', banner: '220 mail.corp.local ESMTP Postfix (Ubuntu)' }],
    emulates: 'Приветствие почтового сервера Postfix.',
    collects: 'Подключение и первую команду (EHLO, попытки открытого релея для спама).', risk: 'Минимальный' },
  { id: 'mysql', icon: 'SQL', name: 'MySQL', level: 'low',
    services: [{ port: 3306, proto: 'banner', banner: '5.7.42-0ubuntu0.18.04.1' }],
    emulates: 'Открытый порт MySQL с версией сервера. Логики базы нет.',
    collects: 'Факт сканирования БД и первые байты клиента.', risk: 'Минимальный',
    note: 'Баннер текстовый, а настоящий MySQL отвечает бинарным пакетом — продвинутый сканер может это заметить.' },
  { id: 'redis', icon: 'RDS', name: 'Redis', level: 'low',
    services: [{ port: 6379, proto: 'banner', banner: '' }],
    emulates: 'Порт Redis без пароля: молчит и ждёт команд, как настоящий.',
    collects: 'Присланные команды (INFO, CONFIG SET, SLAVEOF) — так ищут открытые базы для майнеров и вымогателей.', risk: 'Минимальный' },
  { id: 'tcp', icon: 'TCP', name: 'Любой TCP-порт', level: 'low', custom: true,
    services: [{ port: 9200, proto: 'banner', banner: '' }],
    emulates: 'Пустой TCP-порт на ваш выбор: просто принимает соединение. Порт и баннер задаются в профиле.',
    collects: 'Подключения и первые байты — «радар» для сканеров вроде nmap и masscan.', risk: 'Минимальный' },
  { id: 'fake-ssh', icon: 'SSH', name: 'Поддельный SSH', level: 'medium',
    services: [{ port: 22, proto: 'ssh', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6' }],
    users: ['root', 'admin'], tokens: ['/root/.aws/credentials', '/home/admin/backup.sql'],
    emulates: 'Настоящий SSH-протокол: пускает с любым паролем и выдаёт консоль Ubuntu с поддельной файловой системой.',
    collects: 'Логины и пароли, все команды, попытки скачать файлы (wget, curl), чтение файлов-приманок.', risk: 'Умеренный' },
  { id: 'fake-web', icon: 'WEB', name: 'Поддельная веб-админка', level: 'medium',
    services: [{ port: 80, proto: 'http', banner: 'Apache/2.4.52 (Ubuntu)' }, { port: 8080, proto: 'http', banner: 'Apache/2.4.52 (Ubuntu)' }],
    users: ['admin'], tokens: [],
    emulates: 'Страница входа «Admin Console», правдоподобные 404 и заголовок Apache.',
    collects: 'Логины и пароли из формы, все HTTP-запросы: поиск /.env, /wp-login.php, /phpmyadmin, попытки SQL-инъекций.', risk: 'Умеренный' },
  { id: 'fake-db', icon: 'DB', name: 'Поддельная база данных', level: 'medium', planned: true,
    services: [{ port: 5432, proto: 'db', banner: '' }],
    emulates: 'Протокол PostgreSQL/MySQL с ответами на запросы и таблицами-приманками.',
    collects: 'Учётные данные и SQL-запросы атакующего.', risk: 'Умеренный' },
  { id: 'high-vm', icon: 'VM', name: 'Настоящая ОС в песочнице', level: 'high', planned: true, services: [],
    emulates: 'Полноценная виртуальная машина в изолированной сети с откатом к снимку после атаки.',
    collects: 'Всю сессию: ввод и вывод, загруженные инструменты, попытки двигаться по сети.', risk: 'Высокий' },
]
export const CAT_LEVELS = [['', 'Все'], ['low', 'Low'], ['medium', 'Medium'], ['high', 'High']]

// ============ API → модель ============
export function profileFromApi(p) {
  const d = p.decoys || {}
  const m = p.masking || {}
  return {
    id: p.id, name: p.name, level: p.level, desc: p.description || '', services: p.services || [],
    users: (d.users || []).map((u) => u.username), tokens: (d.honeytokens || []).map((t) => t.path),
    beacon: m.beacon_interval ?? 15, jitter: m.jitter ?? 0.3, raw: p,
  }
}
function fakeContent(path) { // правдоподобное содержимое файла-приманки
  if (/aws/.test(path)) return '[default]\naws_access_key_id = AKIA' + 'Q7HF2KX9TW4ML3RD' + '\naws_secret_access_key = 9fKq2+vXz/8mPw1sLr4TnB6yHc0eJd5gA7uQ3iWo\n'
  if (/\.sql$/.test(path)) return "-- MySQL dump 10.13\nINSERT INTO users VALUES (1,'admin','$2y$10$Jq0vX1eWb7RkQ4sNz2pT8u');\n"
  if (/\.env$/.test(path)) return 'DB_HOST=10.0.3.12\nDB_USER=app\nDB_PASSWORD=Spring2024!\n'
  return '# do not share\n'
}
export function profileToApi(p, existing) {
  const raw = (existing && existing.raw) || {}
  const d = raw.decoys || {}
  const oldUsers = new Map((d.users || []).map((u) => [u.username, u.password]))
  const oldTokens = new Map((d.honeytokens || []).map((t) => [t.path, t]))
  return {
    name: p.name, description: p.desc || '', level: p.level, services: p.services,
    decoys: {
      hostname: d.hostname || 'srv-01', accept_any_password: d.accept_any_password ?? true,
      users: p.users.map((u) => ({ username: u, password: oldUsers.get(u) || 'Winter2024!' })),
      honeytokens: p.tokens.map((path) => oldTokens.get(path) || { type: 'file', path, content: fakeContent(path) }),
    },
    logging: raw.logging || {},
    masking: { ...(raw.masking || {}), beacon_interval: p.beacon, jitter: p.jitter },
  }
}
export function machineFromApi(m) {
  return {
    id: m.vmid, vmid: m.vmid, name: m.name || 'vm-' + m.vmid, type: m.type === 'kvm' ? 'kvm' : 'lxc', node: m.node || '',
    bridge: m.bridge || PVE.bridge, host: m.ip || '', status: m.status, job: m.job || null, agent: m.agent || 'never',
    seen: m.last_seen ? Date.parse(m.last_seen) : null, cores: m.cores || 1,
    ram: Math.max(1, Math.round((m.memory_mb || 1024) / 1024)), disk: m.disk_gb || 0,
  }
}
export function trapFromApi(t, containers) {
  const c = containers.find((x) => x.vmid === t.machine_vmid)
  return {
    id: t.id, name: t.name, vmid: t.machine_vmid, container: c ? c.name : '', profile: t.profile || '',
    profile_id: t.profile_id, enabled: t.enabled, status: t.status, events: t.events,
    seen: t.last_seen ? Date.parse(t.last_seen) : null,
  }
}
export const eventFromApi = (e) => ({ ...e, ts: Date.parse(e.ts) })

// ============ ВЫЧИСЛЯЕМОЕ СОСТОЯНИЕ ============
export function containerState(c, pending) {
  if (c.job && c.job.state === 'error') return 'failed'
  if (c.status === 'creating' || (c.job && c.job.state === 'creating')) return 'creating'
  if (pending[c.vmid]) return pending[c.vmid]
  if (c.status !== 'running') return 'stopped'
  return c.agent === 'online' ? 'online' : c.agent === 'offline' ? 'offline' : 'waiting'
}
export function trapState(t, container) {
  if (!container) return 'offline'
  const cs = container.state
  if (cs !== 'online' && cs !== 'waiting' && cs !== 'offline') return cs
  if (!t.enabled) return 'stopped'
  return t.status === 'online' ? 'online' : t.status === 'offline' ? 'offline' : 'waiting'
}

// порты внутри одной машины не должны пересекаться
export function portConflicts(entries, lookup) {
  const byPort = new Map()
  for (const e of entries) {
    for (const s of (lookup(e.profile) || { services: [] }).services) byPort.set(s.port, [...(byPort.get(s.port) || []), e.name])
  }
  return [...byPort].filter(([, names]) => names.length > 1).map(([p, names]) => t('Порт {p} занят дважды: {names}', { p, names: names.join(', ') }))
}
export const baseName = (profile) => profile.replace(/-(low|medium)$/, '') + '-bait'
export function iconFor(p) {
  const n = p.name.toLowerCase()
  if (/ssh/.test(n)) return 'SSH'
  if (/web|http/.test(n)) return 'WEB'
  if (/db|sql/.test(n)) return 'DB'
  if (/ftp/.test(n)) return 'FTP'
  const proto = (p.services[0] || {}).proto || 'tcp'
  return proto === 'banner' ? 'TCP' : proto.toUpperCase()
}
export function pveCommands(c) {
  const t = TYPE_INFO[c.type]
  const tpl = PVE.templates[c.type] || '—'
  const net = c.type === 'kvm'
    ? '--net0 virtio,bridge=' + c.bridge
    : '--net0 name=eth0,bridge=' + c.bridge + ',ip=' + (c.host || '10.20.0.X') + '/24,gw=10.20.0.1'
  return [
    t.cli + ' clone ' + tpl + ' ' + c.vmid + (c.type === 'kvm' ? ' --name ' : ' --hostname ') + c.name + ' --full --storage ' + PVE.storage,
    t.cli + ' set ' + c.vmid + ' --cores ' + c.cores + ' --memory ' + c.ram * 1024 + ' ' + net + ' --tags honeyforge',
    t.cli + ' resize ' + c.vmid + (c.type === 'kvm' ? ' scsi0 ' : ' rootfs ') + c.disk + 'G',
    t.cli + ' start ' + c.vmid,
  ].join('\n')
}

// ============ ФОРМАТИРОВАНИЕ ============
export function since(ts, now = Date.now()) {
  if (!ts) return t('никогда')
  const s = Math.max(0, Math.round((now - ts) / 1000))
  if (s < 60) return t('{n} с назад', { n: s })
  if (s < 3600) return t('{n} мин назад', { n: Math.round(s / 60) })
  return t('{n} ч назад', { n: Math.round(s / 3600) })
}
export const fmtTime = (ts) => new Date(ts).toLocaleTimeString(getLang() === 'en' ? 'en-GB' : 'ru-RU')
export const fmtDateTime = (ts) => new Date(ts).toLocaleString(getLang() === 'en' ? 'en-GB' : 'ru-RU')

// Шаблон из каталога → поля конструктора профиля
export const servicesToText = (services) =>
  services.map((s) => [s.port, s.proto, (s.banner || '').replace(/\r\n/g, ' ')].join(':').replace(/:$/, '')).join('\n')
export const EMPTY_FORM = { name: '', level: 'low', services: '', users: '', tokens: '', beacon: 15, jitter: 0.3 }
export const formFromTemplate = (e) => ({
  ...EMPTY_FORM, name: e.id + '-' + e.level, level: e.level, services: servicesToText(e.services),
  users: (e.users || []).join('\n'), tokens: (e.tokens || []).join('\n'),
})
export const formFromProfile = (p) => ({
  name: p.name, level: p.level, services: p.services.map((s) => [s.port, s.proto, s.banner].join(':').replace(/:$/, '')).join('\n'),
  users: p.users.join('\n'), tokens: p.tokens.join('\n'), beacon: p.beacon, jitter: p.jitter,
})

// Разбор и проверка формы профиля
export function readProfileForm(f, old) {
  const name = f.name.trim()
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(name)) return { error: t('Название: латиница, цифры, точка, дефис, подчёркивание (до 80 символов)') }
  const lines = (s) => s.split('\n').map((l) => l.trim()).filter(Boolean)
  const services = []
  for (const line of lines(f.services)) {
    const [port, proto = 'banner', ...rest] = line.split(':')
    const n = Number(port)
    if (!Number.isInteger(n) || n < 1 || n > 65535) return { error: t('Неверный порт: {line}', { line }) }
    if (!['banner', 'ssh', 'http'].includes(proto)) return { error: t('Протокол: banner, ssh или http ({line})', { line }) }
    if (f.level === 'low' && proto !== 'banner') return { error: t('Low-ловушка умеет только баннеры (banner)') }
    if (services.some((s) => s.port === n)) return { error: t('Порт {n} указан дважды', { n }) }
    services.push({ port: n, proto, banner: rest.join(':') })
  }
  if (!services.length) return { error: t('Добавьте хотя бы один сервис') }
  const users = lines(f.users)
  if (users.some((u) => !/^[A-Za-z0-9._-]{1,64}$/.test(u))) return { error: t('Имена пользователей: латиница, цифры, точка, дефис, подчёркивание') }
  if (new Set(users).size !== users.length) return { error: t('Имена пользователей повторяются') }
  const tokens = lines(f.tokens)
  if (tokens.some((x) => !x.startsWith('/') || x.includes('..'))) return { error: t('Пути honeytoken: абсолютные, без ..') }
  const beacon = Number(f.beacon)
  const jitter = Number(f.jitter)
  if (!(beacon >= 5 && beacon <= 300)) return { error: t('Интервал маяка: 5–300 с') }
  if (!(jitter >= 0 && jitter <= 0.9)) return { error: t('Джиттер: 0–0.9') }
  return { profile: { id: old ? old.id : null, name, level: f.level, services, users, tokens, beacon, jitter, desc: old ? old.desc : '' } }
}

// Ресурсы машины из полей формы: 1 ядро / 1 ГБ / 10 ГБ по шаблону, можно поменять
export function readResources(v, minDisk) {
  const r = { cores: Number(v.cores), ram: Number(v.ram), disk: Number(v.disk) }
  const bad = (n, [a, b]) => !Number.isInteger(n) || n < a || n > b
  if (bad(r.cores, PVE.limits.cores)) return { error: t('Ядра: от {a} до {b}', { a: PVE.limits.cores[0], b: PVE.limits.cores[1] }) }
  if (bad(r.ram, PVE.limits.ram)) return { error: t('ОЗУ: от {a} до {b} ГБ', { a: PVE.limits.ram[0], b: PVE.limits.ram[1] }) }
  if (bad(r.disk, PVE.limits.disk)) return { error: t('Диск: от {a} до {b} ГБ', { a: PVE.limits.disk[0], b: PVE.limits.disk[1] }) }
  if (minDisk && r.disk < minDisk) return { error: t('Диск можно только увеличить (сейчас {min} ГБ)', { min: minDisk }) }
  return { value: r }
}
