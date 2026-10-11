import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api.js'
import { t } from '../i18n/translations.js'
import { DEMO, demoEvent } from '../lib/demo.js'
import {
  EMPTY_FORM, TYPE_INFO, containerState, formFromTemplate, profileToApi, readProfileForm, templateProfiles, eventFromApi, machineFromApi, profileFromApi, trapFromApi, trapState,
} from '../lib/model.js'
import { DataContext } from './data.js'
import { useUi } from './ui.js'

const EMPTY_STATS = { total: 0, auth: 0, alert: 0, src: {}, pw: {}, buckets: Array(60).fill(0) }
const NO_FILTER = { type: '', trap: '', q: '' }

// Все данные центра: профили, машины (Proxmox), ловушки, события, статистика + живой поток WebSocket.
export default function DataProvider({ children }) {
  const { showToast } = useUi()
  const [profiles, setProfiles] = useState([])
  const [machines, setMachines] = useState([])
  const [trapsRaw, setTrapsRaw] = useState([])
  const [events, setEvents] = useState([])
  const [stats, setStats] = useState(EMPTY_STATS)
  const [orchError, setOrchError] = useState('')
  const [pending, setPending] = useState({}) // vmid → состояние, пока идёт команда (запуск/перезагрузка)
  const [frozen, setFrozen] = useState(null) // снимок ленты на время паузы
  const [cFilter, setCFilter] = useState({ q: '', status: '' })
  const [eventFilter, setEventFilterState] = useState(NO_FILTER)
  const [editor, setEditor] = useState({ editing: null, form: EMPTY_FORM }) // конструктор профиля

  const fail = useCallback((e) => showToast(e.message, true), [showToast])

  // ---------- загрузка ----------
  const refresh = useCallback(async () => {
    try {
      const [ps, ts] = await Promise.all([api('/api/profiles'), api('/api/traps')])
      let ms = []
      let err = ''
      try {
        ms = await api('/api/machines')
      } catch (e) {
        err = e.message
      }
      setProfiles(ps.map(profileFromApi))
      setMachines(ms.map(machineFromApi))
      setTrapsRaw(ts)
      setOrchError(err)
    } catch (e) {
      fail(e)
    }
  }, [fail])

  const loadStats = useCallback(async () => {
    try {
      const st = await api('/api/stats')
      setStats({
        total: st.total_24h,
        auth: st.by_type.auth_attempt || 0,
        alert: st.by_type.alert || 0,
        src: Object.fromEntries(st.top_sources.map((x) => [x.value, x.count])),
        pw: Object.fromEntries(st.top_passwords.map((x) => [x.value, x.count])),
        buckets: st.timeline.map((x) => x.n),
      })
    } catch {
      /* статистика вторична: лента продолжает работать */
    }
  }, [])

  const loadEvents = useCallback(async () => {
    try {
      setEvents((await api('/api/events?limit=200')).items.map(eventFromApi))
    } catch (e) {
      fail(e)
    }
  }, [fail])

  // ---------- производные данные ----------
  const containers = useMemo(() => machines.map((c) => ({ ...c, state: containerState(c, pending) })), [machines, pending])
  const traps = useMemo(
    () =>
      trapsRaw.map((t) => {
        const base = trapFromApi(t, machines)
        return { ...base, state: trapState(base, containers.find((c) => c.vmid === base.vmid)) }
      }),
    [trapsRaw, machines, containers],
  )
  const eventsView = useMemo(() => {
    const byId = new Map(traps.map((t) => [t.id, t.container]))
    return events.map((e) => ({ ...e, container: byId.get(e.trap_id) || '' }))
  }, [events, traps])

  const lookups = useMemo(() => {
    const pickProfiles = [...profiles, ...templateProfiles(profiles)]
    const profileByName = (n) => pickProfiles.find((p) => p.name === n)
    // профиль-заготовку создаём в центре в момент первого использования
    const ensureProfile = async (n) => {
      const p = profileByName(n)
      if (!p || !p.virtual) return p
      const form = readProfileForm({ ...formFromTemplate(p.entry), name: p.name })
      if (form.error) throw new Error(form.error)
      const created = profileFromApi(await api('/api/profiles', { method: 'POST', body: profileToApi({ ...form.profile, desc: t(p.entry.emulates) }, null) }))
      setProfiles((list) => [...list, created])
      return created
    }
    const trapByName = (n) => traps.find((t) => t.name === n)
    const containerByName = (n) => containers.find((c) => c.name === n)
    const trapsOf = (cname) => (cname ? traps.filter((t) => t.container === cname) : [])
    const portsOf = (pname) => (profileByName(pname) || { services: [] }).services.map((s) => s.port)
    return {
      pickProfiles,
      ensureProfile,
      profileByName,
      trapByName,
      containerByName,
      trapsOf,
      portsOf,
      levelOf: (n) => (profileByName(n) || {}).level || '—',
      containerPorts: (cname) => [...new Set(trapsOf(cname).flatMap((t) => portsOf(t.profile)))].sort((a, b) => a - b),
      uniqueName(base, taken = new Set()) {
        let n = 1
        let name = base
        while (taken.has(name) || trapByName(name)) name = base + '-' + ++n
        return name
      },
      uniqueContainerName(base) {
        let n = containers.length + 1
        while (containerByName(base + '-' + n)) n++
        return base + '-' + n
      },
    }
  }, [profiles, traps, containers])

  // ---------- живой поток событий ----------
  const ingest = useCallback((ev) => {
    setEvents((list) => [{ ...ev, live: true }, ...list].slice(0, 500))
    setStats((s) => {
      const next = { ...s, total: s.total + 1 }
      if (ev.src_ip && ev.type !== 'alert') next.src = { ...s.src, [ev.src_ip]: (s.src[ev.src_ip] || 0) + 1 }
      if (ev.type === 'auth_attempt') {
        next.auth = s.auth + 1
        if (ev.password) next.pw = { ...s.pw, [ev.password]: (s.pw[ev.password] || 0) + 1 }
      }
      if (ev.type === 'alert') {
        next.alert = s.alert + 1
      } else {
        next.buckets = s.buckets.slice()
        next.buckets[next.buckets.length - 1]++
      }
      return next
    })
    setTrapsRaw((list) =>
      list.map((t) => (t.id === ev.trap_id ? { ...t, events: t.events + 1, last_seen: new Date().toISOString() } : t)),
    )
  }, [])

  useEffect(() => {
    if (DEMO) {
      // вместо WebSocket центра — вымышленные события раз в несколько секунд
      const t = setInterval(() => ingest(eventFromApi(demoEvent())), 4000)
      return () => clearInterval(t)
    }
    let ws
    let timer = 0
    let closed = false
    const connect = () => {
      ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/ws/events')
      ws.onmessage = (m) => {
        const d = JSON.parse(m.data)
        if (d.type !== 'ping') ingest(eventFromApi(d))
      }
      // центр перезапустили или пропала сеть — переподключаемся
      ws.onclose = () => {
        if (!closed) timer = setTimeout(connect, 3000)
      }
    }
    connect()
    return () => {
      closed = true
      clearTimeout(timer)
      ws.close()
    }
  }, [ingest])

  // ---------- запуск и опрос ----------
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- начальная загрузка данных центра
    refresh().then(() => Promise.all([loadEvents(), loadStats()]))
    const timers = [
      setInterval(refresh, 5000), // машины, ловушки, профили: статусы и «на связи»
      setInterval(loadStats, 30000), // агрегаты пересчитывает центр
      setInterval(() => setStats((s) => ({ ...s, buckets: [...s.buckets.slice(1), 0] })), 60000),
    ]
    return () => timers.forEach(clearInterval)
  }, [refresh, loadStats, loadEvents])

  // ---------- действия ----------
  const machineAction = useCallback(
    async (c, action, okMsg) => {
      if (action !== 'shutdown') setPending((p) => ({ ...p, [c.vmid]: 'starting' }))
      try {
        await api('/api/machines/' + c.vmid + '/' + action, { method: 'POST' })
        showToast(okMsg)
      } catch (e) {
        fail(e)
      }
      setPending((p) => {
        const n = { ...p }
        delete n[c.vmid]
        return n
      })
      await refresh()
    },
    [refresh, showToast, fail],
  )

  const actions = useMemo(
    () => ({
      toggleContainer(c) {
        const info = TYPE_INFO[c.type]
        if (c.status === 'running') {
          machineAction(c, 'shutdown', t('{cli} shutdown {vmid} — «{name}» выключен', { cli: info.cli, vmid: c.vmid, name: c.name }))
        } else {
          machineAction(c, 'start', t('{cli} start {vmid} — «{name}» запущен', { cli: info.cli, vmid: c.vmid, name: c.name }))
        }
      },
      restartContainer(c) {
        const info = TYPE_INFO[c.type]
        if (c.state === 'creating') return showToast(t('Машина ещё создаётся'), true)
        if (c.state === 'stopped' || c.state === 'failed') return showToast(t('Машина выключена — включите её переключателем'), true)
        return machineAction(c, 'reboot', t('{cli} reboot {vmid} — «{name}» перезапущен', { cli: info.cli, vmid: c.vmid, name: c.name }))
      },
      async deleteContainer(c) {
        showToast(t('Удаляю {kind} {vmid}…', { kind: TYPE_INFO[c.type].kind, vmid: c.vmid }))
        try {
          await api('/api/machines/' + c.vmid, { method: 'DELETE' })
          showToast(t('«{name}» удалён вместе с ловушками', { name: c.name }))
        } catch (e) {
          fail(e)
        }
        await refresh()
      },
      async removeTrap(tr) {
        try {
          await api('/api/traps/' + tr.id, { method: 'DELETE' })
          showToast(t('Ловушка «{name}» убрана', { name: tr.name }))
        } catch (e) {
          fail(e)
        }
        await refresh()
      },
    }),
    [machineAction, refresh, showToast, fail],
  )

  const setEventFilter = useCallback((patch) => setEventFilterState((f) => ({ ...f, ...patch })), [])
  const resetEventFilter = useCallback(() => setEventFilterState(NO_FILTER), [])
  const togglePause = useCallback(() => setFrozen((f) => (f ? null : eventsView)), [eventsView])
  const clearFeed = useCallback(() => {
    setEvents([])
    setFrozen((f) => (f ? [] : null))
  }, [])

  const value = useMemo(
    () => ({
      profiles, containers, traps, stats, orchError, refresh, fail,
      events: eventsView, feedEvents: frozen || eventsView, paused: Boolean(frozen), togglePause, clearFeed,
      cFilter, setCFilter, eventFilter, setEventFilter, resetEventFilter,
      editor, setEditor, ...lookups, ...actions,
    }),
    [profiles, containers, traps, stats, orchError, refresh, fail, eventsView, frozen, togglePause, clearFeed,
      cFilter, eventFilter, setEventFilter, resetEventFilter, editor, lookups, actions],
  )

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>
}
