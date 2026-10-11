import { useCallback, useMemo, useState } from 'react'
import { useData } from '../context/data.js'
import { useUi } from '../context/ui.js'
import { api } from '../lib/api.js'
import { eventFromApi } from '../lib/model.js'

export const EMPTY = { type: '', trap: '', ip: '', q: '', since: '', until: '', minScore: '' }
const PAGE = 100

// Запрос к API из полей формы: время вводится в местном поясе, в базе лежит UTC
export function eventQuery(f, traps) {
  const q = new URLSearchParams()
  if (f.type) q.set('type', f.type)
  const tr = traps.find((x) => x.name === f.trap)
  if (tr) q.set('trap_id', tr.id)
  if (f.ip.trim()) q.set('src_ip', f.ip.trim())
  if (f.q.trim()) q.set('q', f.q.trim())
  if (f.since) q.set('since', new Date(f.since).toISOString().slice(0, 19))
  if (f.until) q.set('until', new Date(f.until).toISOString().slice(0, 19))
  if (f.minScore !== '') q.set('min_score', f.minScore)
  return q
}

export function useEventList(extra, limit = PAGE) {
  const { traps } = useData()
  const { showToast } = useUi()
  const [filters, setFilters] = useState(EMPTY)
  const [items, setItems] = useState(null)
  const [next, setNext] = useState(null)
  const [busy, setBusy] = useState(false)
  const base = useMemo(() => ({ ...filters, ...extra }), [filters, extra])

  const load = useCallback(async (before) => {
    const q = eventQuery(base, traps)
    q.set('limit', String(limit))
    if (before) q.set('before_id', before)
    setBusy(true)
    try {
      const d = await api('/api/events?' + q)
      const rows = d.items.map((e) => {
        const ev = eventFromApi(e)
        return { ...ev, container: (traps.find((x) => x.id === ev.trap_id) || {}).container || '' }
      })
      setItems((old) => (before && old ? [...old, ...rows] : rows))
      setNext(d.next_before_id)
    } catch (e) {
      showToast(e.message, true)
    } finally {
      setBusy(false)
    }
  }, [base, traps, limit, showToast])

  return { filters, setFilters, items, next, busy, load, base, traps }
}

