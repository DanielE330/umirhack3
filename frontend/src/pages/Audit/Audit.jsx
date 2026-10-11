import { useCallback, useEffect, useState } from 'react'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { fmtDateTime } from '../../lib/model.js'

// Журнал аудита: кто и что менял в панели (входы, пользователи, ловушки, профили). Только для администратора.
export default function Audit() {
  const { t } = useLanguage()
  const { showToast } = useUi()
  const [items, setItems] = useState(null)
  const [next, setNext] = useState(null)
  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')

  const load = useCallback(async (before) => {
    const q = new URLSearchParams({ limit: '100' })
    if (actor.trim()) q.set('actor', actor.trim())
    if (action.trim()) q.set('action', action.trim())
    if (before) q.set('before_id', before)
    try {
      const d = await api('/api/audit?' + q)
      setItems((old) => (before && old ? [...old, ...d.items] : d.items))
      setNext(d.next_before_id)
    } catch (e) {
      showToast(e.message, true)
    }
  }, [actor, action, showToast])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- загрузка журнала при открытии и смене фильтра
    load(null)
  }, [load])

  return (
    <section>
      <div className="toolbar">
        <input className="w-search" placeholder={t('Пользователь')} aria-label={t('Пользователь')} value={actor} onChange={(e) => setActor(e.target.value)} />
        <input className="w-search" placeholder={t('Действие: trap, user, profile…')} aria-label={t('Действие')} value={action}
          data-tip={t('Начало названия действия, например trap или user.create')} onChange={(e) => setAction(e.target.value)} />
        <span className="spacer" />
        <span className="hint">{t('Записей: {n}', { n: items ? items.length : 0 })}</span>
      </div>
      <div className="card">
        <table className="rows">
          <thead><tr><th>{t('Время')}</th><th>{t('Пользователь')}</th><th>{t('Действие')}</th><th>{t('Подробности')}</th><th>IP</th></tr></thead>
          <tbody>
            {items && items.map((r) => (
              <tr key={r.id}>
                <td className="m">{fmtDateTime(Date.parse(r.ts))}</td>
                <td><b>{r.actor || '—'}</b></td>
                <td className="m">{r.action}</td>
                <td>{r.detail}</td>
                <td className="m">{r.ip}</td>
              </tr>
            ))}
            {items && !items.length && <tr><td colSpan={5} className="empty">{t('Записей нет')}</td></tr>}
          </tbody>
        </table>
        {next && <div className="mt-10"><button className="ghost" onClick={() => load(next)}>{t('Показать ещё')}</button></div>}
      </div>
    </section>
  )
}
