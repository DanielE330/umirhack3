import { useEffect } from 'react'
import Select from '../../components/Select.jsx'
import { HelpMark, TypeTag } from '../../components/common.jsx'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useModals } from '../../hooks/useModals.jsx'
import { clickable } from '../../lib/clickable.js'
import { useEventList, eventQuery, EMPTY } from '../../hooks/useEventList.js'
import { EVENT_TYPES, fmtDateTime } from '../../lib/model.js'

export default function Events() {
  const { t } = useLanguage()
  const { openEvent } = useModals()
  const { traps: allTraps } = useData()
  const { filters, setFilters, items, next, busy, load, base, traps } = useEventList(undefined)
  const set = (patch) => setFilters((f) => ({ ...f, ...patch }))

  useEffect(() => {
    load(null)
  }, [load])

  const exportCsv = () => { location.href = '/api/events/export.csv?' + eventQuery(base, traps) }

  return (
    <section>
      <div className="card">
        <h3>
          {t('События')}
          <HelpMark text={t('Вся история событий из базы центра, а не только последние на экране. Фильтры сочетаются; время вводится в вашем часовом поясе.')} />
        </h3>
        <div className="toolbar tight wrap">
          <Select aria-label={t('Тип события')} value={filters.type} onChange={(e) => set({ type: e.target.value })}
            options={[{ value: '', label: t('Все типы') }, ...EVENT_TYPES.map((x) => ({ value: x, label: x }))]} />
          <Select aria-label={t('Ловушка')} value={filters.trap} onChange={(e) => set({ trap: e.target.value })}
            options={[{ value: '', label: t('Все ловушки') }, ...allTraps.map((x) => ({ value: x.name, label: x.container + ' / ' + x.name }))]} />
          <input className="w-search" placeholder={t('IP источника')} aria-label={t('IP источника')} value={filters.ip} onChange={(e) => set({ ip: e.target.value })} />
          <input className="w-search" placeholder={t('Поиск: логин, пароль, команда…')} aria-label={t('Поиск')} value={filters.q} onChange={(e) => set({ q: e.target.value })} />
        </div>
        <div className="toolbar tight wrap">
          <label className="inline">{t('С')} <input type="datetime-local" aria-label={t('С')} value={filters.since} onChange={(e) => set({ since: e.target.value })} /></label>
          <label className="inline">{t('По')} <input type="datetime-local" aria-label={t('По')} value={filters.until} onChange={(e) => set({ until: e.target.value })} /></label>
          <label className="inline" data-tip={t('Показать события с оценкой опасности HoneyMind не ниже указанной (0–100). 60 и выше — опасно.')}>
            {t('Опасность от')} <input type="number" min={0} max={100} className="w-num" value={filters.minScore} onChange={(e) => set({ minScore: e.target.value })} />
          </label>
          <button className="ghost" onClick={() => setFilters(EMPTY)}>{t('Сбросить')}</button>
          <button className="ghost" onClick={() => load(null)}>{t('Обновить')}</button>
          <span className="spacer" />
          <button className="ghost" data-tip={t('Скачать события по этим фильтрам (до 10 000 строк)')} onClick={exportCsv}>{t('Экспорт CSV')}</button>
        </div>
        <div className="feed tall">
          <table>
            <thead>
              <tr>
                <th>{t('Время')}</th><th>{t('Ловушка')}</th><th>{t('Тип')}</th><th>{t('Источник')}</th><th>{t('Детали')}</th>
                <th data-tip={t('Оценка опасности HoneyMind, 0–100')}>{t('Риск')}</th>
              </tr>
            </thead>
            <tbody>
              {items && items.map((ev) => (
                <tr key={ev.id} className="click" {...clickable(() => openEvent(ev))}>
                  <td className="m">{fmtDateTime(ev.ts)}</td>
                  <td>{ev.trap}</td>
                  <td><TypeTag type={ev.type} /></td>
                  <td className="m" data-tip={ev.geo ? [ev.geo.country, ev.geo.city, ev.geo.asn, ev.geo.org].filter(Boolean).join(' · ') : undefined}>
                    {ev.geo && ev.geo.country_code && ev.geo.country_code !== '--' ? <span className="cc">{ev.geo.country_code}</span> : null}{ev.src_ip}
                  </td>
                  <td className="m">{ev.command || ev.username || ''}</td>
                  <td className="m">{ev.threat_score != null ? <span className={'risk-score' + (ev.threat_score >= 60 ? ' hot' : '')}>{ev.threat_score}</span> : ''}</td>
                </tr>
              ))}
              {items && !items.length && <tr><td className="empty" colSpan={6}>{t('По фильтру ничего нет')}</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="toolbar tight">
          <span className="hint">{t('Показано: {n}', { n: items ? items.length : 0 })}</span>
          {next && <button className="ghost" disabled={busy} onClick={() => load(next)}>{t('Показать ещё')}</button>}
        </div>
      </div>
    </section>
  )
}
