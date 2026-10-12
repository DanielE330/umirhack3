import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import Select from '../../components/Select.jsx'
import { HelpMark, TypeTag } from '../../components/common.jsx'
import { clickable } from '../../lib/clickable.js'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { EVENT_TYPES, fmtTime } from '../../lib/model.js'

const FEED_LIMIT = 60

function Kpi({ title, tip, value, tone, onClick }) {
  return (
    <div className="card kpi" role="button" data-tip={tip} {...clickable(onClick)}>
      <h3>{title}</h3>
      <div className={'num' + (tone ? ' ' + tone : '')}>{value}</div>
    </div>
  )
}

function TopList({ map, active, onPick }) {
  const { t } = useLanguage()
  const list = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 5)
  if (!list.length) return <div className="empty">{t('Нет данных')}</div>
  return (
    <div className="pick">
      {list.map(([value, count]) => (
        <div key={value} className={'bar-row' + (value === active ? ' on' : '')} {...clickable(() => onPick(value === active ? '' : value))}>
          <span>{value}</span>
          <span>{count}</span>
        </div>
      ))}
    </div>
  )
}

export default function Overview() {
  const { stats, traps, feedEvents, events, eventFilter, setEventFilter, resetEventFilter, paused, togglePause, clearFeed,
    setCFilter, trapByName } = useData()
  const { showToast } = useUi()
  const { openEvent } = useModals()
  const { t, locale } = useLanguage()
  const navigate = useNavigate()

  const rows = useMemo(() => {
    const f = eventFilter
    const q = f.q.toLowerCase()
    return feedEvents
      .filter((ev) => {
        if (f.type && ev.type !== f.type) return false
        if (f.trap && ev.trap !== f.trap) return false
        if (q && ![ev.src_ip, ev.trap, ev.container, ev.username, ev.password, ev.command].join(' ').toLowerCase().includes(q)) return false
        return true
      })
      .slice(0, FEED_LIMIT)
  }, [feedEvents, eventFilter])

  const max = Math.max(...stats.buckets, 1)
  const online = traps.filter((tr) => tr.state === 'online').length

  const exportCsv = () => {
    // выгрузка из базы центра с теми же фильтрами, а не только того, что на экране
    const q = new URLSearchParams()
    if (eventFilter.type) q.set('type', eventFilter.type)
    const tr = trapByName(eventFilter.trap)
    if (tr) q.set('trap_id', tr.id)
    if (eventFilter.q) q.set('q', eventFilter.q)
    location.href = '/api/events/export.csv?' + q
  }
  const toggle = () => {
    togglePause()
    showToast(paused ? t('Лента возобновлена') : t('Лента на паузе: события продолжают копиться'))
  }

  return (
    <section>
      <div className="grid">
        <Kpi title={t('Событий за 24 ч')} value={stats.total.toLocaleString(locale)}
          tip={t('Все события с ловушек за сутки. Нажмите, чтобы сбросить фильтры ленты')}
          onClick={() => { resetEventFilter(); showToast(t('Фильтры сброшены')) }} />
        <Kpi title={t('Ловушки онлайн')} value={online + ' / ' + traps.length} tone="ok"
          tip={t('Сколько ловушек сейчас на связи с центром из общего числа. Нажмите, чтобы показать работающие машины')}
          onClick={() => { setCFilter((f) => ({ ...f, status: 'online' })); navigate('/containers') }} />
        <Kpi title={t('Попыток входа')} value={stats.auth.toLocaleString(locale)}
          tip={t('Сколько раз атакующие вводили логин и пароль. Нажмите, чтобы показать только их')}
          onClick={() => setEventFilter({ type: 'auth_attempt', trap: '', q: '' })} />
        <Kpi title={t('Алертов')} value={stats.alert} tone="bad"
          tip={t('Тревоги центра: например, перебор паролей (5+ попыток с одного IP за минуту). Нажмите, чтобы показать только их')}
          onClick={() => setEventFilter({ type: 'alert', trap: '', q: '' })} />
      </div>

      <div className="cols">
        <div className="card">
          <h3>
            {t('Лента атак в реальном времени')}
            <HelpMark text={t('Каждая строка — действие атакующего на ловушке. Новые события появляются сверху сами. Нажмите строку, чтобы увидеть подробности.')} />
          </h3>
          <div className="toolbar tight">
            <Select aria-label={t('Тип события')} data-tip={t('Показать только события выбранного типа')} value={eventFilter.type}
              options={[{ value: '', label: t('Все типы') }, ...EVENT_TYPES.map((x) => ({ value: x, label: x }))]}
              onChange={(e) => setEventFilter({ type: e.target.value })} />
            <Select aria-label={t('Ловушка')} data-tip={t('Показать события только одной ловушки')} value={eventFilter.trap}
              options={[{ value: '', label: t('Все ловушки') }, ...traps.map((x) => ({ value: x.name, label: x.container + ' / ' + x.name }))]}
              onChange={(e) => setEventFilter({ trap: e.target.value })} />
            <input className="w-search" placeholder={t('Поиск: IP, логин, команда…')} aria-label={t('Поиск')} value={eventFilter.q}
              data-tip={t('Поиск по IP, логину, паролю, команде и имени ловушки')} onChange={(e) => setEventFilter({ q: e.target.value })} />
            <button className="ghost" data-tip={t('Убрать все фильтры ленты')} onClick={resetEventFilter}>{t('Сбросить')}</button>
            <button className="ghost" data-tip={t('Остановить прокрутку ленты, чтобы спокойно рассмотреть события. Новые события продолжат считаться')} onClick={toggle}>
              {paused ? t('▶ Продолжить') : t('⏸ Пауза')}
            </button>
            <button className="ghost" data-tip={t('Очистить ленту на экране (в базе события останутся)')} onClick={() => { clearFeed(); showToast(t('Лента очищена')) }}>
              {t('Очистить')}
            </button>
            <button className="ghost" data-tip={t('Скачать отфильтрованные события таблицей для Excel')} onClick={exportCsv}>{t('Экспорт CSV')}</button>
          </div>
          <div className="feed">
            <table>
              <thead>
                <tr>
                  <th>{t('Время')}</th><th>{t('Ловушка')}</th><th data-tip={t('Наведите на тег в строке, чтобы узнать, что он значит')}>{t('Тип')}</th>
                  <th data-tip={t('IP-адрес атакующего')}>{t('Источник')}</th><th data-tip={t('Команда, запрос или введённые логин/пароль')}>{t('Детали')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.length ? rows.map((ev) => (
                  <tr key={ev.id} className={'click' + (ev.live ? ' new' : '')} {...clickable(() => openEvent(ev))}>
                    <td className="m">{fmtTime(ev.ts)}</td>
                    <td>{ev.trap}</td>
                    <td><TypeTag type={ev.type} /></td>
                    <td className="m" data-tip={ev.geo ? [ev.geo.country, ev.geo.city, ev.geo.asn, ev.geo.org].filter(Boolean).join(' · ') : undefined}>
                      {ev.geo && ev.geo.country_code && ev.geo.country_code !== '--' ? <span className="cc">{ev.geo.country_code}</span> : null}{ev.src_ip}
                    </td>
                    <td className="m">{ev.command || ev.username || ''}</td>
                  </tr>
                )) : (
                  <tr><td className="empty" colSpan={5}>{events.length ? t('По фильтру ничего нет') : t('Событий пока нет')}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <h3>{t('Активность за час')}<HelpMark text={t('Число событий по минутам за последний час. Наведите на столбик, чтобы увидеть точное значение.')} /></h3>
            <div className="bars">
              {stats.buckets.map((n, i) => (
                <i key={i} style={{ height: Math.max(3, (n / max) * 100) + '%' }}
                  data-tip={t('{n} событий, {m} мин назад', { n, m: stats.buckets.length - 1 - i })} />
              ))}
            </div>
          </div>
          <div className="card">
            <h3>
              {t('Топ источников')}<HelpMark text={t('IP-адреса, с которых пришло больше всего событий. Это кандидаты на блокировку.')} />
              <span className="hint">{t('нажмите для фильтра')}</span>
            </h3>
            <TopList map={stats.src} active={eventFilter.q} onPick={(v) => setEventFilter({ q: v })} />
            <div className="mt-10">
              <button className="ghost" data-tip={t('IoC (индикаторы компрометации) — список IP атакующих. Его можно загрузить в межсетевой экран или SIEM')}
                onClick={() => { location.href = '/api/iocs.csv' }}>
                {t('Экспорт IoC (CSV)')}
              </button>
            </div>
          </div>
          <div className="card">
            <h3>
              {t('Откуда атакуют')}<HelpMark text={t('Страны и провайдеры (ASN) источников за 24 часа. Определяются по публичной базе IP; частные адреса не учитываются.')} />
            </h3>
            <TopList map={stats.countries} active="" onPick={(v) => setEventFilter({ q: v })} />
            <div className="mt-10"><TopList map={stats.asn} active="" onPick={(v) => setEventFilter({ q: v })} /></div>
          </div>
          <div className="card">
            <h3>
              {t('Топ паролей')}<HelpMark text={t('Пароли, которые атакующие пробуют чаще всего. Показывает, какие словари используют для перебора.')} />
              <span className="hint">{t('нажмите для фильтра')}</span>
            </h3>
            <TopList map={stats.pw} active={eventFilter.q} onPick={(v) => setEventFilter({ q: v })} />
          </div>
        </div>
      </div>
    </section>
  )
}
