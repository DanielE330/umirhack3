import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import Select from '../../components/Select.jsx'
import { HelpMark, TypeTag } from '../../components/common.jsx'
import { clickable } from '../../lib/clickable.js'
import { useData } from '../../context/data.js'
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
  const list = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 5)
  if (!list.length) return <div className="empty">Нет данных</div>
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
  const online = traps.filter((t) => t.state === 'online').length

  const exportCsv = () => {
    // выгрузка из базы центра с теми же фильтрами, а не только того, что на экране
    const q = new URLSearchParams()
    if (eventFilter.type) q.set('type', eventFilter.type)
    const t = trapByName(eventFilter.trap)
    if (t) q.set('trap_id', t.id)
    if (eventFilter.q) q.set('q', eventFilter.q)
    location.href = '/api/events/export.csv?' + q
  }
  const toggle = () => {
    togglePause()
    showToast(paused ? 'Лента возобновлена' : 'Лента на паузе: события продолжают копиться')
  }

  return (
    <section>
      <div className="grid">
        <Kpi title="Событий за 24 ч" value={stats.total.toLocaleString('ru-RU')}
          tip="Все события с ловушек за сутки. Нажмите, чтобы сбросить фильтры ленты"
          onClick={() => { resetEventFilter(); showToast('Фильтры сброшены') }} />
        <Kpi title="Ловушки онлайн" value={online + ' / ' + traps.length} tone="ok"
          tip="Сколько ловушек сейчас на связи с центром из общего числа. Нажмите, чтобы показать работающие машины"
          onClick={() => { setCFilter((f) => ({ ...f, status: 'online' })); navigate('/containers') }} />
        <Kpi title="Попыток входа" value={stats.auth.toLocaleString('ru-RU')}
          tip="Сколько раз атакующие вводили логин и пароль. Нажмите, чтобы показать только их"
          onClick={() => setEventFilter({ type: 'auth_attempt', trap: '', q: '' })} />
        <Kpi title="Алертов" value={stats.alert} tone="bad"
          tip="Тревоги центра: например, перебор паролей (5+ попыток с одного IP за минуту). Нажмите, чтобы показать только их"
          onClick={() => setEventFilter({ type: 'alert', trap: '', q: '' })} />
      </div>

      <div className="cols">
        <div className="card">
          <h3>
            Лента атак в реальном времени
            <HelpMark text="Каждая строка — действие атакующего на ловушке. Новые события появляются сверху сами. Нажмите строку, чтобы увидеть подробности." />
          </h3>
          <div className="toolbar tight">
            <Select aria-label="Тип события" data-tip="Показать только события выбранного типа" value={eventFilter.type}
              options={[{ value: '', label: 'Все типы' }, ...EVENT_TYPES.map((t) => ({ value: t, label: t }))]}
              onChange={(e) => setEventFilter({ type: e.target.value })} />
            <Select aria-label="Ловушка" data-tip="Показать события только одной ловушки" value={eventFilter.trap}
              options={[{ value: '', label: 'Все ловушки' }, ...traps.map((t) => ({ value: t.name, label: t.container + ' / ' + t.name }))]}
              onChange={(e) => setEventFilter({ trap: e.target.value })} />
            <input className="w-search" placeholder="Поиск: IP, логин, команда…" aria-label="Поиск" value={eventFilter.q}
              data-tip="Поиск по IP, логину, паролю, команде и имени ловушки" onChange={(e) => setEventFilter({ q: e.target.value })} />
            <button className="ghost" data-tip="Убрать все фильтры ленты" onClick={resetEventFilter}>Сбросить</button>
            <button className="ghost" data-tip="Остановить прокрутку ленты, чтобы спокойно рассмотреть события. Новые события продолжат считаться" onClick={toggle}>
              {paused ? '▶ Продолжить' : '⏸ Пауза'}
            </button>
            <button className="ghost" data-tip="Очистить ленту на экране (в базе события останутся)" onClick={() => { clearFeed(); showToast('Лента очищена') }}>Очистить</button>
            <button className="ghost" data-tip="Скачать отфильтрованные события таблицей для Excel" onClick={exportCsv}>Экспорт CSV</button>
          </div>
          <div className="feed">
            <table>
              <thead>
                <tr>
                  <th>Время</th><th>Ловушка</th><th data-tip="Наведите на тег в строке, чтобы узнать, что он значит">Тип</th>
                  <th data-tip="IP-адрес атакующего">Источник</th><th data-tip="Команда, запрос или введённые логин/пароль">Детали</th>
                </tr>
              </thead>
              <tbody>
                {rows.length ? rows.map((ev) => (
                  <tr key={ev.id} className={'click' + (ev.live ? ' new' : '')} {...clickable(() => openEvent(ev))}>
                    <td className="m">{fmtTime(ev.ts)}</td>
                    <td>{ev.trap}</td>
                    <td><TypeTag type={ev.type} /></td>
                    <td className="m">{ev.src_ip}</td>
                    <td className="m">{ev.command || ev.username || ''}</td>
                  </tr>
                )) : (
                  <tr><td className="empty" colSpan={5}>{events.length ? 'По фильтру ничего нет' : 'Событий пока нет'}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <h3>Активность за час<HelpMark text="Число событий по минутам за последний час. Наведите на столбик, чтобы увидеть точное значение." /></h3>
            <div className="bars">
              {stats.buckets.map((n, i) => (
                <i key={i} style={{ height: Math.max(3, (n / max) * 100) + '%' }} data-tip={n + ' событий, ' + (stats.buckets.length - 1 - i) + ' мин назад'} />
              ))}
            </div>
          </div>
          <div className="card">
            <h3>
              Топ источников<HelpMark text="IP-адреса, с которых пришло больше всего событий. Это кандидаты на блокировку." />
              <span className="hint">нажмите для фильтра</span>
            </h3>
            <TopList map={stats.src} active={eventFilter.q} onPick={(v) => setEventFilter({ q: v })} />
            <div style={{ marginTop: 10 }}>
              <button className="ghost" data-tip="IoC (индикаторы компрометации) — список IP атакующих. Его можно загрузить в межсетевой экран или SIEM"
                onClick={() => { location.href = '/api/iocs.csv' }}>
                Экспорт IoC (CSV)
              </button>
            </div>
          </div>
          <div className="card">
            <h3>
              Топ паролей<HelpMark text="Пароли, которые атакующие пробуют чаще всего. Показывает, какие словари используют для перебора." />
              <span className="hint">нажмите для фильтра</span>
            </h3>
            <TopList map={stats.pw} active={eventFilter.q} onPick={(v) => setEventFilter({ q: v })} />
          </div>
        </div>
      </div>
    </section>
  )
}
