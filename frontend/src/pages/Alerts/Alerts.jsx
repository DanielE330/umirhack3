import { useEffect, useMemo, useState } from 'react'
import { TypeTag } from '../../components/common.jsx'
import { useLanguage } from '../../context/language.js'
import { useModals } from '../../hooks/useModals.jsx'
import { clickable } from '../../lib/clickable.js'
import { fmtDateTime } from '../../lib/model.js'
import { useEventList } from '../../hooks/useEventList.js'

const KINDS = [['alert', 'Тревоги'], ['honeytoken', 'Приманки (honeytoken)']]

// Самое важное для оператора: тревоги центра (перебор паролей) и срабатывания файлов-приманок.
export default function Alerts() {
  const { t } = useLanguage()
  const { openEvent } = useModals()
  const [kind, setKind] = useState('alert')
  const extra = useMemo(() => ({ type: kind }), [kind])
  const { items, next, busy, load } = useEventList(extra, 100)

  useEffect(() => {
    load(null)
    const timer = setInterval(() => load(null), 10000)
    return () => clearInterval(timer)
  }, [load])

  return (
    <section>
      <div className="toolbar">
        <div className="chips" role="radiogroup" aria-label={t('Вид')}>
          {KINDS.map(([v, label]) => (
            <button key={v} type="button" role="radio" aria-checked={v === kind} className={v === kind ? 'on' : ''} onClick={() => setKind(v)}>{t(label)}</button>
          ))}
        </div>
        <span className="spacer" />
        <span className="hint">{t('Обновляется каждые 10 секунд')}</span>
      </div>
      <p className="lead">
        {kind === 'alert'
          ? t('Тревога центра: пять и более попыток входа с одного IP за минуту. Такие же сообщения приходят в Telegram.')
          : t('Атакующий открыл файл-приманку или адрес-приманку — это почти всегда настоящая разведка или компрометация.')}
      </p>
      <div className="card">
        <table className="rows">
          <thead><tr><th>{t('Время')}</th><th>{t('Ловушка')}</th><th>{t('Тип')}</th><th>{t('Источник')}</th><th>{t('Детали')}</th></tr></thead>
          <tbody>
            {items && items.map((ev) => (
              <tr key={ev.id} className="click" {...clickable(() => openEvent(ev))}>
                <td className="m">{fmtDateTime(ev.ts)}</td>
                <td>{ev.trap}</td>
                <td><TypeTag type={ev.type} /></td>
                <td className="m">{ev.geo && ev.geo.country_code && ev.geo.country_code !== '--' ? <span className="cc">{ev.geo.country_code}</span> : null}{ev.src_ip}</td>
                <td className="m">{ev.command || ev.username || ''}</td>
              </tr>
            ))}
            {items && !items.length && <tr><td colSpan={5} className="empty">{t('Событий этого вида пока нет')}</td></tr>}
          </tbody>
        </table>
        {next && <div className="mt-10"><button className="ghost" disabled={busy} onClick={() => load(next)}>{t('Показать ещё')}</button></div>}
      </div>
    </section>
  )
}
