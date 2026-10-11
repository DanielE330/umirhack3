import { useNavigate } from 'react-router-dom'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { fmtDateTime } from '../../lib/model.js'
import { Kv } from '../common.jsx'

export default function EventModal({ ev }) {
  const { trapByName, setEventFilter } = useData()
  const { closeModal, showToast } = useUi()
  const { openTrap } = useModals()
  const { t } = useLanguage()
  const navigate = useNavigate()

  const filterBy = (patch) => {
    closeModal()
    setEventFilter({ q: '', type: '', trap: '', ...patch })
    navigate('/overview')
  }
  const copyIp = async () => {
    try {
      await navigator.clipboard.writeText(ev.src_ip)
      showToast(t('Скопировано'))
    } catch {
      showToast(t('Не удалось скопировать: выделите текст вручную'), true)
    }
  }
  const openTrapOf = () => {
    const tr = trapByName(ev.trap)
    if (tr) openTrap(tr)
    else showToast(t('Ловушка уже удалена'), true)
  }

  return (
    <>
      <Kv rows={[
        ['Время', fmtDateTime(ev.ts)], ['Машина', ev.container], ['Ловушка', ev.trap], ['Тип', ev.type],
        ['Источник', ev.src_ip + ':' + ev.src_port],
        ['Страна / город', ev.geo ? [ev.geo.country, ev.geo.city].filter(Boolean).join(', ') : ''],
        ['ASN / провайдер', ev.geo ? [ev.geo.asn, ev.geo.org].filter(Boolean).join(' · ') : ''], ['Порт ловушки', ev.dst_port], ['Протокол', ev.proto],
        ['Сессия', ev.session_id], ['Логин', ev.username], ['Пароль', ev.password], ['Команда / запрос', ev.command],
        ['Файл (SHA-256)', (ev.data && ev.data.sha256) || ''],
      ]} />
      <div className="inline">
        <button className="ghost" onClick={() => filterBy({ q: ev.src_ip })}>{t('⌕ Все события этого IP')}</button>
        <button className="ghost" onClick={() => filterBy({ trap: ev.trap })}>{t('☰ События этой ловушки')}</button>
        <button className="ghost" onClick={copyIp}>{t('⧉ Копировать IP')}</button>
        <button className="ghost" onClick={openTrapOf}>{t('→ Открыть ловушку')}</button>
        {ev.data && ev.data.artifact && <a className="ghost btn" href={'/api/artifacts/' + ev.data.artifact + '/download'}>{t('⬇ Скачать файл')}</a>}
      </div>
    </>
  )
}
