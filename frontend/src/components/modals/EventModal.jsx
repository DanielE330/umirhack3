import { useNavigate } from 'react-router-dom'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { fmtDateTime } from '../../lib/model.js'
import { Kv } from '../common.jsx'

export default function EventModal({ ev }) {
  const { trapByName, setEventFilter } = useData()
  const { closeModal, showToast } = useUi()
  const { openTrap } = useModals()
  const navigate = useNavigate()

  const filterBy = (patch) => {
    closeModal()
    setEventFilter({ q: '', type: '', trap: '', ...patch })
    navigate('/overview')
  }
  const copyIp = async () => {
    try {
      await navigator.clipboard.writeText(ev.src_ip)
      showToast('Скопировано')
    } catch {
      showToast('Не удалось скопировать: выделите текст вручную', true)
    }
  }
  const openTrapOf = () => {
    const t = trapByName(ev.trap)
    if (t) openTrap(t)
    else showToast('Ловушка уже удалена', true)
  }

  return (
    <>
      <Kv rows={[
        ['Время', fmtDateTime(ev.ts)], ['Машина', ev.container], ['Ловушка', ev.trap], ['Тип', ev.type],
        ['Источник', ev.src_ip + ':' + ev.src_port], ['Порт ловушки', ev.dst_port], ['Протокол', ev.proto],
        ['Сессия', ev.session_id], ['Логин', ev.username], ['Пароль', ev.password], ['Команда / запрос', ev.command],
      ]} />
      <div className="inline">
        <button className="ghost" onClick={() => filterBy({ q: ev.src_ip })}>⌕ Все события этого IP</button>
        <button className="ghost" onClick={() => filterBy({ trap: ev.trap })}>☰ События этой ловушки</button>
        <button className="ghost" onClick={copyIp}>⧉ Копировать IP</button>
        <button className="ghost" onClick={openTrapOf}>→ Открыть ловушку</button>
      </div>
    </>
  )
}
