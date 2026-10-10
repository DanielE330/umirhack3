import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { ORDER, STATES } from '../../lib/model.js'
import Select from '../../components/Select.jsx'
import ContainerCard from './ContainerCard.jsx'

export default function Containers() {
  const { containers, traps, profiles, cFilter, setCFilter, trapsOf } = useData()
  const { showToast } = useUi()
  const { openNewContainer } = useModals()
  const navigate = useNavigate()

  const q = cFilter.q.trim().toLowerCase()
  const list = useMemo(
    () =>
      containers.filter((c) => {
        if (cFilter.status && c.state !== cFilter.status) return false
        if (!q) return true
        return [c.name, c.host, String(c.vmid), c.type, ...trapsOf(c.name).flatMap((t) => [t.name, t.profile])].join(' ').toLowerCase().includes(q)
      }),
    [containers, cFilter.status, q, trapsOf],
  )
  const working = containers.filter((c) => c.state === 'online').length

  const add = () => {
    if (!profiles.length) {
      showToast('Сначала создайте профиль ловушки', true)
      navigate('/profiles')
      return
    }
    openNewContainer()
  }

  return (
    <section>
      <div className="toolbar">
        <button className="btn" data-tip="Создать в Proxmox новую машину в изолированной сети и запустить в ней ловушки" onClick={add}>+ Новый контейнер</button>
        <input className="w-search" placeholder="Поиск по контейнерам и ловушкам…" aria-label="Поиск" value={cFilter.q}
          onChange={(e) => setCFilter((f) => ({ ...f, q: e.target.value }))} />
        <Select className="w-status" aria-label="Статус" data-tip="Показать только машины в выбранном состоянии" value={cFilter.status}
          options={[{ value: '', label: 'Все состояния' }, ...ORDER.map((k) => ({ value: k, label: STATES[k].label }))]}
          onChange={(e) => setCFilter((f) => ({ ...f, status: e.target.value }))} />
        <span className="spacer" />
        <span className="hint">{containers.length} машин · {traps.length} ловушек · работает: {working}</span>
      </div>
      <div className="legend">
        {ORDER.map((k) => (
          <span key={k} data-tip={STATES[k].hint}><span className={'dot ' + k} />{STATES[k].label}</span>
        ))}
      </div>
      <div className="cgrid">
        {list.length
          ? list.map((c) => <ContainerCard key={c.id} c={c} />)
          : <div className="cnone">{containers.length ? 'Ничего не найдено' : 'Контейнеров пока нет — создайте первый'}</div>}
      </div>
    </section>
  )
}
