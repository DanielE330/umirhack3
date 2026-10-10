import { useState } from 'react'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { baseName, portConflicts } from '../../lib/model.js'
import { Field } from '../common.jsx'
import TrapPicker from './TrapPicker.jsx'

export default function AddTrapModal({ vmid }) {
  const { containers, trapsOf, portsOf, profiles, profileByName, trapByName, uniqueName, refresh } = useData()
  const { closeModal, showToast } = useUi()
  const c = containers.find((x) => x.vmid === vmid)
  const [selected, setSelected] = useState([])
  const [name, setName] = useState('')
  const [touched, setTouched] = useState(false)
  const [err, setErr] = useState('')
  if (!c) return <p className="hint">Машина уже удалена</p>

  const existing = trapsOf(c.name)
  const noFree = !profiles.some((p) => !portsOf(p.name).some((port) => existing.some((t) => portsOf(t.profile).includes(port))))
  const pick = (list) => {
    setSelected(list)
    if (list[0] && !touched) setName(uniqueName(baseName(list[0])))
  }

  const add = async () => {
    const p = selected[0]
    const n = name.trim()
    if (!p) return setErr('Выберите тип ловушки')
    if (!/^[A-Za-z0-9._-]{1,60}$/.test(n)) return setErr('Имя: латиница, цифры, точка, дефис, подчёркивание')
    if (trapByName(n)) return setErr('Ловушка с таким именем уже есть')
    const errs = portConflicts([...existing.map((t) => ({ name: t.name, profile: t.profile })), { name: n, profile: p }], profileByName)
    if (errs.length) return setErr(errs.join('\n'))
    try {
      await api('/api/traps', { method: 'POST', body: { name: n, profile_id: profileByName(p).id, machine_vmid: c.vmid } })
    } catch (e) {
      return setErr(e.message)
    }
    closeModal()
    showToast('Ловушка «' + n + '» добавлена — подключите к ней агента в окне ловушки')
    return refresh()
  }

  return (
    <>
      <p className="hint">
        {existing.length
          ? 'Уже в машине: ' + existing.map((t) => t.name + ' (' + portsOf(t.profile).join(', ') + ')').join(', ')
          : 'Машина пока пустая.'}
      </p>
      <TrapPicker existing={existing} selected={selected} multi={false} onChange={pick} />
      <Field label="Имя ловушки">
        <input maxLength={60} value={name} placeholder="сначала выберите тип выше" aria-label="Имя ловушки"
          onChange={(e) => { setTouched(true); setName(e.target.value) }} />
      </Field>
      <div className="err" role="alert">
        {err || (noFree ? 'Все типы ловушек конфликтуют по портам с уже установленными. Создайте профиль с другими портами или новую машину.' : '')}
      </div>
      <div className="actions">
        <button className="btn" disabled={!selected.length} onClick={add}>Добавить ловушку</button>
        <button className="ghost" onClick={closeModal}>Отмена</button>
      </div>
    </>
  )
}
